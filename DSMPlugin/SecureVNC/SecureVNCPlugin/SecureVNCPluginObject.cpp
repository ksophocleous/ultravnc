/////////////////////////////////////////////////////////////////////////////
//  Copyright (C) 2005 Ultr@Vnc.  All Rights Reserved.
//  Copyright (C) 1998-2002 The OpenSSL Project.  All rights reserved.
//  Copyright (C) 2010 Adam D. Walling aka Adzm.  All Rights Reserved.
//
//  This product includes software developed by the OpenSSL Project for use 
//  in the OpenSSL Toolkit (http://www.openssl.org/)
//
////////////////////////////////////////////////////////////////////////////
//
//  This library is free software; you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public
//  License as published by the Free Software Foundation; either
//  version 2.1 of the License, or (at your option) any later version.
// 
//  This library is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//  Lesser General Public License for more details.
// 
//  You should have received a copy of the GNU Lesser General Public
//  License along with this library; if not, write to the Free Software
//  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
//  USA.
//
//  LGPL - http://www.gnu.org/licenses/lgpl-2.1.html
//
// If the source code for the program is not available from the place from
// which you received this file, please refer to the addresses below:
//
// UltraVNC                 - http://ultravnc.sourceforge.net/
// OpenSSL                  - http://openssl.org 
// Adam D. Walling aka Adzm - http://adamwalling.com/SecureVNC/
//                          - http://sourceforge.net/projects/securevncplugin/
//                          - mailto:adam.walling@gmail.com
////////////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "SecureVNCPluginObject.h"
#include "SecureVNCPlugin.h"
#include "CryptUtils.h"
#include "openssl/rand.h"

#define RSA_PUBKEY_SIZE 270
#define ENCRYPTED_KEY_SIZE 256
#define SIGNATURE_SIZE 256
#define KEY_SIZE 16
#define RESERVED_SIZE 4



SecureVNCPlugin::SecureVNCPlugin() :
	MultithreadedPlugin() {
	::InterlockedIncrement(&g_nInstanceCount);

	//adzm - 2009-06-20 - and initialize our cipher contexts.
	EVP_CIPHER_CTX_init(&m_ContextE);
	EVP_CIPHER_CTX_init(&m_ContextD);
	
	m_nEncryptPacketSequence = 0;
	m_nDecryptPacketSequence = 0;
	m_bHandshakeComplete = false;

	m_rsa = NULL;
	m_bUseAESCipher = false;

	HANDLE hClientAuthPublicKeyFile = FindClientAuthPublicKeyFile();
	HANDLE hClientAuthPrivateKeyFile = FindClientAuthPrivateKeyFile();

	if (hClientAuthPublicKeyFile != INVALID_HANDLE_VALUE) {
		m_bClientAuthPublicKeyAvailable = true;		
		::CloseHandle(hClientAuthPublicKeyFile);
	} else {
		m_bClientAuthPublicKeyAvailable = false;
	}
		
	if (hClientAuthPrivateKeyFile != INVALID_HANDLE_VALUE) {
		m_bClientAuthPrivateKeyAvailable = true;
		::CloseHandle(hClientAuthPrivateKeyFile);
	} else {
		m_bClientAuthPrivateKeyAvailable = false;
	}	

	m_pRSAData = NULL;
};

SecureVNCPlugin::~SecureVNCPlugin()
{
	//adzm - 2009-06-20 - clean up cipher contexts.
	//technically, the context should be initialized and cleared each time it is used so sensitive information
	//does not remain in memory. However since we will be constantly encrypting and decrypting small packets of
	//information, I've simply kept it around for the life of the plugin interface.
	EVP_CIPHER_CTX_cleanup(&m_ContextE);
	EVP_CIPHER_CTX_cleanup(&m_ContextD);

	if (m_rsa) {
		RSA_free(m_rsa);
		m_rsa = NULL;
	}

	if (m_pRSAData) {
		delete[] m_pRSAData;
	}

	if (::InterlockedDecrement(&g_nInstanceCount) == 0) {
		OpenSSL_Cleanup();
	}
};

// 
// TransformBuffer function
//
// Transform the data given in pDataBuffer then return the pointer on the allocated 
// buffer containing the resulting data.
// The length of the resulting data is given by pnTransformedDataLen
//	
BYTE* SecureVNCPlugin::TransformBuffer(BYTE* pDataBuffer, int nDataLen, int* pnTransformedDataLen)
{
	LockCriticalSection lock(m_csEncryption);

	m_nEncryptPacketSequence++;
	
	int nHeaderLen = 0;

	int nTransformedDataLen = GetTransformedDataLen(nDataLen);
	
	DebugLogVerbose(_T("Transform \t(%li / %li) \tnDataLen %li \tnTransformedDataLen %li\r\n"), m_nEncryptPacketSequence, m_nDecryptPacketSequence, nDataLen, nTransformedDataLen);
	
    BYTE* pTransBuffer = EnsureLocalTransformBufferSize(nTransformedDataLen);
    if (pTransBuffer == NULL)
    {
        *pnTransformedDataLen = -1;
        return NULL;
    }

	if (m_nEncryptPacketSequence == 1) {
		if (m_rsa == NULL) {
			// we have no RSA, so we must be initiating, so send the public key
	
			DebugLog(_T("Transform \t(%li / %li) \tLoading or creating private key\r\n"), m_nEncryptPacketSequence, m_nDecryptPacketSequence);
			m_rsa = LoadOrCreatePrivateKey(256);
			if (m_rsa == NULL) {
				// Error
				DebugLog(_T("Failed to load or create RSA private key!\r\n"));
				return NULL;
			} else {
				BYTE* pOutputBuffer = NULL;
				int nOutputLength = i2d_RSAPublicKey(m_rsa, &pOutputBuffer);
				// == RSA_PUBKEY_SIZE
				
				// store the RSA data for later
				if (m_pRSAData) {
					delete[] m_pRSAData;
				}
				m_pRSAData = new unsigned char[nOutputLength];
				memcpy(m_pRSAData, pOutputBuffer, nOutputLength);

				nHeaderLen += nOutputLength;

				memcpy(pTransBuffer, pOutputBuffer, nOutputLength);

				{
					m_bUseAESCipher = false;
				}
				{
					// Server flags
					DWORD dwServerFlags = 0;
					if (m_bUseAESCipher) {
						dwServerFlags |= flagUseAESCipher;
						DebugLog(_T("Using AES Cipher\r\n"));
					}
					if (m_bClientAuthPublicKeyAvailable) {
						dwServerFlags |= flagUseSignature;
					}
					memcpy(pTransBuffer+nOutputLength, &dwServerFlags, RESERVED_SIZE);

					nHeaderLen += RESERVED_SIZE;
				}

				{
					//memcpy(pTransBuffer+nHeaderLen, pDataBuffer, nDataLen);

					//just use the hash of the key to encrypt the first buffer; this is at least a bit better than plaintext, although
					//it is not secure at all. However for VNC usage, this will always simply be the RFB version header string.
					DebugLog(_T("Transform \t(%li / %li) \tPreparing initial symmetric key\r\n"), m_nEncryptPacketSequence, m_nDecryptPacketSequence);

					EVP_CIPHER_CTX InitialContextE;
					EVP_CIPHER_CTX_init(&InitialContextE);
					unsigned char* pInitialKey = new unsigned char[KEY_SIZE];
					EVP_BytesToKey(EVP_rc4(), EVP_sha1(), NULL, pOutputBuffer, nOutputLength, 1, pInitialKey, NULL);
					
					DebugLogSensitive(_T("Initialize intial encryption context with key:\r\n"));
					DebugLogBinarySensitive(pInitialKey, KEY_SIZE);
					EVP_CipherInit_ex(&InitialContextE, EVP_rc4(), NULL, pInitialKey, NULL, 1);

					
					DebugLogSensitive(_T("Initial transform %li bytes\r\n"), nDataLen);
					DebugLogBinarySensitive(pDataBuffer, nDataLen);

					int nByteCount = 0;
					EVP_CipherUpdate(&InitialContextE, pTransBuffer+nHeaderLen, &nByteCount, pDataBuffer, nDataLen);

					DebugLog(_T("Transform \t(%li / %li) \tInitial packet encrypted\r\n"), m_nEncryptPacketSequence, m_nDecryptPacketSequence);
					
					DebugLogSensitive(_T("Initial transformed to %li bytes\r\n"), nByteCount);
					DebugLogBinarySensitive(pTransBuffer+nHeaderLen, nByteCount);

					EVP_CIPHER_CTX_cleanup(&InitialContextE);

					delete[] pInitialKey;
				}
				delete[] pOutputBuffer;

				// return the transformed data length
				DebugLogVerbose(_T("Transform \t(%li / %li) \tEnsure private key \nnOutputLength %li\r\n"), m_nEncryptPacketSequence, m_nDecryptPacketSequence, nOutputLength);
				*pnTransformedDataLen = nTransformedDataLen;
				
				return pTransBuffer; 
			}
		} else {
			// we have an RSA key, we are responding, so encrypt our symmetric key		

			unsigned char* pKeyBuffer = new unsigned char[KEY_SIZE];

			unsigned char* pEncryptedKeyBuffer = new unsigned char[RSA_size(m_rsa)];

#define RAND_KEY_SOURCE 1024
			unsigned char RandSource[RAND_KEY_SOURCE];
			RAND_bytes(RandSource, RAND_KEY_SOURCE);
			
			DebugLog(_T("Transform \t(%li / %li) \tCreating persistent symmetric session key\r\n"), m_nEncryptPacketSequence, m_nDecryptPacketSequence);

			EVP_BytesToKey(GetCipher(), EVP_sha1(), NULL, RandSource, RAND_KEY_SOURCE, 1, pKeyBuffer, NULL);
			DebugLogSensitive(_T("Initialize encryption context with key:\r\n"));
			DebugLogBinarySensitive(pKeyBuffer, KEY_SIZE);
			EVP_CipherInit_ex(&m_ContextE, GetCipher(), NULL, pKeyBuffer, NULL, 1);
			DebugLogSensitive(_T("Initialize decryption context with key:\r\n"));
			DebugLogBinarySensitive(pKeyBuffer, KEY_SIZE);
			EVP_CipherInit_ex(&m_ContextD, GetCipher(), NULL, pKeyBuffer, NULL, 0);

			DebugLog(_T("Transform \t(%li / %li) \tSymmetric keys created; encrypting...\r\n"), m_nEncryptPacketSequence, m_nDecryptPacketSequence);
			

			//DebugLog(_T("Initial encrypt context cipher data:\r\n"));
			//DebugLogBinary((BYTE*)m_ContextE.cipher_data, m_ContextE.cipher->ctx_size);
			//DebugLog(_T("Initial decrypt context cipher data:\r\n"));
			//DebugLogBinary((BYTE*)m_ContextD.cipher_data, m_ContextD.cipher->ctx_size);

//#ifdef _DEBUG
			//HANDLE hOutputFile = CreateFile(_T("TransformKey.bin"), GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			//DWORD dwWritten = 0;
			//WriteFile(hOutputFile, pKeyBuffer, KEY_SIZE, &dwWritten, NULL);
			//CloseHandle(hOutputFile);
//#endif

			int nEncryptedSize = RSA_public_encrypt(KEY_SIZE, pKeyBuffer, pEncryptedKeyBuffer, m_rsa, RSA_PKCS1_PADDING);

			DebugLog(_T("Transform \t(%li / %li) \tSymmetric keys encrypted\r\n"), m_nEncryptPacketSequence, m_nDecryptPacketSequence);

			// nEncryptedSize == RSA_size(m_rsa) ? == ENCRYPTED_KEY_SIZE?

			if (nEncryptedSize == -1) {
				// Error
				*pnTransformedDataLen = -1;
				return NULL;
			}
			
			DebugLogVerbose(_T("Transform \t(%li / %li) \tCreate sym \tnEncryptedSize %li \tnTransformedDataLen %li\r\n"), m_nEncryptPacketSequence, m_nDecryptPacketSequence, nEncryptedSize, nTransformedDataLen);

			DebugLog(_T("Transform \t(%li / %li) \tHandshake is complete!\r\n"), m_nEncryptPacketSequence, m_nDecryptPacketSequence);
			m_bHandshakeComplete = true;

			if (!m_bUseAESCipher) {
				BYTE* pDummy = new BYTE[RC4_DROP_BYTES];
				BYTE* pDummyEncrypted = new BYTE[RC4_DROP_BYTES];
				int nDummyByteCount = 0;
				EVP_CipherUpdate(&m_ContextE, (unsigned char *)pDummy, &nDummyByteCount, pDummyEncrypted, RC4_DROP_BYTES);
				EVP_CipherUpdate(&m_ContextD, (unsigned char *)pDummyEncrypted, &nDummyByteCount, pDummy, RC4_DROP_BYTES);
				delete[] pDummy;
				delete[] pDummyEncrypted;
				DebugLog(_T("Discarded beginning of RC4 keystream\r\n"));
			}

			memcpy(pTransBuffer, pEncryptedKeyBuffer, nEncryptedSize);

			nHeaderLen += nEncryptedSize;

			delete[] pEncryptedKeyBuffer;

			
			{
				// Viewer Response Flags
				DWORD dwViewerFlags = 0;
				
				if (m_bUseAESCipher) {
					dwViewerFlags |= flagUseAESCipher;
				}

				if (m_bClientAuthPrivateKeyAvailable) {
					dwViewerFlags |= flagUseSignature;
				}

				memcpy(pTransBuffer+nHeaderLen, &dwViewerFlags, RESERVED_SIZE);

				nHeaderLen += RESERVED_SIZE;
			}

			if (m_bClientAuthPrivateKeyAvailable) {
				DebugLog(__T("Signing symmetric key...\r\n"));
				::ZeroMemory(pTransBuffer+nHeaderLen, SIGNATURE_SIZE);

				// Sign the symmetric key with the Client Authentication private key
				RSA* rsaClientAuth = LoadClientAuthPrivateKey();

				if (rsaClientAuth) {
					// create a message digest of the symmetric key
					unsigned int messageDigestLength = 0;
					BYTE* messageDigest = new BYTE[EVP_MAX_MD_SIZE];

					BYTE* pPublicAndSymmetricKeyBuffer = new BYTE[KEY_SIZE + RSA_PUBKEY_SIZE];
					{
						BYTE* pPosition = pPublicAndSymmetricKeyBuffer;
						memcpy(pPosition, m_pRSAData, RSA_PUBKEY_SIZE);
						pPosition += RSA_PUBKEY_SIZE;
						memcpy(pPosition, pKeyBuffer, KEY_SIZE);
					}

					EVP_MD_CTX digestContext;
					EVP_DigestInit(&digestContext, EVP_sha1());
					EVP_DigestUpdate(&digestContext, pPublicAndSymmetricKeyBuffer, KEY_SIZE + RSA_PUBKEY_SIZE);
					EVP_DigestFinal(&digestContext, messageDigest, &messageDigestLength);

					delete[] pPublicAndSymmetricKeyBuffer;

					DebugLog(__T("\tCreated SHA-1 hash\r\n"));
					DebugLogBinary(messageDigest, messageDigestLength);

					//ASSERT(messageDigestLength == 20);

					unsigned int signatureLength = 0;
					BYTE* signature = new BYTE[RSA_size(rsaClientAuth)];
					RSA_sign(NID_sha1, messageDigest, messageDigestLength, signature, &signatureLength, rsaClientAuth);

					//ASSERT(signatureLength == SIGNATURE_SIZE);

					RSA_free(rsaClientAuth);

					delete[] messageDigest;

					DebugLog(__T("\tCreated signature\r\n"));
					DebugLogBinary(signature, SIGNATURE_SIZE);

					memcpy(pTransBuffer+nHeaderLen, signature, SIGNATURE_SIZE);

					delete[] signature;
				} else {
					DebugLog(_T("Failed to load client auth private key!\r\n"));
				}

				nHeaderLen += SIGNATURE_SIZE;
			}

			delete[] pKeyBuffer;
		}
	}
	
	if (nDataLen > 0)
	{
		//DebugLog(_T("Encrypt context cipher data:\r\n"));
		//DebugLogBinary((BYTE*)m_ContextE.cipher_data, m_ContextE.cipher->ctx_size);

		DebugLogSensitive(_T("Transform %li bytes\r\n"), nDataLen);
		DebugLogBinarySensitive(pDataBuffer, nDataLen);

		int nByteCount = 0;
		if(!EVP_CipherUpdate(&m_ContextE, (unsigned char *)pTransBuffer+nHeaderLen, &nByteCount, pDataBuffer, nDataLen))
		{
			// Error 
			return NULL;
		}		
		DebugLogSensitive(_T("Transformed to %li bytes\r\n"), nByteCount);
		DebugLogBinarySensitive(pTransBuffer+nHeaderLen, nDataLen);

		//DebugLog(_T("Post-encrypt context cipher data:\r\n"));
		//DebugLogBinary((BYTE*)m_ContextE.cipher_data, m_ContextE.cipher->ctx_size);
	}

	// return the transformed data length
    *pnTransformedDataLen = nTransformedDataLen;
	
    return pTransBuffer; 
}

//
// RestoreBuffer function
//
// This function has a 2 mandatory behaviors:
//
// 1. If pRestoredDataBuffer is NULL, the function must return the pointer to current
//    LocalRestBuffer that is going to receive the Transformed data to restore
//    from VNC viewer/server's socket.
//    This buffer must be of the size of transformed data, calculated from nDataLen
//    and this size must be given back in pnRestoredDataLen.
//
// 2. If pRestoredDataBuffer != NULL, it is the destination buffer that is going to receive
//    the restored data. So the function must restore the data that is currently in the
//    local pLocalRestBuffer (nDataLen long) and put the result in pRestoredDataBuffer.
//    The length of the resulting data is given back in pnTransformedDataLen
//
// Explanation: Actually, when VNC viewer/server wants to restore some data, it does the following:
// - Calls RestoreBuffer with NULL to get the buffer (and its length) to store incoming transformed data
// - Reads incoming transformed data from socket directly into the buffer given (and of given length)
// - Calls RestoreBuffer again to actually restore data into the given destination buffer.
// This way the copies of data buffers are reduced to the minimum.
// 
BYTE* SecureVNCPlugin::RestoreBuffer(BYTE* pTransBuffer, int nTransDataLen, int* pnRestoredDataLen)
{
	LockCriticalSection lock(m_csEncryption);

	int nHeaderLen = 0;
		
    // If given buffer is NULL, allocate necessary space here and return the pointer.
    // Additinaly, calculate the resulting length based on nDataLen and return it at the same time.
    if (pTransBuffer == NULL)
    {
		int nTransformedDataLen = GetTransformedDataLen(nTransDataLen);
        *pnRestoredDataLen = nTransformedDataLen;
		
		DebugLogVerbose(_T("RestoreCheck \t(%li / %li) \tnTransDataLen %li \tpDataBuffer 0x%08x \tnTransformedDataLen %li\r\n"), m_nEncryptPacketSequence, m_nDecryptPacketSequence, nTransDataLen, pTransBuffer, nTransformedDataLen);
        // Ensure the pLocalRestBuffer that receive transformed data is big enough
        BYTE* pBuffer = EnsureLocalRestoreBufferSize(nTransformedDataLen);
        return pBuffer; // Actually pBuffer = pLocalRestBuffer
    }

	m_nDecryptPacketSequence++;

	int nRestoredDataLen = GetRestoredDataLen(nTransDataLen);
	
	DebugLogVerbose(_T("Restore \t(%li / %li) \tnTransDataLen %li \tpDataBuffer 0x%08x \tnRestoredDataLen %li\r\n"), m_nEncryptPacketSequence, m_nDecryptPacketSequence, nTransDataLen, pTransBuffer, nRestoredDataLen);
	
	if (m_nDecryptPacketSequence == 1) {
		if (m_rsa == NULL) {
			MultithreadedPlugin::ThreadLocalMemoryInfo* pMemory = GetThreadLocalMemoryInfo();
			

			// no key, so we must be getting it from the server
			unsigned char* pBuffer = new unsigned char[RSA_PUBKEY_SIZE];
			memcpy(pBuffer, pMemory->m_pRestBuffer, RSA_PUBKEY_SIZE);

			nHeaderLen += RSA_PUBKEY_SIZE;

			{
				// Server flags
				DWORD dwServerFlags = 0;
				memcpy(&dwServerFlags, pMemory->m_pRestBuffer + nHeaderLen, RESERVED_SIZE);

				nHeaderLen += RESERVED_SIZE;

				if (dwServerFlags & flagUseAESCipher) {
					m_bUseAESCipher = true;
					DebugLog(_T("Using AES Cipher\r\n"));
				}
				if (dwServerFlags & flagUseSignature) {
					DebugLog(_T("Server wants client auth signature\r\n"));
				}
			}			

			unsigned char* pInitialKey = new unsigned char[KEY_SIZE];
			EVP_BytesToKey(EVP_rc4(), EVP_sha1(), NULL, pBuffer, RSA_PUBKEY_SIZE, 1, pInitialKey, NULL);
			
			DebugLog(_T("Restore \t(%li / %li) \tLoading public key\r\n"), m_nEncryptPacketSequence, m_nDecryptPacketSequence);
			// store the RSA data for later
			if (m_pRSAData) {
				delete[] m_pRSAData;
			}
			m_pRSAData = new unsigned char[RSA_PUBKEY_SIZE];
			memcpy(m_pRSAData, pBuffer, RSA_PUBKEY_SIZE);
			BYTE* pNewRSAData = m_pRSAData;
			m_rsa = d2i_RSAPublicKey(NULL, (const unsigned char**)&pNewRSAData, RSA_PUBKEY_SIZE);

			if (m_rsa == NULL) {
				// Error
				DebugLog(_T("Failed to load RSA public key!\r\n"));
				*pnRestoredDataLen = 0;
				return NULL;
			}
			
			
			DebugLog(_T("Restore \t(%li / %li) \tLoaded public key\r\n"), m_nEncryptPacketSequence, m_nDecryptPacketSequence);

			if (nTransDataLen > 0 && nRestoredDataLen > 0)
			{	
				{
					//memcpy(pTransBuffer, pMemory->m_pRestBuffer+nHeaderLen, nRestoredDataLen);

					//just use the hash of the key to encrypt the first buffer; this is at least a bit better than plaintext, although
					//it is not secure at all. However for VNC usage, this will always simply be the RFB version header string.
					EVP_CIPHER_CTX InitialContextD;
					EVP_CIPHER_CTX_init(&InitialContextD);

					DebugLog(_T("Restore \t(%li / %li) \tPreparing initial symmetric key\r\n"), m_nEncryptPacketSequence, m_nDecryptPacketSequence);
					
					DebugLogSensitive(_T("Initialize intial decryption context with key:\r\n"));
					DebugLogBinarySensitive(pInitialKey, KEY_SIZE);
					EVP_CipherInit_ex(&InitialContextD, EVP_rc4(), NULL, pInitialKey, NULL, 1);

					
					DebugLogSensitive(_T("Initial transform %li bytes\r\n"), nRestoredDataLen);
					DebugLogBinarySensitive(pMemory->m_pRestBuffer+nHeaderLen, nRestoredDataLen);

					int nByteCount = 0;
					EVP_CipherUpdate(&InitialContextD, pTransBuffer, &nByteCount, pMemory->m_pRestBuffer+nHeaderLen, nRestoredDataLen);
					
					DebugLogSensitive(_T("Initial transformed to %li bytes\r\n"), nByteCount);
					DebugLogBinarySensitive(pTransBuffer, nByteCount);
					
					DebugLog(_T("Restore \t(%li / %li) \tDecrypted initial packet\r\n"), m_nEncryptPacketSequence, m_nDecryptPacketSequence);

					EVP_CIPHER_CTX_cleanup(&InitialContextD);
				}

				*pnRestoredDataLen = nRestoredDataLen;
			} else {
				*pnRestoredDataLen = nRestoredDataLen;
			}
			
			delete[] pInitialKey;

			return pMemory->m_pRestBuffer;
		} else {
			// we already have a key loaded, so we are getting the symmetric key from the viewer
			MultithreadedPlugin::ThreadLocalMemoryInfo* pMemory = GetThreadLocalMemoryInfo();

			unsigned char* pBuffer = new unsigned char[ENCRYPTED_KEY_SIZE];
			unsigned char* pDecryptedKey = new unsigned char[KEY_SIZE];

			memcpy(pBuffer, pMemory->m_pRestBuffer, ENCRYPTED_KEY_SIZE);
			nHeaderLen += ENCRYPTED_KEY_SIZE;
			
			{
				// Viewer Response flags
				DWORD dwViewerFlags = 0;
				memcpy(&dwViewerFlags, pMemory->m_pRestBuffer+nHeaderLen, RESERVED_SIZE);

				nHeaderLen += RESERVED_SIZE;
			}

			DebugLog(_T("Restore \t(%li / %li) \tDecrypting symmetric key\r\n"), m_nEncryptPacketSequence, m_nDecryptPacketSequence);

			int nDecryptedSize = RSA_private_decrypt(ENCRYPTED_KEY_SIZE, pBuffer, pDecryptedKey, m_rsa, RSA_PKCS1_PADDING);

			if (nDecryptedSize == -1) {
				// Error
				DebugLog(_T("Failed to decrypt encrypted symmetric key!!\r\n"));
				*pnRestoredDataLen = 0;
				return NULL;
			}

			delete[] pBuffer;

			DebugLog(_T("Restore \t(%li / %li) \tLoading symmetric key\r\n"), m_nEncryptPacketSequence, m_nDecryptPacketSequence);

			DebugLogSensitive(_T("Initialize encryption context with key:\r\n"));
			DebugLogBinarySensitive(pDecryptedKey, KEY_SIZE);
			EVP_CipherInit_ex(&m_ContextE, GetCipher(), NULL, pDecryptedKey, NULL, 1);
			DebugLogSensitive(_T("Initialize decryption context with key:\r\n"));
			DebugLogBinarySensitive(pDecryptedKey, KEY_SIZE);
			EVP_CipherInit_ex(&m_ContextD, GetCipher(), NULL, pDecryptedKey, NULL, 0);

			//DebugLog(_T("Initial encrypt context cipher data:\r\n"));
			//DebugLogBinary((BYTE*)m_ContextE.cipher_data, m_ContextE.cipher->ctx_size);
			//DebugLog(_T("Initial decrypt context cipher data:\r\n"));
			//DebugLogBinary((BYTE*)m_ContextD.cipher_data, m_ContextD.cipher->ctx_size);
			
			DebugLog(_T("Restore \t(%li / %li) \tHandshake is complete!\r\n"), m_nEncryptPacketSequence, m_nDecryptPacketSequence);

			m_bHandshakeComplete = true;

//#ifdef _DEBUG
			//HANDLE hOutputFile = CreateFile(_T("RestoreKey.bin"), GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			//DWORD dwWritten = 0;
			//WriteFile(hOutputFile, pDecryptedKey, KEY_SIZE, &dwWritten, NULL);
			//CloseHandle(hOutputFile);
//#endif
			if (m_bClientAuthPublicKeyAvailable) {
				DebugLog(__T("Verifying signature from client...\r\n"));

				RSA* rsaClientAuth = LoadClientAuthPublicKey();

				if (rsaClientAuth) {
					// let's check the signature of the decrypted symmetric key

					// create a message digest of the decrypted symmetric key
					unsigned int messageDigestLength = 0;
					BYTE* messageDigest = new BYTE[EVP_MAX_MD_SIZE];

					BYTE* pPublicAndSymmetricKeyBuffer = new BYTE[KEY_SIZE + RSA_PUBKEY_SIZE];
					{
						BYTE* pPosition = pPublicAndSymmetricKeyBuffer;
						memcpy(pPosition, m_pRSAData, RSA_PUBKEY_SIZE);
						pPosition += RSA_PUBKEY_SIZE;
						memcpy(pPosition, pDecryptedKey, KEY_SIZE);
					}

					EVP_MD_CTX digestContext;
					EVP_DigestInit(&digestContext, EVP_sha1());
					EVP_DigestUpdate(&digestContext, pPublicAndSymmetricKeyBuffer, KEY_SIZE + RSA_PUBKEY_SIZE);
					EVP_DigestFinal(&digestContext, messageDigest, &messageDigestLength);

					delete[] pPublicAndSymmetricKeyBuffer;

					//ASSERT(messageDigestLength == 20);

					DebugLog(__T("\tCreated SHA-1 hash"));
					DebugLogBinary(messageDigest, messageDigestLength);

					
					DebugLog(__T("\tLoaded signature"));
					DebugLogBinary(pMemory->m_pRestBuffer + nHeaderLen, SIGNATURE_SIZE);

					int verified = RSA_verify(NID_sha1, messageDigest, messageDigestLength, pMemory->m_pRestBuffer + nHeaderLen, SIGNATURE_SIZE, rsaClientAuth);

					RSA_free(rsaClientAuth);

					delete[] messageDigest;

					if (!verified) {
						DebugLog(__T("Signature could not be verified!\r\n"));
						return NULL;
					} else {
						DebugLog(__T("Signature successfully verified!\r\n"));
					}
				} else {
					DebugLog(_T("Failed to load client auth public key!\r\n"));
				}

				nHeaderLen += SIGNATURE_SIZE;
			}

			delete[] pDecryptedKey;
			
			DebugLog(_T("Restore \t(%li / %li) \tLoaded symmetric key\r\n"), m_nEncryptPacketSequence, m_nDecryptPacketSequence);

			if (!m_bUseAESCipher) {
				BYTE* pDummy = new BYTE[RC4_DROP_BYTES];
				BYTE* pDummyEncrypted = new BYTE[RC4_DROP_BYTES];
				int nDummyByteCount = 0;
				EVP_CipherUpdate(&m_ContextE, (unsigned char *)pDummy, &nDummyByteCount, pDummyEncrypted, RC4_DROP_BYTES);
				EVP_CipherUpdate(&m_ContextD, (unsigned char *)pDummyEncrypted, &nDummyByteCount, pDummy, RC4_DROP_BYTES);
				delete[] pDummy;
				delete[] pDummyEncrypted;
				DebugLog(_T("Discarded beginning of RC4 keystream\r\n"));
			}
		}
	}

	MultithreadedPlugin::ThreadLocalMemoryInfo* pMemory = GetThreadLocalMemoryInfo();

	if (nTransDataLen > 0 && nRestoredDataLen > 0)
	{	
		int nByteCount = 0;
		//DebugLog(_T("Decrypt context cipher data:\r\n"));
		//DebugLogBinary((BYTE*)m_ContextD.cipher_data, m_ContextD.cipher->ctx_size);

		DebugLogVerbose(_T("Restore %li bytes\r\n"), nTransDataLen-nHeaderLen);
		DebugLogBinarySensitive(pMemory->m_pRestBuffer+nHeaderLen, nTransDataLen-nHeaderLen);
		if(!EVP_CipherUpdate(&m_ContextD, pTransBuffer, &nByteCount, pMemory->m_pRestBuffer+nHeaderLen, nTransDataLen-nHeaderLen))
		{
			// Error 
			DebugLog(_T("Error decrypting buffer!\r\n"));
			*pnRestoredDataLen = 0;
			return NULL;
		} else {
			*pnRestoredDataLen = nRestoredDataLen;
		}
		DebugLogVerbose(_T("Restored to %li bytes\r\n"), nByteCount);
		DebugLogBinarySensitive(pTransBuffer, nByteCount);
		
		//DebugLog(_T("Post-decrypt context cipher data:\r\n"));
		//DebugLogBinary((BYTE*)m_ContextD.cipher_data, m_ContextD.cipher->ctx_size);
	} else {
		*pnRestoredDataLen = nRestoredDataLen;
	}

    return pMemory->m_pRestBuffer;
}


//
// Calculate the len of the data after transformation and return it. 
// 
// MANDATORY: The calculation must be possible by
// ONLY knowing the source data length ! (=> forget compression algos...)
//
// Example:
// For 128bits key encryption, the typical calculation would be;
// Pad the DataBuffer so it is 16 bytes (128 bits) modulo 
//      nPad = (nDataLen % 16 == 0) ? 0 : (16 - (nDataLen % 16));
// Then add a 16 bytes to store the original buffer length (this way it's 
// still 16 bytes modulo) that will be necessary for decryption
//      *pnTransformedDataLen = nDataLen + nPad + 16;
//adzm - 2009-06-20 - this is a stream cipher; padding is unnecessary
int SecureVNCPlugin::GetTransformedDataLen(int nDataLen) 
{
	if (m_bHandshakeComplete) {
		DebugLogVerbose(_T("\tGetTransformedDataLen \t(%li / %li) HANDSHAKE COMPLETE \tnDataLen %li \treturn nDataLen %li\r\n"), m_nEncryptPacketSequence, m_nDecryptPacketSequence, nDataLen, nDataLen);
		return nDataLen;
	}

	if (m_nEncryptPacketSequence == 1) {
		if (m_rsa == NULL) {
			// we have no RSA, so we must be initiating, so send the public key
			
			DebugLogVerbose(_T("\tGetTransformedDataLen \t(%li / %li) \tnDataLen %li \treturn nDataLen + RSA_PUBKEY_SIZE %li\r\n"), m_nEncryptPacketSequence, m_nDecryptPacketSequence, nDataLen, nDataLen + RSA_PUBKEY_SIZE + RESERVED_SIZE);
			return nDataLen + RSA_PUBKEY_SIZE + RESERVED_SIZE;
		} else {
			// we have an RSA key, we are responding, so encrypt our symmetric key	
			
			if (m_bClientAuthPrivateKeyAvailable || m_bClientAuthPublicKeyAvailable) {
				DebugLogVerbose(_T("\tGetTransformedDataLen (signature)\t(%li / %li) \tnDataLen %li \treturn nDataLen + ENCRYPTED_KEY_SIZE + RESERVED_SIZE + SIGNATURE_SIZE%li\r\n"), m_nEncryptPacketSequence, m_nDecryptPacketSequence, nDataLen, nDataLen + ENCRYPTED_KEY_SIZE + RESERVED_SIZE + SIGNATURE_SIZE);
				return nDataLen + ENCRYPTED_KEY_SIZE + RESERVED_SIZE + SIGNATURE_SIZE;
			} else {
				DebugLogVerbose(_T("\tGetTransformedDataLen \t(%li / %li) \tnDataLen %li \treturn nDataLen + ENCRYPTED_KEY_SIZE + RESERVED_SIZE %li\r\n"), m_nEncryptPacketSequence, m_nDecryptPacketSequence, nDataLen, nDataLen + ENCRYPTED_KEY_SIZE + RESERVED_SIZE);
				return nDataLen + ENCRYPTED_KEY_SIZE + RESERVED_SIZE;
			}
		}
	} else if (m_nEncryptPacketSequence == 0) {		
		DebugLogVerbose(_T("\tGetTransformedDataLen \t(%li / %li) \tnDataLen %li \treturn nDataLen + RSA_PUBKEY_SIZE + RESERVED_SIZE! %li\r\n"), m_nEncryptPacketSequence, m_nDecryptPacketSequence, nDataLen, nDataLen + RSA_PUBKEY_SIZE + RESERVED_SIZE);
		return nDataLen + RSA_PUBKEY_SIZE + RESERVED_SIZE;
	} else {
		DebugLogVerbose(_T("\tGetTransformedDataLen \t(%li / %li) \tnDataLen %li \treturn nDataLen %li\r\n"), m_nEncryptPacketSequence, m_nDecryptPacketSequence, nDataLen, nDataLen);
		return nDataLen;
	}
}

//
// Calculate the len of the data after Restauration and return it. 
// 
// MANDATORY: The calculation must be possible by
// ONLY knowing the source data length ! (=> forget compression algos...)
//
//adzm - 2009-06-20 - this is a stream cipher; padding is unnecessary
int SecureVNCPlugin::GetRestoredDataLen(int nDataLen)
{
	if (m_bHandshakeComplete) {
		DebugLogVerbose(_T("\tGetRestoredDataLen \t(%li / %li) HANDSHAKE COMPLETE \tnDataLen %li \treturn nDataLen %li\r\n"), m_nEncryptPacketSequence, m_nDecryptPacketSequence, nDataLen, nDataLen);
		return nDataLen;
	}

	if (m_nDecryptPacketSequence == 1) {
		if (m_rsa == NULL) {
			// no key, so we must be getting it from the server
			DebugLogVerbose(_T("\tGetRestoredDataLen \t(%li / %li) \tnDataLen %li \treturn nDataLen - RSA_PUBKEY_SIZE - RESERVED_SIZE %li\r\n"), m_nEncryptPacketSequence, m_nDecryptPacketSequence, nDataLen, nDataLen - RSA_PUBKEY_SIZE - RESERVED_SIZE);
			return nDataLen - RSA_PUBKEY_SIZE - RESERVED_SIZE;
		} else {
			// we already have a key loaded, so we are getting the symmetric key from the viewer
			if (m_bClientAuthPublicKeyAvailable || m_bClientAuthPublicKeyAvailable) {
				DebugLogVerbose(_T("\tGetRestoredDataLen (signature) \t(%li / %li) \tnDataLen %li \treturn nDataLen - ENCRYPTED_KEY_SIZE - RESERVED_SIZE - SIGNATURE_SIZE%li\r\n"), m_nEncryptPacketSequence, m_nDecryptPacketSequence, nDataLen, nDataLen - ENCRYPTED_KEY_SIZE - RESERVED_SIZE - SIGNATURE_SIZE);
				return nDataLen - ENCRYPTED_KEY_SIZE - RESERVED_SIZE - SIGNATURE_SIZE;
			} else {				
				DebugLogVerbose(_T("\tGetRestoredDataLen \t(%li / %li) \tnDataLen %li \treturn nDataLen - ENCRYPTED_KEY_SIZE - RESERVED_SIZE%li\r\n"), m_nEncryptPacketSequence, m_nDecryptPacketSequence, nDataLen, nDataLen - ENCRYPTED_KEY_SIZE - RESERVED_SIZE);
				return nDataLen - ENCRYPTED_KEY_SIZE - RESERVED_SIZE;
			}
		}
	} else {
		DebugLogVerbose(_T("\tGetRestoredDataLen \t(%li / %li) \tnDataLen %li \treturn nDataLen %li\r\n"), m_nEncryptPacketSequence, m_nDecryptPacketSequence, nDataLen, nDataLen);
		return nDataLen;
	}
}
