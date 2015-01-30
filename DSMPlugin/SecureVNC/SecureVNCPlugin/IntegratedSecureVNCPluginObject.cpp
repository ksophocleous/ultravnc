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

#include "StdAfx.h"
#include "IntegratedSecureVNCPluginObject.h"
#include "SecureVNCPlugin.h"
#include <assert.h>

const BYTE g_DefaultPassword[32] = {
	0x69, 0xF4, 0xA4, 0x7C, 0xF8, 0xF1, 0xA6, 0x11, 0xC1, 0x05, 0x81, 0xC4,
	0x95, 0x49, 0xAF, 0x4E, 0xB9, 0x55, 0x22, 0x69, 0x2F, 0x68, 0x32, 0xF4,
	0xD5, 0x64, 0x5D, 0xF5, 0xE2, 0x37, 0x02, 0x70
};

IntegratedSecureVNCPlugin::IntegratedSecureVNCPlugin() :
	m_bIsServer(false),
	m_bIsViewer(false),
	m_bHandshakeComplete(false),
	m_szLastErrorString(NULL),
	m_szCurrentSettingsDescription(NULL),
	m_bTriple(false),
	m_rsa(NULL),
	m_nRSASize(0),
	m_rsaClientAuthPublicKey(NULL),
	m_szClientAuthPublicKeyIdentifier(NULL),
	m_nClientAuthPublicKeyRSASize(0),
	m_pPasswordData(NULL),
	m_nPasswordDataLength(0),
	m_bOverridePassphrase(false),
	m_pServerIdentificationData(NULL),
	m_nServerIdentificationLength(0),
	m_dwChallengeFlags(0),
	m_dwResponseFlags(0),
	m_dwServerOptionFlags(0),
	m_pPublicKeyRaw(NULL),
	m_nPublicKeyRawLength(0)
{
	::InterlockedIncrement(&g_nInstanceCount);

	EVP_CIPHER_CTX_init(&m_ContextSV1);
	EVP_CIPHER_CTX_init(&m_ContextVS1);	
	EVP_CIPHER_CTX_init(&m_ContextSV2);
	EVP_CIPHER_CTX_init(&m_ContextVS2);	
	EVP_CIPHER_CTX_init(&m_ContextSV3);
	EVP_CIPHER_CTX_init(&m_ContextVS3);	

	SetLastErrorString("Initialized");
}

IntegratedSecureVNCPlugin::~IntegratedSecureVNCPlugin()
{
	EVP_CIPHER_CTX_cleanup(&m_ContextSV1);
	EVP_CIPHER_CTX_cleanup(&m_ContextVS1);
	EVP_CIPHER_CTX_cleanup(&m_ContextSV2);
	EVP_CIPHER_CTX_cleanup(&m_ContextVS2);
	EVP_CIPHER_CTX_cleanup(&m_ContextSV3);
	EVP_CIPHER_CTX_cleanup(&m_ContextVS3);

	if (m_rsa) {
		RSA_free(m_rsa);
		m_rsa = NULL;
	}

	if (m_rsaClientAuthPublicKey) {
		RSA_free(m_rsaClientAuthPublicKey);
		m_rsaClientAuthPublicKey = NULL;
	}

	if (m_pPasswordData) {
		delete[] m_pPasswordData;
		m_pPasswordData = NULL;
	}

	if (m_pServerIdentificationData) {
		delete[] m_pServerIdentificationData;
		m_pServerIdentificationData = NULL;
	}

	if (m_pPublicKeyRaw != NULL) {
		delete[] m_pPublicKeyRaw;
		m_pPublicKeyRaw = NULL;
	}
	
	if (m_szClientAuthPublicKeyIdentifier) {
		delete[] m_szClientAuthPublicKeyIdentifier;
		m_szClientAuthPublicKeyIdentifier = NULL;
	}

	if (m_szLastErrorString) {
		delete[] m_szLastErrorString;
		m_szLastErrorString = NULL;
	}

	if (m_szCurrentSettingsDescription) {
		delete[] m_szCurrentSettingsDescription;
		m_szCurrentSettingsDescription = NULL;
	}

	if (::InterlockedDecrement(&g_nInstanceCount) == 0) {
		OpenSSL_Cleanup();
	}
}

void IntegratedSecureVNCPlugin::Destroy() // Safe destruction (not using delete!)
{
	if (this) {
		delete this;
	}
}

int IntegratedSecureVNCPlugin::InterfaceVersion()
{
	return 2;
}

void IntegratedSecureVNCPlugin::FreeMemory(void* pMemory)
{
	if (pMemory) {
		delete[] pMemory;
	}
}

void IntegratedSecureVNCPlugin::SetServerIdentification(const BYTE* pIdentification, int nLength)
{
	if (m_pServerIdentificationData) {
		delete[] m_pServerIdentificationData;
		m_pServerIdentificationData = NULL;
	}
	m_nServerIdentificationLength = 0;

	if (nLength > 0) {		
		m_pServerIdentificationData = new BYTE[nLength];
		m_nServerIdentificationLength = nLength;
		memcpy(m_pServerIdentificationData, pIdentification, nLength);
	}
}

void IntegratedSecureVNCPlugin::SetServerOptions(LPCSTR szOptions)
{
	ConfigHelper configHelper(szOptions);
	m_dwServerOptionFlags = configHelper.m_dwFlags;

	if (configHelper.m_szPassphrase && strlen(configHelper.m_szPassphrase) > 0) {
		SetPasswordData((const BYTE*)configHelper.m_szPassphrase, (int)strlen(configHelper.m_szPassphrase));
		m_bOverridePassphrase = true;
	}
}

void IntegratedSecureVNCPlugin::SetViewerOptions(LPCSTR szOptions)
{

}

LPCSTR IntegratedSecureVNCPlugin::GetLastErrorString()
{
	return m_szLastErrorString;
}

LPCSTR IntegratedSecureVNCPlugin::DescribeCurrentSettings()
{
	if (!m_bHandshakeComplete) {
		return "In progress (no encryption)";
	}

	DWORD dwFlags = m_dwResponseFlags;

	if (dwFlags == 0) {
		return "Uninitialized (no encryption)";
	}

#define CURRENT_SETTINGS_DESCRIPTION_SIZE 256
	if (m_szCurrentSettingsDescription == NULL) {
		m_szCurrentSettingsDescription = new char[CURRENT_SETTINGS_DESCRIPTION_SIZE];
	}

	const EVP_CIPHER* pCipher = EVP_CIPHER_CTX_cipher(&m_ContextSV1);
	if (pCipher == NULL) {
		return "Error: no cipher context available!";
	}

	const char* szCipherName = NULL;
	if (!m_bTriple) {
		szCipherName = EVP_CIPHER_name(pCipher);
	} else {
		szCipherName = "3AES-CFB8";
	}
	int nKeyLength = EVP_CIPHER_CTX_key_length(&m_ContextSV1);

	char szExtra[32];
	if (m_dwChallengeFlags & svncClientAuthRequired) {
		_sntprintf_s(szExtra, 32 - 2, _TRUNCATE, m_pPasswordData ? "Auth(RSA-%li)+PW" : "Auth(RSA-%li)", m_nClientAuthPublicKeyRSASize * 8);
	} else {
		strcpy_s(szExtra, 32 - 2, m_pPasswordData ? "PW" : "");
	}

	::ZeroMemory(m_szCurrentSettingsDescription, CURRENT_SETTINGS_DESCRIPTION_SIZE);

	_sntprintf_s(m_szCurrentSettingsDescription, CURRENT_SETTINGS_DESCRIPTION_SIZE - 2, _TRUNCATE, "%s(%li); RSA-%li; %s", szCipherName, nKeyLength * 8, m_nRSASize * 8, szExtra);

	return m_szCurrentSettingsDescription;
}

void IntegratedSecureVNCPlugin::SetLastErrorString(LPCSTR szFormat, ...)
{
#define LAST_ERROR_STRING_SIZE 512
	if (m_szLastErrorString == NULL) {
		m_szLastErrorString = new char[LAST_ERROR_STRING_SIZE];
	}

	::ZeroMemory(m_szLastErrorString, LAST_ERROR_STRING_SIZE);

	if (szFormat == NULL || szFormat[0] == '\0') {
		return;
	}

	va_list args;
	va_start(args, szFormat);

	_vsntprintf_s(m_szLastErrorString, LAST_ERROR_STRING_SIZE - 2, _TRUNCATE, szFormat, args);
}

void IntegratedSecureVNCPlugin::SetHandshakeComplete()
{
	m_bHandshakeComplete = true;

	if (m_rsa) {
		RSA_free(m_rsa);
		m_rsa = NULL;
	}

	if (m_rsaClientAuthPublicKey) {
		RSA_free(m_rsaClientAuthPublicKey);
		m_rsaClientAuthPublicKey = NULL;
	}

	if (m_pPublicKeyRaw != NULL) {
		delete[] m_pPublicKeyRaw;
		m_pPublicKeyRaw = NULL;
	}
	
	if (m_szClientAuthPublicKeyIdentifier) {
		delete[] m_szClientAuthPublicKeyIdentifier;
		m_szClientAuthPublicKeyIdentifier = NULL;
	}
}

bool IntegratedSecureVNCPlugin::EncryptBytesWithKey(const BYTE* pPlainData, int nPlainDataLength, const BYTE* pPassphrase, int nPassphraseLength, BYTE*& pEncryptedData, int& nEncryptedDataLength, bool bIncludeHash)
{
	return CipherWithKey(true, pPlainData, nPlainDataLength, pPassphrase, nPassphraseLength, pEncryptedData, nEncryptedDataLength, bIncludeHash);
}

bool IntegratedSecureVNCPlugin::DecryptBytesWithKey(const BYTE* pEncryptedData, int nEncryptedDataLength, const BYTE* pPassphrase, int nPassphraseLength, BYTE*& pPlainData, int& nPlainDataLength, bool bIncludeHash)
{
	return CipherWithKey(false, pEncryptedData, nEncryptedDataLength, pPassphrase, nPassphraseLength, pPlainData, nPlainDataLength, bIncludeHash);
}

bool IntegratedSecureVNCPlugin::CipherWithKey(bool bEncrypt, const BYTE* pInputData, int nInputDataLength, const BYTE* pPassphrase, int nPassphraseLength, BYTE*& pOutputData, int& nOutputDataLength, bool bIncludeHash)
{	
	SetLastErrorString("Begin cipher operation.");

	const BYTE* pInputDataPos = pInputData;
	pOutputData = NULL;
	nOutputDataLength = 0;

	EVP_CIPHER_CTX Context;
	EVP_CIPHER_CTX_init(&Context);
	const EVP_CIPHER* pCipher = EVP_aes_256_ofb();

	BYTE messageDigest[EVP_MAX_MD_SIZE];
	unsigned int messageDigestLength = 0;
	EVP_MD_CTX digestContext;
	EVP_DigestInit(&digestContext, EVP_sha1());


	int nIVLength = EVP_CIPHER_iv_length(pCipher);
	int nKeySize = EVP_CIPHER_key_length(pCipher);

	AutoBlob<> blobIV(nIVLength);

	if (bEncrypt) {
		RAND_bytes(blobIV, nIVLength);
	} else {
		memcpy(blobIV, pInputData, nIVLength);
		pInputDataPos += nIVLength;
		nInputDataLength -= nIVLength;
	}

	// salt the hash with the IV
	EVP_DigestUpdate(&digestContext, blobIV, nIVLength);

	if (!bEncrypt && bIncludeHash) {
		// don't include the hash!
		nInputDataLength -= EVP_MD_CTX_size(&digestContext);
	}

	AutoBlob<> blobKey(nKeySize);
	if (!EVP_BytesToKey(pCipher, EVP_sha1(), NULL, pPassphrase, nPassphraseLength, 11, blobKey, NULL)) {
		EVP_MD_CTX_cleanup(&digestContext);

		SetLastErrorString("Failed to create key from passphrase.");

		return false;
	}

	EVP_CipherInit_ex(&Context, pCipher, NULL, blobKey, blobIV, bEncrypt ? 1 : 0);

	int nOutputByteCount = 0;
	AutoBlob<> blobOutputDataTemp(nInputDataLength + 32);
	if (!EVP_CipherUpdate(&Context, blobOutputDataTemp, &nOutputByteCount, pInputDataPos, nInputDataLength)) {
		EVP_MD_CTX_cleanup(&digestContext);

		SetLastErrorString("Cipher operation failed.");

		return false;
	}
	
	if (bIncludeHash) {
		if (bEncrypt) {		
			// prepare the hash of the input data
			EVP_DigestUpdate(&digestContext, pInputDataPos, nInputDataLength);
			EVP_DigestFinal(&digestContext, messageDigest, &messageDigestLength);
		} else {
			// prepare the hash of the output data
			EVP_DigestUpdate(&digestContext, blobOutputDataTemp, nOutputByteCount);
			EVP_DigestFinal(&digestContext, messageDigest, &messageDigestLength);
		}
	}

	pInputDataPos += nInputDataLength;

	EVP_MD_CTX_cleanup(&digestContext);

	bool bHashOK = false;

	if (bEncrypt) {
		bHashOK = true;
		nOutputDataLength = nIVLength + nOutputByteCount;

		if (bIncludeHash) {
			nOutputDataLength += messageDigestLength;
		}

		pOutputData = new BYTE[nOutputDataLength];

		BYTE* pOutputDataPos = pOutputData;

		memcpy(pOutputDataPos, blobIV, nIVLength);
		pOutputDataPos += nIVLength;

		memcpy(pOutputDataPos, blobOutputDataTemp, nOutputByteCount);
		pOutputDataPos += nOutputByteCount;

		if (bIncludeHash) {
			memcpy(pOutputDataPos, messageDigest, messageDigestLength);
		}
	} else {
		nOutputDataLength = nOutputByteCount;
		pOutputData = new BYTE[nOutputDataLength];

		memcpy(pOutputData, blobOutputDataTemp, nOutputDataLength);

		if (bIncludeHash) {
			if (memcmp(messageDigest, pInputDataPos, messageDigestLength) == 0) {
				bHashOK = true;
			} else {
				bHashOK = false;

				SetLastErrorString("Hash comparison failed -- wrong passphrase?");
			}
		}
	}

	EVP_CIPHER_CTX_cleanup(&Context);

	if (bHashOK) {
		SetLastErrorString("Cipher operation OK.");
	}

	return bHashOK;
}


// 
// TransformBuffer function
//
// Transform the data given in pDataBuffer then return the pointer on the allocated 
// buffer containing the resulting data.
// The length of the resulting data is given by pnTransformedDataLen
//	
BYTE* IntegratedSecureVNCPlugin::TransformBuffer(BYTE* pDataBuffer, int nDataLen, int* pnTransformedDataLen)
{
	LockCriticalSection lock(m_csEncryption);

	*pnTransformedDataLen = nDataLen;

	BYTE* pTransBuffer = EnsureLocalTransformBufferSize(nDataLen);
    if (pTransBuffer == NULL)
    {
        *pnTransformedDataLen = -1;
        return NULL;
    }

	TransformBufferInternal(pDataBuffer, nDataLen, pTransBuffer);

	return pTransBuffer;
}

void IntegratedSecureVNCPlugin::TransformBufferTo(const BYTE* pDataBuffer, int nDataLen, BYTE* pOutputBuffer)
{
	LockCriticalSection lock(m_csEncryption);

	TransformBufferInternal(pDataBuffer, nDataLen, pOutputBuffer);
}

void IntegratedSecureVNCPlugin::TransformBufferInternal(const BYTE* pDataBuffer, int nDataLen, BYTE* pOutputBuffer)
{
	if (nDataLen > 0) {
		if (m_bHandshakeComplete) {

			int nEncryptedLength = 0;

			if (m_bTriple) {
				BYTE* pTempBuffer = EnsureLocalTransformTempBufferSize(nDataLen);
				int nEncryptedLength2 = 0;
				int nEncryptedLength3 = 0;

				if (m_bIsServer) {
					EVP_CipherUpdate(&m_ContextSV1, pOutputBuffer, &nEncryptedLength, pDataBuffer, nDataLen);
					EVP_CipherUpdate(&m_ContextSV2, pTempBuffer, &nEncryptedLength2, pOutputBuffer, nEncryptedLength);
					EVP_CipherUpdate(&m_ContextSV3, pOutputBuffer, &nEncryptedLength3, pTempBuffer, nEncryptedLength2);
				} else if (m_bIsViewer) {
					EVP_CipherUpdate(&m_ContextVS1, pOutputBuffer, &nEncryptedLength, pDataBuffer, nDataLen);
					EVP_CipherUpdate(&m_ContextVS2, pTempBuffer, &nEncryptedLength2, pOutputBuffer, nEncryptedLength);
					EVP_CipherUpdate(&m_ContextVS3, pOutputBuffer, &nEncryptedLength3, pTempBuffer, nEncryptedLength2);
				} else {
					SetLastErrorString("Invalid state for transform buffer.");
					memcpy(pOutputBuffer, pDataBuffer, nDataLen);
				}
			} else {
				if (m_bIsServer) {
					EVP_CipherUpdate(&m_ContextSV1, pOutputBuffer, &nEncryptedLength, pDataBuffer, nDataLen);
				} else if (m_bIsViewer) {
					EVP_CipherUpdate(&m_ContextVS1, pOutputBuffer, &nEncryptedLength, pDataBuffer, nDataLen);
				} else {
					SetLastErrorString("Invalid state for transform buffer.");
					memcpy(pOutputBuffer, pDataBuffer, nDataLen);
				}
			}
		} else {
			memcpy(pOutputBuffer, pDataBuffer, nDataLen);
		}
	}
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
BYTE* IntegratedSecureVNCPlugin::RestoreBuffer(BYTE* pTransBuffer, int nTransDataLen, int* pnRestoredDataLen)
{
	LockCriticalSection lock(m_csEncryption);
	
    *pnRestoredDataLen = nTransDataLen;
		
	BYTE* pRestBuffer = EnsureLocalRestoreBufferSize(nTransDataLen);

	RestoreBufferInternal(pRestBuffer, nTransDataLen, pTransBuffer);

	return pRestBuffer;
}

void IntegratedSecureVNCPlugin::RestoreBufferTo(const BYTE* pDataBuffer, int nDataLen, BYTE* pOutputBuffer)
{
	LockCriticalSection lock(m_csEncryption);

	RestoreBufferInternal(pDataBuffer, nDataLen, pOutputBuffer);
}

void IntegratedSecureVNCPlugin::RestoreBufferInternal(const BYTE* pDataBuffer, int nDataLen, BYTE* pOutputBuffer)
{    
	// If given buffer is NULL, just return the pointer.
    if (pOutputBuffer != NULL)
    {	
		if (nDataLen > 0) {
			if (m_bHandshakeComplete) {

				int nEncryptedLength = 0;

				if (m_bTriple) {
					BYTE* pTempBuffer = EnsureLocalRestoreTempBufferSize(nDataLen);
					int nEncryptedLength2 = 0;
					int nEncryptedLength3 = 0;

					if (m_bIsServer) {
						EVP_CipherUpdate(&m_ContextVS3, pOutputBuffer, &nEncryptedLength, pDataBuffer, nDataLen);
						EVP_CipherUpdate(&m_ContextVS2, pTempBuffer, &nEncryptedLength2, pOutputBuffer, nEncryptedLength);
						EVP_CipherUpdate(&m_ContextVS1, pOutputBuffer, &nEncryptedLength3, pTempBuffer, nEncryptedLength2);
					} else if (m_bIsViewer) {
						EVP_CipherUpdate(&m_ContextSV3, pOutputBuffer, &nEncryptedLength, pDataBuffer, nDataLen);
						EVP_CipherUpdate(&m_ContextSV2, pTempBuffer, &nEncryptedLength2, pOutputBuffer, nEncryptedLength);
						EVP_CipherUpdate(&m_ContextSV1, pOutputBuffer, &nEncryptedLength3, pTempBuffer, nEncryptedLength2);
					} else {
						SetLastErrorString("Invalid state for restore buffer.");
						memcpy(pOutputBuffer, pDataBuffer, nDataLen);
					}
				} else {
					if (m_bIsServer) {
						EVP_CipherUpdate(&m_ContextVS1, pOutputBuffer, &nEncryptedLength, pDataBuffer, nDataLen);
					} else if (m_bIsViewer) {
						EVP_CipherUpdate(&m_ContextSV1, pOutputBuffer, &nEncryptedLength, pDataBuffer, nDataLen);
					} else {
						SetLastErrorString("Invalid state for restore buffer.");
						memcpy(pOutputBuffer, pDataBuffer, nDataLen);
					}
				}
			} else {
				memcpy(pOutputBuffer, pDataBuffer, nDataLen);
			}
		}
    }
}

// server
void IntegratedSecureVNCPlugin::SetPasswordData(const BYTE* pPasswordData, int nLength)
{
	if (m_bOverridePassphrase) {
		SetLastErrorString("Using passphrase override.");
		return;
	}

	if (m_pPasswordData) {
		delete[] m_pPasswordData;
		m_pPasswordData = NULL;
	}
	m_nPasswordDataLength = 0;

	if (nLength > 0) {
		m_pPasswordData = new BYTE[nLength];
		m_nPasswordDataLength = nLength;
		memcpy(m_pPasswordData, pPasswordData, nLength);
	}
}

bool IntegratedSecureVNCPlugin::GetChallenge(BYTE*& pChallenge, int& nChallengeLength, int nSequenceNumber) 
{
	LockCriticalSection lock(m_csEncryption);
	SetLastErrorString("Begin GetChallenge.");

	m_bIsServer = true;

	if (m_dwServerOptionFlags == 0 || m_dwServerOptionFlags == ULONG_MAX) {
		m_dwChallengeFlags = svncCipherAES | svncKey256 | svncNewKey;
	} else {
		m_dwChallengeFlags = m_dwServerOptionFlags & ~svncConfigMask;
	}

	if (0 == CheckBestSupportedFlags(m_dwChallengeFlags)) {
		// Something must be messed up in the settings. Revert to svncCipherAES | svncKey256
		m_dwChallengeFlags = svncCipherAES | svncKey256 | svncNewKey;
	}
	DebugLog("GetChallenge m_dwServerOptionFlags 0x%08x\r\n", m_dwServerOptionFlags);

	int nRSASize = 256;
	if (m_dwServerOptionFlags & svncConfigRSA1024) {
		nRSASize = 128;
	} else if (m_dwServerOptionFlags & svncConfigRSA512) {
		nRSASize = 64;
	} else if (m_dwServerOptionFlags & svncConfigRSA3072) {
		nRSASize = 384;
	}

	DebugLog("Intended RSA size %li\r\n", nRSASize);

	if (m_rsa != NULL) {
		RSA_free(m_rsa);
		m_rsa = NULL;
		m_nRSASize = 0;
	}	

	m_rsa = LoadOrCreatePrivateKey(nRSASize);

	if (m_rsa == NULL) {
		// Error
		DebugLog(_T("Failed to load or create RSA private key!\r\n"));
		SetLastErrorString("Failed to load or create RSA private key!");
		return false;
	}

	m_nRSASize = RSA_size(m_rsa);
	DebugLog("Created RSA key size %li\r\n", m_nRSASize);

	if (m_nRSASize < 128) {
		m_dwChallengeFlags = m_dwChallengeFlags & ~(svncKey448 | svncKey256);
	}

	if (m_bOverridePassphrase) {
		m_dwChallengeFlags |= svncOverridePassphrase;
	}

	if (m_dwServerOptionFlags & svncConfigLowKey) {
		m_dwChallengeFlags |= (svncLowKey | svncNewKey);
	}
	
	if (m_dwServerOptionFlags & svncConfigNewKey) {
		m_dwChallengeFlags |= svncNewKey;
	}

	char szClientAuthPublicKeyIdentifier[_MAX_PATH];
	szClientAuthPublicKeyIdentifier[0] = '\0';
	WORD wClientAuthPublicKeyIdentifierLength = 0;

	m_rsaClientAuthPublicKey = LoadClientAuthPublicKey(szClientAuthPublicKeyIdentifier);

	if (m_rsaClientAuthPublicKey) {
		m_dwChallengeFlags |= svncClientAuthRequired;
		wClientAuthPublicKeyIdentifierLength = (WORD)strlen(szClientAuthPublicKeyIdentifier);
		m_nClientAuthPublicKeyRSASize = RSA_size(m_rsaClientAuthPublicKey);
	} else {
		szClientAuthPublicKeyIdentifier[0] = '\0';
		m_nClientAuthPublicKeyRSASize = 0;
	}

	m_nPublicKeyRawLength = i2d_RSAPublicKey(m_rsa, &m_pPublicKeyRaw);

	BYTE Salt[8];
	RAND_bytes(Salt, 8);
	
	// prepare a hash of the salt + plaintext public key
	unsigned int messageDigestLength = 0;
	AutoBlob<> blobMessageDigest(EVP_MAX_MD_SIZE);
	{		
		EVP_MD_CTX digestContext;
		EVP_DigestInit(&digestContext, EVP_sha1());
		EVP_DigestUpdate(&digestContext, Salt, 8);
		EVP_DigestUpdate(&digestContext, m_pPublicKeyRaw, m_nPublicKeyRawLength);
		EVP_DigestFinal(&digestContext, blobMessageDigest, &messageDigestLength);
		EVP_MD_CTX_cleanup(&digestContext);
	}

	const BYTE* pPasswordData = m_pPasswordData;
	int nPasswordDataLength = m_nPasswordDataLength;

	if (pPasswordData == NULL || nPasswordDataLength == 0) {
		pPasswordData = g_DefaultPassword;
		nPasswordDataLength = sizeof(g_DefaultPassword);
	}

	EVP_CIPHER_CTX InitialContext;
	EVP_CIPHER_CTX_init(&InitialContext);

	int nKeySize = 0;
	const EVP_CIPHER* pCipher = NULL;
	if (m_dwChallengeFlags & svncLowKey) {
		pCipher = EVP_bf_ofb();
		nKeySize = 56 / 8;		
		
		EVP_CipherInit(&InitialContext, pCipher, NULL, NULL, 1);
		EVP_CIPHER_CTX_set_key_length(&InitialContext, nKeySize);
	} else {
		pCipher = EVP_aes_256_ofb();
		nKeySize = EVP_CIPHER_key_length(pCipher);		

		EVP_CipherInit(&InitialContext, pCipher, NULL, NULL, 1);
	}
	//EVP_CIPHER_CTX_set_key_length
	AutoBlob<> blobInitialKey(nKeySize);

	int nIVLength = EVP_CIPHER_iv_length(pCipher);
	AutoBlob<> blobInitialKeyIV(nIVLength);
	
	if (m_dwChallengeFlags & svncNewKey) {
		PKCS5_PBKDF2_HMAC_SHA1((const char*)pPasswordData, nPasswordDataLength, Salt, sizeof(Salt), 0x1001, nKeySize, blobInitialKey.data);
		RAND_bytes(blobInitialKeyIV.data, blobInitialKeyIV.length);
	} else {
		EVP_BytesToKey(pCipher, EVP_sha1(), Salt, pPasswordData, nPasswordDataLength, 11, blobInitialKey, blobInitialKeyIV);
	}
	
	EVP_CipherInit_ex(&InitialContext, NULL, NULL, blobInitialKey, blobInitialKeyIV, 1);

	BYTE nPluginID = 0x01;
	BYTE nPluginVersionCompatability = 0x1;
	if (m_dwChallengeFlags & svncNewKey) {
		nPluginVersionCompatability = 0x2;
	}

	WORD wPublicKeyRawLength = (WORD)m_nPublicKeyRawLength;

	nChallengeLength = sizeof(nPluginID) + sizeof(nPluginVersionCompatability) + sizeof(m_nServerIdentificationLength) + m_nServerIdentificationLength + sizeof(m_dwChallengeFlags) + sizeof(wClientAuthPublicKeyIdentifierLength) + (sizeof(char) * wClientAuthPublicKeyIdentifierLength) + sizeof(Salt) + nIVLength + sizeof(wPublicKeyRawLength) + m_nPublicKeyRawLength + messageDigestLength;
	pChallenge = new BYTE[nChallengeLength];

	BYTE* pChallengeData = pChallenge;

	memcpy(pChallengeData, &nPluginID, sizeof(nPluginID));
	pChallengeData += sizeof(nPluginID);

	memcpy(pChallengeData, &nPluginVersionCompatability, sizeof(nPluginVersionCompatability));
	pChallengeData += sizeof(nPluginVersionCompatability);

	memcpy(pChallengeData, &m_nServerIdentificationLength, sizeof(m_nServerIdentificationLength));
	pChallengeData += sizeof(m_nServerIdentificationLength);

	memcpy(pChallengeData, m_pServerIdentificationData, m_nServerIdentificationLength);
	pChallengeData += m_nServerIdentificationLength;

	memcpy(pChallengeData, &m_dwChallengeFlags, sizeof(m_dwChallengeFlags));
	pChallengeData += sizeof(m_dwChallengeFlags);

	memcpy(pChallengeData, &wClientAuthPublicKeyIdentifierLength, sizeof(wClientAuthPublicKeyIdentifierLength));
	pChallengeData += sizeof(wClientAuthPublicKeyIdentifierLength);

	if (wClientAuthPublicKeyIdentifierLength > 0) {
		memcpy(pChallengeData, szClientAuthPublicKeyIdentifier, wClientAuthPublicKeyIdentifierLength);
		pChallengeData += wClientAuthPublicKeyIdentifierLength;
	}

	memcpy(pChallengeData, Salt, sizeof(Salt));
	pChallengeData += sizeof(Salt);

	memcpy(pChallengeData, blobInitialKeyIV, nIVLength);
	pChallengeData += nIVLength;

	memcpy(pChallengeData, &wPublicKeyRawLength, sizeof(wPublicKeyRawLength));
	pChallengeData += sizeof(wPublicKeyRawLength);

	int nByteCount = 0;
	EVP_CipherUpdate(&InitialContext, pChallengeData, &nByteCount, m_pPublicKeyRaw, m_nPublicKeyRawLength);

	EVP_CIPHER_CTX_cleanup(&InitialContext);

	pChallengeData += nByteCount;

	memcpy(pChallengeData, blobMessageDigest, messageDigestLength);

	SetLastErrorString("GetChallenge OK.");

	return true;
}

bool IntegratedSecureVNCPlugin::HandleResponse(const BYTE* pResponse, int nResponseLength, int nSequenceNumber, bool& bSendChallenge)
{
	LockCriticalSection lock(m_csEncryption);

	SetLastErrorString("Begin HandleResponse.");

	bSendChallenge = false;

	if (m_rsa == NULL) {
		SetLastErrorString("Private key unavailable.");
		return false;
	}
	
	const BYTE* pMaxResponseData = pResponse + nResponseLength;
	const BYTE* pResponseData = pResponse;

	if (!SafeMemcpyFrom(&m_dwResponseFlags, pResponseData, sizeof(m_dwResponseFlags), pMaxResponseData)) return false;
	pResponseData += sizeof(m_dwResponseFlags);

	if (!AreFlagsAcceptable(m_dwChallengeFlags, m_dwResponseFlags)) {
		SetLastErrorString("Response flags 0x%08x invalid for challenge flags 0x%08x.", m_dwResponseFlags, m_dwChallengeFlags);
		return false;
	}

	int nEncryptedKeySize = 0;
	WORD wEncryptedKeySize = 0;
	if (!SafeMemcpyFrom(&wEncryptedKeySize, pResponseData, sizeof(wEncryptedKeySize), pMaxResponseData)) return false;
	pResponseData += sizeof(wEncryptedKeySize);
	nEncryptedKeySize = wEncryptedKeySize;
	
	int nKeyLength = 0;
	const EVP_CIPHER* pCipher = GetCipher(m_dwResponseFlags, nKeyLength);
	if (!pCipher) {
		SetLastErrorString("No available cipher.");
		return false;
	}
	
	EVP_CipherInit(&m_ContextSV1, pCipher, NULL, NULL, 1);
	EVP_CipherInit(&m_ContextVS1, pCipher, NULL, NULL, 0);

	EVP_CIPHER_CTX_set_key_length(&m_ContextSV1, nKeyLength);
	EVP_CIPHER_CTX_set_key_length(&m_ContextVS1, nKeyLength);

	if (m_dwResponseFlags & svncCipher3AESOFB) {
		// encrypt/decrypt swapped for key 2
		EVP_CipherInit(&m_ContextSV2, pCipher, NULL, NULL, 0);
		EVP_CipherInit(&m_ContextVS2, pCipher, NULL, NULL, 1);

		EVP_CIPHER_CTX_set_key_length(&m_ContextSV2, nKeyLength);
		EVP_CIPHER_CTX_set_key_length(&m_ContextVS2, nKeyLength);

		EVP_CipherInit(&m_ContextSV3, pCipher, NULL, NULL, 1);
		EVP_CipherInit(&m_ContextVS3, pCipher, NULL, NULL, 0);

		EVP_CIPHER_CTX_set_key_length(&m_ContextSV3, nKeyLength);
		EVP_CIPHER_CTX_set_key_length(&m_ContextVS3, nKeyLength);
	}


	if (!CheckBufferSize(pResponseData, nEncryptedKeySize, pMaxResponseData)) return false;

	int nKeyDataLength = nKeyLength * 2;
	if (m_dwChallengeFlags & svncNewKey) {
		nKeyDataLength = RSA_size(m_rsa) - 12;
	}

	AutoBlob<> blobKeys(nKeyDataLength);
	
	int nDecryptedSize = RSA_private_decrypt(nEncryptedKeySize, pResponseData, blobKeys, m_rsa, RSA_PKCS1_PADDING);

	m_bTriple = false;
	if (m_dwChallengeFlags & svncNewKey) {		

		
		if (m_dwResponseFlags & svncCipher3AESOFB) {
			m_bTriple = true;			

			AutoBlob<> blobKeySV1(nKeyLength);
			AutoBlob<> blobKeyVS1(nKeyLength);
			AutoBlob<> blobKeySV2(nKeyLength);
			AutoBlob<> blobKeyVS2(nKeyLength);
			AutoBlob<> blobKeySV3(nKeyLength);
			AutoBlob<> blobKeyVS3(nKeyLength);

			int nIVLength = EVP_CIPHER_CTX_iv_length(&m_ContextSV1);

			int nSourceLength = (blobKeys.length - nIVLength) / 6;

			PKCS5_PBKDF2_HMAC_SHA1((const char*)(blobKeys.data + (nSourceLength * 0)), nSourceLength, 0, 0, 0x1001, nKeyLength, blobKeySV1);
			PKCS5_PBKDF2_HMAC_SHA1((const char*)(blobKeys.data + (nSourceLength * 1)), nSourceLength, 0, 0, 0x1001, nKeyLength, blobKeyVS1);
			
			PKCS5_PBKDF2_HMAC_SHA1((const char*)(blobKeys.data + (nSourceLength * 2)), nSourceLength, 0, 0, 0x1001, nKeyLength, blobKeySV2);
			PKCS5_PBKDF2_HMAC_SHA1((const char*)(blobKeys.data + (nSourceLength * 3)), nSourceLength, 0, 0, 0x1001, nKeyLength, blobKeyVS2);
			
			PKCS5_PBKDF2_HMAC_SHA1((const char*)(blobKeys.data + (nSourceLength * 4)), nSourceLength, 0, 0, 0x1001, nKeyLength, blobKeySV3);
			PKCS5_PBKDF2_HMAC_SHA1((const char*)(blobKeys.data + (nSourceLength * 5)), nSourceLength, 0, 0, 0x1001, nKeyLength, blobKeyVS3);

			const BYTE* pIV = blobKeys.data + (blobKeys.length - nIVLength);

			EVP_CipherInit_ex(&m_ContextSV1, NULL, NULL, blobKeySV1, pIV, 1);
			EVP_CipherInit_ex(&m_ContextVS1, NULL, NULL, blobKeyVS1, pIV, 0);
			EVP_CipherInit_ex(&m_ContextSV2, NULL, NULL, blobKeySV2, pIV, 0); // swapped for 2
			EVP_CipherInit_ex(&m_ContextVS2, NULL, NULL, blobKeyVS2, pIV, 1);
			EVP_CipherInit_ex(&m_ContextSV3, NULL, NULL, blobKeySV3, pIV, 1);
			EVP_CipherInit_ex(&m_ContextVS3, NULL, NULL, blobKeyVS3, pIV, 0);
		} else {
			AutoBlob<> blobKeySV(nKeyLength);
			AutoBlob<> blobKeyVS(nKeyLength);
			
			int nIVLength = EVP_CIPHER_CTX_iv_length(&m_ContextSV1);

			PKCS5_PBKDF2_HMAC_SHA1((const char*)(blobKeys.data), ((blobKeys.length - nIVLength) / 2), 0, 0, 0x1001, nKeyLength, blobKeySV);
			PKCS5_PBKDF2_HMAC_SHA1((const char*)(blobKeys.data + ((blobKeys.length - nIVLength) / 2)), ((blobKeys.length - nIVLength) / 2), 0, 0, 0x1001, nKeyLength, blobKeyVS);

			const BYTE* pIV = blobKeys.data + (blobKeys.length - nIVLength);

			EVP_CipherInit_ex(&m_ContextSV1, NULL, NULL, blobKeySV, pIV, 1);
			EVP_CipherInit_ex(&m_ContextVS1, NULL, NULL, blobKeyVS, pIV, 0);
		}
	} else {		
		BYTE* pKeySV = blobKeys;
		BYTE* pKeyVS = pKeySV + nKeyLength;

		EVP_CipherInit_ex(&m_ContextSV1, NULL, NULL, pKeySV, NULL, 1);
		EVP_CipherInit_ex(&m_ContextVS1, NULL, NULL, pKeyVS, NULL, 0);
	}
	
	pResponseData += nEncryptedKeySize;

	unsigned int nClientAuthSigLength = 0;
	WORD wClientAuthSigLength = 0;
	if (!SafeMemcpyFrom(&wClientAuthSigLength, pResponseData, sizeof(wClientAuthSigLength), pMaxResponseData)) {return false;};
	pResponseData += sizeof(wClientAuthSigLength);
	nClientAuthSigLength = wClientAuthSigLength;

	bool bClientAuthOK = false;

	if (nClientAuthSigLength > 0) {
		AutoBlob<> blobClientAuthSig(nClientAuthSigLength);

		if (!SafeMemcpyFrom(blobClientAuthSig, pResponseData, nClientAuthSigLength, pMaxResponseData)) {return false;};
		
		if (m_rsaClientAuthPublicKey) {
			unsigned int messageDigestLength = 0;
			AutoBlob<> blobMessageDigest(EVP_MAX_MD_SIZE);
			
			EVP_MD_CTX digestContext;
			EVP_DigestInit(&digestContext, EVP_sha1());
			EVP_DigestUpdate(&digestContext, m_pPublicKeyRaw, m_nPublicKeyRawLength);
			EVP_DigestUpdate(&digestContext, blobKeys, nKeyDataLength);
			EVP_DigestFinal(&digestContext, blobMessageDigest, &messageDigestLength);
			EVP_MD_CTX_cleanup(&digestContext);

			int verified = RSA_verify(NID_sha1, blobMessageDigest, messageDigestLength, blobClientAuthSig, nClientAuthSigLength, m_rsaClientAuthPublicKey);

			if (!verified) {
				SetLastErrorString("Response failed client authentication.");
			} else {
				bClientAuthOK = true;
			}
		} else {
			SetLastErrorString("Public key unavailable for client authentication.");
		}
	} else {
		// verify client auth required
		SetLastErrorString("Handshake response lacked client authentication key.");
		bClientAuthOK = (m_dwChallengeFlags & svncClientAuthRequired) ? false : true;
	}

	if (!bClientAuthOK) {
		return false;
	}

	if (m_dwResponseFlags & svncCipherARC4) {
		AutoBlob<> blobFlotsam(RC4_DROP_BYTES);
		AutoBlob<> blobJetsam(RC4_DROP_BYTES);
		int nDummyByteCount = 0;
		EVP_CipherUpdate(&m_ContextSV1, (BYTE*)blobFlotsam, &nDummyByteCount, blobJetsam, RC4_DROP_BYTES);
		EVP_CipherUpdate(&m_ContextVS1, (BYTE*)blobFlotsam, &nDummyByteCount, blobJetsam, RC4_DROP_BYTES);
	}

	SetLastErrorString("HandleResponse OK.");

	return true;
}

// client
bool IntegratedSecureVNCPlugin::HandleChallenge(const BYTE* pChallenge, int nChallengeLength, int nSequenceNumber, bool& bPasswordOK, bool& bPassphraseRequired)
{
	LockCriticalSection lock(m_csEncryption);

	SetLastErrorString("Begin HandleChallenge.");

	bPasswordOK = false;
	bPassphraseRequired = false;

	if (m_rsa != NULL) {
		RSA_free(m_rsa);
		m_rsa = NULL;
		m_nRSASize = 0;
	}	

	const BYTE* pMaxChallengeData = pChallenge + nChallengeLength;
	const BYTE* pChallengeData = pChallenge;
	
	BYTE nPluginID = 0;
	BYTE nPluginVersionCompatability = 0;

	if (!SafeMemcpyFrom(&nPluginID, pChallengeData, sizeof(nPluginID), pMaxChallengeData)) return false;
	pChallengeData += sizeof(nPluginID);

	if(nPluginID != 0x1) {
		SetLastErrorString("Plugin ID %lu is incompatible with SecureVNCPlugin.", (long)nPluginID);
		return false;
	}

	if (!SafeMemcpyFrom(&nPluginVersionCompatability, pChallengeData, sizeof(nPluginVersionCompatability), pMaxChallengeData)) return false;
	pChallengeData += sizeof(nPluginVersionCompatability);

	if(nPluginVersionCompatability > 0x03) {
		SetLastErrorString("Plugin compatibility level %lu is incompatible with this version of SecureVNCPlugin.", (long)nPluginVersionCompatability);
		return false;
	}

	int nServerIdentificationLength = 0;
	if (!SafeMemcpyFrom(&nServerIdentificationLength, pChallengeData, sizeof(nServerIdentificationLength), pMaxChallengeData)) return false;
	pChallengeData += sizeof(nServerIdentificationLength);

	if (nServerIdentificationLength > 0) {
		if (m_pServerIdentificationData) {
			delete[] m_pServerIdentificationData;
		}

		m_pServerIdentificationData = new BYTE[nServerIdentificationLength];

		if (!SafeMemcpyFrom(m_pServerIdentificationData, pChallengeData, nServerIdentificationLength, pMaxChallengeData)) return false;

		m_nServerIdentificationLength = nServerIdentificationLength;
	} else {
		if (m_pServerIdentificationData) {
			delete[] m_pServerIdentificationData;
		}
		m_pServerIdentificationData = NULL;
		m_nServerIdentificationLength = 0;
	}
	pChallengeData += nServerIdentificationLength;

	if (!SafeMemcpyFrom(&m_dwChallengeFlags, pChallengeData, sizeof(m_dwChallengeFlags), pMaxChallengeData)) return false;
	pChallengeData += sizeof(m_dwChallengeFlags);

	if (m_dwChallengeFlags & svncOverridePassphrase) {
		bPassphraseRequired = true;
	}

	WORD wClientAuthPublicKeyIdentifierLength = 0;	
	if (!SafeMemcpyFrom(&wClientAuthPublicKeyIdentifierLength, pChallengeData, sizeof(wClientAuthPublicKeyIdentifierLength), pMaxChallengeData)) return false;
	pChallengeData += sizeof(wClientAuthPublicKeyIdentifierLength);

	if (wClientAuthPublicKeyIdentifierLength >= _MAX_PATH) {
		SetLastErrorString("Public key identifier length invalid.");
		return false;
	}

	if (m_szClientAuthPublicKeyIdentifier) {
		delete[] m_szClientAuthPublicKeyIdentifier;
		m_szClientAuthPublicKeyIdentifier = NULL;
	}
	if (wClientAuthPublicKeyIdentifierLength > 0) {
		m_szClientAuthPublicKeyIdentifier = new char[wClientAuthPublicKeyIdentifierLength + 1];
		if (!SafeMemcpyFrom(m_szClientAuthPublicKeyIdentifier, pChallengeData, wClientAuthPublicKeyIdentifierLength, pMaxChallengeData)) return false;

		m_szClientAuthPublicKeyIdentifier[wClientAuthPublicKeyIdentifierLength] = '\0';

		pChallengeData += wClientAuthPublicKeyIdentifierLength;
	}

	BYTE Salt[8];
	if (!SafeMemcpyFrom(Salt, pChallengeData, sizeof(Salt), pMaxChallengeData)) return false;
	pChallengeData += sizeof(Salt);
	
	// prepare a hash of the salt + plaintext public key
	unsigned int messageDigestLength = 0;
	AutoBlob<> blobMessageDigest(EVP_MAX_MD_SIZE);
	EVP_MD_CTX digestContext;
	EVP_DigestInit(&digestContext, EVP_sha1());
	EVP_DigestUpdate(&digestContext, Salt, 8);

	const BYTE* pPasswordData = m_pPasswordData;
	DWORD nPasswordDataLength = m_nPasswordDataLength;

	if (pPasswordData == NULL || nPasswordDataLength == 0) {
		pPasswordData = g_DefaultPassword;
		nPasswordDataLength = sizeof(g_DefaultPassword);
	}

	EVP_CIPHER_CTX InitialContext;
	EVP_CIPHER_CTX_init(&InitialContext);
	
	int nKeySize = 0;
	const EVP_CIPHER* pCipher = NULL;
	if (m_dwChallengeFlags & svncLowKey) {
		pCipher = EVP_bf_ofb();
		nKeySize = 56 / 8;		
		EVP_CipherInit(&InitialContext, pCipher, NULL, NULL, 0);
		EVP_CIPHER_CTX_set_key_length(&InitialContext, nKeySize);
	} else {
		pCipher = EVP_aes_256_ofb();
		EVP_CipherInit(&InitialContext, pCipher, NULL, NULL, 0);

		nKeySize = EVP_CIPHER_key_length(pCipher);		
	}
	int nIVLength = EVP_CIPHER_iv_length(pCipher);

	AutoBlob<> blobInitialKeyIV(nIVLength);
	if (!SafeMemcpyFrom(blobInitialKeyIV, pChallengeData, nIVLength, pMaxChallengeData)) {return false;};
	pChallengeData += nIVLength;

	int nPublicKeyLength = 0;
	WORD wPublicKeyLength = 0;
	if (!SafeMemcpyFrom(&wPublicKeyLength, pChallengeData, sizeof(wPublicKeyLength), pMaxChallengeData)) {return false;};
	pChallengeData += sizeof(wPublicKeyLength);
	nPublicKeyLength = wPublicKeyLength;

	AutoBlob<> blobInitialKey(nKeySize);

	if (m_dwChallengeFlags & svncNewKey) {
		PKCS5_PBKDF2_HMAC_SHA1((const char*)pPasswordData, nPasswordDataLength, Salt, sizeof(Salt), 0x1001, nKeySize, blobInitialKey.data);
	} else {
		EVP_BytesToKey(pCipher, EVP_sha1(), Salt, pPasswordData, nPasswordDataLength, 11, blobInitialKey, NULL);
	}

	EVP_CipherInit_ex(&InitialContext, NULL, NULL, blobInitialKey, blobInitialKeyIV, 0);

	if (!CheckBufferSize(pChallengeData, nPublicKeyLength, pMaxChallengeData)) {return false;};

	if (m_pPublicKeyRaw) {
		delete[] m_pPublicKeyRaw;
		m_pPublicKeyRaw = NULL;
	}
	m_pPublicKeyRaw = new BYTE[nPublicKeyLength];
	EVP_CipherUpdate(&InitialContext, m_pPublicKeyRaw, &m_nPublicKeyRawLength, pChallengeData, nPublicKeyLength); 
	pChallengeData += nPublicKeyLength;

	// include the newly-decrypted key in our hash, and finalize.
	EVP_DigestUpdate(&digestContext, m_pPublicKeyRaw, m_nPublicKeyRawLength);
	EVP_DigestFinal(&digestContext, blobMessageDigest, &messageDigestLength);
	EVP_MD_CTX_cleanup(&digestContext);

	// compare our hash with the one sent to us
	bool bMatch = false;
	if (memcmp(pChallengeData, blobMessageDigest, EVP_MD_size(EVP_sha1())) == 0) {
		bMatch = true;
	}
	
	EVP_CIPHER_CTX_cleanup(&InitialContext);
	
	if (bMatch) {
		BYTE* pNewBuffer = m_pPublicKeyRaw;
		m_rsa = d2i_RSAPublicKey(NULL, (const BYTE**)&pNewBuffer, m_nPublicKeyRawLength);
		if (m_rsa == NULL) {
			SetLastErrorString("Failed to load public key.");
			return false;
		} else {
			m_nRSASize = RSA_size(m_rsa);
			bPasswordOK = true;

			SetLastErrorString("HandleChallenge OK.");
			return true;
		}
	} else {
		SetLastErrorString("Password does not match.");
		bPasswordOK = false;
		return true;
	}
}

bool IntegratedSecureVNCPlugin::GetResponse(BYTE*& pResponse, int& nResponseLength, int nSequenceNumber, bool& bExpectChallenge)
{
	LockCriticalSection lock(m_csEncryption);

	SetLastErrorString("Begin GetResponse.");

	bExpectChallenge = false;
	
	if (m_rsa == NULL) {
		SetLastErrorString("Public key unavailable.");
		return false;
	}

	m_bIsViewer = true;

	m_dwResponseFlags = GetBestSupportedFlags(m_dwChallengeFlags);

	if (m_dwResponseFlags == 0) {
		SetLastErrorString("Invalid response flags.");
		return false;
	}
	
	int nKeyLength = 0;
	const EVP_CIPHER* pCipher = GetCipher(m_dwResponseFlags, nKeyLength);
	if (!pCipher) {
		SetLastErrorString("No available cipher.");
		return false;
	}
	
	EVP_CipherInit(&m_ContextSV1, pCipher, NULL, NULL, 0);
	EVP_CipherInit(&m_ContextVS1, pCipher, NULL, NULL, 1);

	EVP_CIPHER_CTX_set_key_length(&m_ContextSV1, nKeyLength);
	EVP_CIPHER_CTX_set_key_length(&m_ContextVS1, nKeyLength);

	if (m_dwResponseFlags & svncCipher3AESOFB) {
		// encrypt/decrypt swapped for key 2
		EVP_CipherInit(&m_ContextSV2, pCipher, NULL, NULL, 1);
		EVP_CipherInit(&m_ContextVS2, pCipher, NULL, NULL, 0);

		EVP_CIPHER_CTX_set_key_length(&m_ContextSV2, nKeyLength);
		EVP_CIPHER_CTX_set_key_length(&m_ContextVS2, nKeyLength);
		
		EVP_CipherInit(&m_ContextSV3, pCipher, NULL, NULL, 0);
		EVP_CipherInit(&m_ContextVS3, pCipher, NULL, NULL, 1);

		EVP_CIPHER_CTX_set_key_length(&m_ContextSV3, nKeyLength);
		EVP_CIPHER_CTX_set_key_length(&m_ContextVS3, nKeyLength);
	}

	int nKeyDataLength = nKeyLength * 2;

	if (m_dwChallengeFlags & svncNewKey) {
		nKeyDataLength = RSA_size(m_rsa) - 12;
	}

	AutoBlob<> blobKeys(nKeyDataLength);


	m_bTriple = false;
	if (m_dwChallengeFlags & svncNewKey) {
		RAND_bytes(blobKeys.data, blobKeys.length);
		
		if (m_dwResponseFlags & svncCipher3AESOFB) {
			m_bTriple = true;

			AutoBlob<> blobKeySV1(nKeyLength);
			AutoBlob<> blobKeyVS1(nKeyLength);
			AutoBlob<> blobKeySV2(nKeyLength);
			AutoBlob<> blobKeyVS2(nKeyLength);
			AutoBlob<> blobKeySV3(nKeyLength);
			AutoBlob<> blobKeyVS3(nKeyLength);

			int nIVLength = EVP_CIPHER_CTX_iv_length(&m_ContextSV1);

			DebugLog("Using 3AES NewKey; IV %li, data %li\r\n", nIVLength, blobKeys.length);

			int nSourceLength = (blobKeys.length - nIVLength) / 6;

			PKCS5_PBKDF2_HMAC_SHA1((const char*)(blobKeys.data + (nSourceLength * 0)), nSourceLength, 0, 0, 0x1001, nKeyLength, blobKeySV1);
			PKCS5_PBKDF2_HMAC_SHA1((const char*)(blobKeys.data + (nSourceLength * 1)), nSourceLength, 0, 0, 0x1001, nKeyLength, blobKeyVS1);
			
			PKCS5_PBKDF2_HMAC_SHA1((const char*)(blobKeys.data + (nSourceLength * 2)), nSourceLength, 0, 0, 0x1001, nKeyLength, blobKeySV2);
			PKCS5_PBKDF2_HMAC_SHA1((const char*)(blobKeys.data + (nSourceLength * 3)), nSourceLength, 0, 0, 0x1001, nKeyLength, blobKeyVS2);
			
			PKCS5_PBKDF2_HMAC_SHA1((const char*)(blobKeys.data + (nSourceLength * 4)), nSourceLength, 0, 0, 0x1001, nKeyLength, blobKeySV3);
			PKCS5_PBKDF2_HMAC_SHA1((const char*)(blobKeys.data + (nSourceLength * 5)), nSourceLength, 0, 0, 0x1001, nKeyLength, blobKeyVS3);

			const BYTE* pIV = blobKeys.data + (blobKeys.length - nIVLength);
			
			EVP_CipherInit_ex(&m_ContextSV1, NULL, NULL, blobKeySV1, pIV, 0);
			EVP_CipherInit_ex(&m_ContextVS1, NULL, NULL, blobKeyVS1, pIV, 1);
			EVP_CipherInit_ex(&m_ContextSV2, NULL, NULL, blobKeySV2, pIV, 1); // swapped for 2
			EVP_CipherInit_ex(&m_ContextVS2, NULL, NULL, blobKeyVS2, pIV, 0);
			EVP_CipherInit_ex(&m_ContextSV3, NULL, NULL, blobKeySV3, pIV, 0);
			EVP_CipherInit_ex(&m_ContextVS3, NULL, NULL, blobKeyVS3, pIV, 1);
		} else {
			AutoBlob<> blobKeySV(nKeyLength);
			AutoBlob<> blobKeyVS(nKeyLength);

			int nIVLength = EVP_CIPHER_CTX_iv_length(&m_ContextSV1);

			DebugLog("Using NewKey; IV %li, data %li\r\n", nIVLength, blobKeys.length);

			PKCS5_PBKDF2_HMAC_SHA1((const char*)(blobKeys.data), ((blobKeys.length - nIVLength) / 2), 0, 0, 0x1001, nKeyLength, blobKeySV);
			PKCS5_PBKDF2_HMAC_SHA1((const char*)(blobKeys.data + ((blobKeys.length - nIVLength) / 2)), ((blobKeys.length - nIVLength) / 2), 0, 0, 0x1001, nKeyLength, blobKeyVS);
			
			const BYTE* pIV = blobKeys.data + (blobKeys.length - nIVLength);

			EVP_CipherInit_ex(&m_ContextSV1, NULL, NULL, blobKeySV, pIV, 0);
			EVP_CipherInit_ex(&m_ContextVS1, NULL, NULL, blobKeyVS, pIV, 1);
		}
	} else {
		BYTE* pKeySV = blobKeys;
		BYTE* pKeyVS = pKeySV + nKeyLength;
		
		EVP_CIPHER_CTX_rand_key(&m_ContextSV1, pKeySV);
		EVP_CIPHER_CTX_rand_key(&m_ContextVS1, pKeyVS);

		EVP_CipherInit_ex(&m_ContextSV1, NULL, NULL, pKeySV, NULL, 0);
		EVP_CipherInit_ex(&m_ContextVS1, NULL, NULL, pKeyVS, NULL, 1);
	}

	
	AutoBlob<> blobEncryptedKeysBuffer(RSA_size(m_rsa));
	
	int nEncryptedSize = RSA_public_encrypt(blobKeys.length, blobKeys.data, blobEncryptedKeysBuffer, m_rsa, RSA_PKCS1_PADDING);
	if (nEncryptedSize == -1) {
		SetLastErrorString("Failed to encrypt symmetric keys.");
		return false;
	}

	AutoBlob<> blobClientAuthSig;
	unsigned int nClientAuthSigLength = 0;
	if (m_dwChallengeFlags & svncClientAuthRequired) {
		// Sign with the Client Authentication private key
		RSA* rsaClientAuth = LoadClientAuthPrivateKey(m_szClientAuthPublicKeyIdentifier);

		if (rsaClientAuth) {
			m_nClientAuthPublicKeyRSASize = RSA_size(rsaClientAuth);
			unsigned int messageDigestLength = 0;
			AutoBlob<> blobMessageDigest(EVP_MAX_MD_SIZE);
			
			EVP_MD_CTX digestContext;
			EVP_DigestInit(&digestContext, EVP_sha1());
			EVP_DigestUpdate(&digestContext, m_pPublicKeyRaw, m_nPublicKeyRawLength);
			EVP_DigestUpdate(&digestContext, blobKeys, nKeyDataLength);
			EVP_DigestFinal(&digestContext, blobMessageDigest, &messageDigestLength);

			blobClientAuthSig.Alloc(RSA_size(rsaClientAuth));
			RSA_sign(NID_sha1, blobMessageDigest, messageDigestLength, blobClientAuthSig, &nClientAuthSigLength, rsaClientAuth);

			RSA_free(rsaClientAuth);
		} else {
			m_nClientAuthPublicKeyRSASize = 0;
			SetLastErrorString("Client authentication private key unavailable.");
		}
	}

	WORD wEncryptedSize = (WORD)nEncryptedSize;
	WORD wClientAuthSigLength = (WORD)nClientAuthSigLength;

	nResponseLength = sizeof(m_dwResponseFlags) + sizeof(wEncryptedSize) + nEncryptedSize + sizeof(wClientAuthSigLength) + nClientAuthSigLength;
	pResponse = new BYTE[nResponseLength];
	BYTE* pResponseData = pResponse;

	memcpy(pResponseData, &m_dwResponseFlags, sizeof(m_dwResponseFlags));
	pResponseData += sizeof(m_dwResponseFlags);

	memcpy(pResponseData, &wEncryptedSize, sizeof(wEncryptedSize));
	pResponseData += sizeof(wEncryptedSize);

	memcpy(pResponseData, blobEncryptedKeysBuffer, nEncryptedSize);
	pResponseData += nEncryptedSize;

	memcpy(pResponseData, &wClientAuthSigLength, sizeof(wClientAuthSigLength));
	pResponseData += sizeof(wClientAuthSigLength);

	memcpy(pResponseData, blobClientAuthSig, nClientAuthSigLength);
	pResponseData += nClientAuthSigLength;

	if (m_dwResponseFlags & svncCipherARC4) {
		AutoBlob<> blobFlotsam(RC4_DROP_BYTES);
		AutoBlob<> blobJetsam(RC4_DROP_BYTES);
		int nDummyByteCount = 0;
		EVP_CipherUpdate(&m_ContextSV1, (BYTE*)blobFlotsam, &nDummyByteCount, blobJetsam, RC4_DROP_BYTES);
		EVP_CipherUpdate(&m_ContextVS1, (BYTE*)blobFlotsam, &nDummyByteCount, blobJetsam, RC4_DROP_BYTES);
	}

	SetLastErrorString("GetResponse OK.");

	return true;
}

const EVP_CIPHER* IntegratedSecureVNCPlugin::GetCipher(DWORD dwFlags, int& nKeyLength)
{
	nKeyLength = 0;

	if (dwFlags & svncCipher3AESOFB) {
		if (dwFlags & svncKey256) {
			nKeyLength = 256 / 8;
			return EVP_aes_256_cfb8();
		} else if (dwFlags & svncKey192) {
			nKeyLength = 192 / 8;
			return EVP_aes_192_cfb8();
		} else if (dwFlags & svncKey128) {
			nKeyLength = 128 / 8;
			return EVP_aes_128_cfb8();
		} else {
			SetLastErrorString("Invalid keysize for cipher (flags 0x%08x).", dwFlags);
			return NULL;
		}
	} else if (dwFlags & svncCipherAESCFB) {
		if (dwFlags & svncKey256) {
			nKeyLength = 256 / 8;
			return EVP_aes_256_cfb8();
		} else if (dwFlags & svncKey192) {
			nKeyLength = 192 / 8;
			return EVP_aes_192_cfb8();
		} else if (dwFlags & svncKey128) {
			nKeyLength = 128 / 8;
			return EVP_aes_128_cfb8();
		} else {
			SetLastErrorString("Invalid keysize for cipher (flags 0x%08x).", dwFlags);
			return NULL;
		}
	} else if (dwFlags & svncCipherAES) {
		if (dwFlags & svncKey256) {
			nKeyLength = 256 / 8;
			return EVP_aes_256_ofb();
		} else if (dwFlags & svncKey192) {
			nKeyLength = 192 / 8;
			return EVP_aes_192_ofb();
		} else if (dwFlags & svncKey128) {
			nKeyLength = 128 / 8;
			return EVP_aes_128_ofb();
		} else {
			SetLastErrorString("Invalid keysize for cipher (flags 0x%08x).", dwFlags);
			return NULL;
		}
	} else if (dwFlags & svncCipherBlowfish) {		
		if (dwFlags & svncKey448) {
			nKeyLength = 448 / 8;
			return EVP_bf_ofb();
		} else if (dwFlags & svncKey256) {
			nKeyLength = 256 / 8;
			return EVP_bf_ofb();
		} else if (dwFlags & svncKey192) {
			nKeyLength = 192 / 8;
			return EVP_bf_ofb();
		} else if (dwFlags & svncKey128) {
			nKeyLength = 128 / 8;
			return EVP_bf_ofb();
		} else {
			SetLastErrorString("Invalid keysize for cipher (flags 0x%08x).", dwFlags);
			return NULL;
		}
	} else if (dwFlags & svncCipherIDEA) {	
		if (dwFlags & svncKey128) {
			nKeyLength = 128 / 8;
			return EVP_idea_ofb();
		} else {
			SetLastErrorString("Invalid keysize for cipher (flags 0x%08x).", dwFlags);	
			return NULL;
		}
	} else if (dwFlags & svncCipherCAST5) {	
		if (dwFlags & svncKey128) {
			nKeyLength = 128 / 8;
			return EVP_cast5_ofb();
		} else if (dwFlags & svncKey56) {
			nKeyLength = 56 / 8;
			return EVP_cast5_ofb();
		} else {
			SetLastErrorString("Invalid keysize for cipher (flags 0x%08x).", dwFlags);	
			return NULL;
		}
	} else if (dwFlags & svncCipherARC4) {	
		if (dwFlags & svncKey256) {
			nKeyLength = 256 / 8;
			return EVP_rc4();
		} else if (dwFlags & svncKey192) {
			nKeyLength = 192 / 8;
			return EVP_rc4();
		} else if (dwFlags & svncKey128) {
			nKeyLength = 128 / 8;
			return EVP_rc4();
		} else if (dwFlags & svncKey56) {
			nKeyLength = 56 / 8;
			return EVP_rc4();
		} else {
			SetLastErrorString("Invalid keysize for cipher (flags 0x%08x).", dwFlags);	
			return NULL;
		}
	} else {
		SetLastErrorString("Invalid cipher (flags 0x%08x).", dwFlags);
		return NULL;
	}
}

DWORD IntegratedSecureVNCPlugin::GetBestSupportedFlags(DWORD dwChallengeFlags)
{
	DWORD dwBestSupportedFlags = CheckBestSupportedFlags(dwChallengeFlags);
	if (dwBestSupportedFlags == 0) {
		SetLastErrorString("Invalid cipher (challenge flags 0x%08x).", dwChallengeFlags);
	}

	return dwBestSupportedFlags;
}

DWORD IntegratedSecureVNCPlugin::CheckBestSupportedFlags(DWORD dwFlags)
{
	if (dwFlags & svncKey448) {
		if (dwFlags & svncCipherBlowfish) {
			return svncKey448 | svncCipherBlowfish;
		}
	}
	if (dwFlags & svncKey256) {
		if (dwFlags & svncCipher3AESOFB) {
			return svncKey256 | svncCipher3AESOFB;
		}
		if (dwFlags & svncCipherAESCFB) {
			return svncKey256 | svncCipherAESCFB;
		}
		if (dwFlags & svncCipherAES) {
			return svncKey256 | svncCipherAES;
		}
		if (dwFlags & svncCipherBlowfish) {
			return svncKey256 | svncCipherBlowfish;
		}
		if (dwFlags & svncCipherARC4) {
			return svncKey256 | svncCipherARC4;
		}
	}
	if (dwFlags & svncKey192) {
		if (dwFlags & svncCipher3AESOFB) {
			return svncKey192 | svncCipher3AESOFB;
		}
		if (dwFlags & svncCipherAESCFB) {
			return svncKey192 | svncCipherAESCFB;
		}
		if (dwFlags & svncCipherAES) {
			return svncKey192 | svncCipherAES;
		}
		if (dwFlags & svncCipherBlowfish) {
			return svncKey192 | svncCipherBlowfish;
		}
		if (dwFlags & svncCipherARC4) {
			return svncKey192 | svncCipherARC4;
		}
	}
	if (dwFlags & svncKey128) {
		if (dwFlags & svncCipher3AESOFB) {
			return svncKey128 | svncCipher3AESOFB;
		}
		if (dwFlags & svncCipherAESCFB) {
			return svncKey128 | svncCipherAESCFB;
		}
		if (dwFlags & svncCipherAES) {
			return svncKey128 | svncCipherAES;
		}
		if (dwFlags & svncCipherBlowfish) {
			return svncKey128 | svncCipherBlowfish;
		}
		if (dwFlags & svncCipherIDEA) {
			return svncKey128 | svncCipherIDEA;
		}
		if (dwFlags & svncCipherCAST5) {
			return svncKey128 | svncCipherCAST5;
		}
		if (dwFlags & svncCipherARC4) {
			return svncKey128 | svncCipherARC4;
		}
	}
	if (dwFlags & svncKey56) {
		if (dwFlags & svncCipherBlowfish) {
			return svncKey56 | svncCipherBlowfish;
		}
		if (dwFlags & svncCipherCAST5) {
			return svncKey56 | svncCipherCAST5;
		}
		if (dwFlags & svncCipherARC4) {
			return svncKey56 | svncCipherARC4;
		}
	}

	return 0;
}

bool IntegratedSecureVNCPlugin::AreFlagsAcceptable(DWORD dwChallengeFlags, DWORD dwResponseFlags)
{
	DWORD dwChallengeCipher = dwChallengeFlags & svncCipherMask;
	DWORD dwResponseCipher = dwResponseFlags & svncCipherMask;

	if (dwChallengeCipher & dwResponseCipher) {
		// ciphers are acceptable.

		DWORD dwChallengeKey = dwChallengeFlags & svncKeyMask;
		DWORD dwResponseKey = dwResponseFlags & svncKeyMask;

		if (dwChallengeKey & dwResponseKey) {
			// key sizes are acceptable
			return true;
		}
	}

	return false;
}

bool IntegratedSecureVNCPlugin::CheckBufferSize(const BYTE* _Src, size_t _Size, const BYTE* _MaxSrc)
{
	if (_Src + _Size > _MaxSrc) {
		SetLastErrorString("Out of data!");
		return false;
	}
	return true;
}

bool IntegratedSecureVNCPlugin::SafeMemcpyFrom(void* _Dst, const BYTE* _Src, size_t _Size, const BYTE* _MaxSrc)
{
	if (!CheckBufferSize(_Src, _Size, _MaxSrc)) {
		return false;
	}

	memcpy(_Dst, _Src, _Size);
	return true;
}