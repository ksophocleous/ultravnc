#pragma once

#include "MultiThreadedPlugin.h"
#include "openssl/rsa.h"

//derived from common IPlugin interface.
class SecureVNCPlugin : public IPlugin, public MultithreadedPlugin
{
public:
	SecureVNCPlugin();

	virtual ~SecureVNCPlugin();
	
	virtual BYTE* TransformBuffer(BYTE* pDataBuffer, int nDataLen, int* pnTransformedDataLen);
	virtual BYTE* RestoreBuffer(BYTE* pTransBuffer, int nDataLen, int* pnRestoredDataLen);

protected:

	//CriticalSection m_csEncrypt;
	//CriticalSection m_csDecrypt;
	//adzm - 2009-06-20 - a single critical section for encryption and decryption due to salt/header issues.
	//According to performance tests, this is negligible. The real performance hit was from a misguided
	//critical section in the winvnc server which was held during a network read.
	CriticalSection m_csEncryption; 

	//OpenSSL Crypto context for Encryption and Decryption
	EVP_CIPHER_CTX m_ContextE; //Ectx;
	EVP_CIPHER_CTX m_ContextD; //Dctx;

	RSA* m_rsa;
	unsigned char* m_pRSAData;

	const EVP_CIPHER* GetCipher() {
		if (m_bUseAESCipher) {
			return EVP_aes_128_ofb();
		} else {
			return EVP_rc4();
		}
	};

	int m_nEncryptPacketSequence;
	int m_nDecryptPacketSequence;

	bool m_bHandshakeComplete;
	bool m_bUseAESCipher;

	bool m_bClientAuthPublicKeyAvailable;
	bool m_bClientAuthPrivateKeyAvailable;

	int GetTransformedDataLen(int nDataLen);
	int GetRestoredDataLen(int nDataLen);

	enum Flags {
		flagUseAESCipher	= 0x00000001,
		flagUseSignature	= 0x10000000,
		flagInvalid			= 0xFFFFFFFF,
	};
};