#pragma once

#include "MultithreadedPlugin.h"

class IntegratedSecureVNCPlugin : public IIntegratedPluginEx, public MultithreadedPlugin
{
public:
	IntegratedSecureVNCPlugin();
	virtual ~IntegratedSecureVNCPlugin();

	virtual void Destroy(); // Safe destruction (not using delete!)

	virtual int InterfaceVersion(); // 2 == IIntegratedPluginEx
	
	enum SecureVNCFlags
	{
		svncInvalid					= 0x00,
		svncCipherAES				= 0x01,
		svncCipherARC4				= 0x02,
		svncCipherBlowfish			= 0x04,
		svncCipherIDEA				= 0x08,
		svncCipherCAST5				= 0x10,
		svncCipherAESCFB			= 0x20,
		svncCipher3AESOFB			= 0x40,

		svncCipherMask				= 0xFF,

		svncKey128					= 0x1000,
		svncKey192					= 0x2000,
		svncKey256					= 0x4000,
		svncKey448					= 0x8000,
		svncKey56					= 0x0100,

		svncKeyMask					= 0xFF00,
		
		svncClientAuthRequired		= 0x00010000,
		svncOverridePassphrase		= 0x00020000,
		svncLowKey					= 0x00040000,
		svncNewKey					= 0x00800000,

		/**** ONLY USED FOR SAVED CONFIG, NOT IN ACTUAL FLAGS ****/
		//svncOptionRSA2048			= 0x00000000, // default
		svncConfigRSA1024			= 0x00010000,
		svncConfigRSA512			= 0x00020000,
		svncConfigRSA3072			= 0x00040000,
		svncConfigLowKey			= 0x00080000,
		svncConfigNewKey			= 0x00100000,
		svncConfigMask				= 0xFFFF0000,
		/**** ****/

		svncOptionsMask				= 0xFFFF0000,

		svncMax						= 0xFFFFFFFF,
	};

	virtual void FreeMemory(void* pMemory);

	virtual LPCSTR GetLastErrorString(); // volatile, must be copied or may be invalidated
	virtual LPCSTR DescribeCurrentSettings(); // volatile, must be copied or may be invalidated

	void SetLastErrorString(LPCSTR szFormat, ...);

	virtual void SetHandshakeComplete();

	virtual bool EncryptBytesWithKey(const BYTE* pPlainData, int nPlainDataLength, const BYTE* pPassphrase, int nPassphraseLength, BYTE*& pEncryptedData, int& nEncryptedDataLength, bool bIncludeHash);
	virtual bool DecryptBytesWithKey(const BYTE* pEncryptedData, int nEncryptedDataLength, const BYTE* pPassphrase, int nPassphraseLength, BYTE*& pPlainData, int& nPlainDataLength, bool bIncludeHash);

	bool CipherWithKey(bool bEncrypt, const BYTE* pInputData, int nInputDataLength, const BYTE* pPassphrase, int nPassphraseLength, BYTE*& pOutputData, int& nOutputDataLength, bool bIncludeHash);

	virtual BYTE* TransformBuffer(BYTE* pDataBuffer, int nDataLen, int* pnTransformedDataLen);
	// Transformations and restorations are guaranteed to be the same size as the input data
	virtual void TransformBufferTo(const BYTE* pDataBuffer, int nDataLen, BYTE* pOutputBuffer);
	void TransformBufferInternal(const BYTE* pDataBuffer, int nDataLen, BYTE* pOutputBuffer);

	virtual BYTE* RestoreBuffer(BYTE* pTransBuffer, int nTransDataLen, int* pnRestoredDataLen);
	// Transformations and restorations are guaranteed to be the same size as the input data
	virtual void RestoreBufferTo(const BYTE* pDataBuffer, int nDataLen, BYTE* pOutputBuffer);
	virtual void RestoreBufferInternal(const BYTE* pDataBuffer, int nDataLen, BYTE* pOutputBuffer);


	// server
	virtual void SetServerIdentification(const BYTE* pIdentification, int nLength);
	virtual void SetServerOptions(LPCSTR szOptions);
	virtual void SetPasswordData(const BYTE* pPasswordData, int nLength);
	virtual bool GetChallenge(BYTE*& pChallenge, int& nChallengeLength, int nSequenceNumber);
	virtual bool HandleResponse(const BYTE* pResponse, int nResponseLength, int nSequenceNumber, bool& bSendChallenge);

	// client
	virtual void SetViewerOptions(LPCSTR szOptions);
	virtual bool HandleChallenge(const BYTE* pChallenge, int nChallengeLength, int nSequenceNumber, bool& bPasswordOK, bool& bPassphraseRequired);
	virtual bool GetResponse(BYTE*& pResponse, int& nResponseLength, int nSequenceNumber, bool& bExpectChallenge);

	static DWORD CheckBestSupportedFlags(DWORD dwChallengeFlags);

protected:	
	CriticalSection m_csEncryption; 

	bool SafeMemcpyFrom(void* _Dst, const BYTE* _Src, size_t _Size, const BYTE* _MaxSrc);
	bool CheckBufferSize(const BYTE* _Src, size_t _Size, const BYTE* _MaxSrc);

	bool m_bHandshakeComplete;

	LPSTR m_szLastErrorString;
	LPSTR m_szCurrentSettingsDescription;

	BYTE* m_pPasswordData;
	int m_nPasswordDataLength;
	bool m_bOverridePassphrase;

	BYTE* m_pServerIdentificationData;
	int m_nServerIdentificationLength;

	EVP_CIPHER_CTX m_ContextVS1;
	EVP_CIPHER_CTX m_ContextSV1;
	EVP_CIPHER_CTX m_ContextVS2;
	EVP_CIPHER_CTX m_ContextSV2;
	EVP_CIPHER_CTX m_ContextVS3;
	EVP_CIPHER_CTX m_ContextSV3;
	bool m_bTriple;
	RSA* m_rsa;
	int m_nRSASize;
	
	BYTE* m_pPublicKeyRaw;
	int m_nPublicKeyRawLength;

	RSA* m_rsaClientAuthPublicKey;
	LPSTR m_szClientAuthPublicKeyIdentifier;
	int m_nClientAuthPublicKeyRSASize;

	DWORD m_dwChallengeFlags;
	DWORD m_dwResponseFlags;
	DWORD m_dwServerOptionFlags;

	DWORD GetBestSupportedFlags(DWORD dwChallengeFlags);
	bool AreFlagsAcceptable(DWORD dwChallengeFlags, DWORD dwResponseFlags);

	bool m_bIsServer;
	bool m_bIsViewer;

	const EVP_CIPHER* GetCipher(DWORD dwFlags, int& nKeyLength);
};