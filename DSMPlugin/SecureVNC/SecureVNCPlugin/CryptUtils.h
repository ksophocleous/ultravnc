#pragma once
#include "openssl/rsa.h"
#include <map>

#define RC4_DROP_BYTES 3072

extern volatile long g_nInstanceCount;

template<class DataType = BYTE, class LengthType = int>
class AutoBlob
{
public:
	AutoBlob()
		: data(NULL)
		, length(0)
	{
	};

	AutoBlob(const AutoBlob<DataType, LengthType>& copy)
		: data(NULL)
		, length(copy.length)
	{
		if (length > 0) {
			data = new DataType[length];
			memcpy(data, copy.data, length);
		}
	};

	AutoBlob(LengthType _length)
		: data(NULL)
		, length(_length)
	{
		if (length > 0) {
			data = new DataType[_length];
		}
	};

	AutoBlob(DataType* _data, LengthType _length)
		: data(NULL)
		, length(_length)
	{
		if (length > 0) {
			data = new DataType[_length];
			memcpy(data, _data, _length);
		}
	};

	~AutoBlob()
	{
		Free();
	};

	DataType* data;
	LengthType length;

	operator DataType*()
	{
		return data;
	};

	DataType* GetData()
	{
		return data;
	};

	LengthType GetLength()
	{
		return length;
	};

	LengthType GetTotalBytes()
	{
		return sizeof(DataType) * length;
	};

	void Alloc(LengthType _length, DataType* _data = NULL)
	{
		Free();

		length = _length;
		data = new DataType[_length];
		if (_data) {
			memcpy(data, _data, length);
		}
	};

	void Free()
	{
		if (data) {
			::SecureZeroMemory(data, length);
			delete[] data;
			data = NULL;
		}

		length = 0;
	};
};

void OpenSSL_Cleanup();

RSA* CreateRSAPrivateKeyFile(int nRSASize, const TCHAR* szPath);
void CreateRSAPublicKeyFile(RSA* rsa, const TCHAR* szPath);
RSA* GenerateNewRSAPrivateKey(int nRSASize);

RSA* LoadOrCreatePrivateKey(int nRSASize);

RSA* LoadClientAuthPrivateKey(TCHAR* szDesiredIdentifier = NULL);
RSA* LoadClientAuthPublicKey(TCHAR* szIdentifier = NULL);

RSA* GetCachedRSAPrivateKey(int nRSASize);
void CacheRSAKeys();
void ClearRSAKeys();

HANDLE FindPrivateKeyFile();
HANDLE FindClientAuthPublicKeyFile(TCHAR* szIdentifier = NULL);
HANDLE FindClientAuthPrivateKeyFile(TCHAR* szDesiredIdentifier = NULL);

