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
#include "CryptUtils.h"
#include "Utils.h"
#include "openssl/rand.h"
#include <shlwapi.h>
#include <shlobj.h>
#pragma comment(lib, "shlwapi.lib")
#include <map>
#include "IntegratedSecureVNCPluginObject.h"

volatile long g_nInstanceCount = 0;

CriticalSection g_csKeys;
std::map<int, AutoBlob<> > g_keys;
AutoBlob<> g_keyphrase;


void OpenSSL_Cleanup()
{
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}

RSA* CreateRSAPrivateKeyFile(int nRSASize, const TCHAR* szPath)
{
	RSA* rsa = NULL;
	HANDLE hOutputFile = CreateFile(szPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hOutputFile != INVALID_HANDLE_VALUE && hOutputFile != NULL) {
		rsa = GenerateNewRSAPrivateKey(nRSASize);

		if (rsa) {
			BYTE* pOutputBuffer = NULL;
			int nOutputLength = i2d_RSAPrivateKey(rsa, &pOutputBuffer);

			DWORD dwWritten = 0;
			::WriteFile(hOutputFile, pOutputBuffer, nOutputLength, &dwWritten, NULL);

			delete[] pOutputBuffer;

			//RSA_free(rsa);
			::CloseHandle(hOutputFile);
			hOutputFile = NULL;
		} else {
			// error
			DebugLog(_T("Could not generate RSA key!\r\n"));
			::CloseHandle(hOutputFile);
			hOutputFile = NULL;
		}
	} else {
		// error
		DebugLog(_T("Could not create RSA key file %s!\r\n"), szPath);
	}

	return rsa;
}

void CreateRSAPublicKeyFile(RSA* rsa, const TCHAR* szPath)
{
	HANDLE hOutputFile = CreateFile(szPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hOutputFile != INVALID_HANDLE_VALUE && hOutputFile != NULL) {
		BYTE* pOutputBuffer = NULL;
		int nOutputLength = i2d_RSAPublicKey(rsa, &pOutputBuffer);

		DWORD dwWritten = 0;
		::WriteFile(hOutputFile, pOutputBuffer, nOutputLength, &dwWritten, NULL);

		delete[] pOutputBuffer;

		::CloseHandle(hOutputFile);
		hOutputFile = NULL;				
	} else {
		// error
		DebugLog(_T("Could not create RSA public key file %s!\r\n"), szPath);
	}
}

RSA* GenerateNewRSAPrivateKey(int nRSASize)
{
	DebugLog(_T("GenerateNewRSAPrivateKey size %li\r\n"), nRSASize);
	BIGNUM* e = BN_new();
	BN_set_word(e, 0x10001);
	RSA* rsa = RSA_new();
	RSA_generate_key_ex(rsa, nRSASize * 8, e, NULL);
	BN_free(e);

	return rsa;
}

RSA* LoadOrCreatePrivateKey(int nRSASize)
{	
	HANDLE hInputFile = FindPrivateKeyFile();

	RSA* rsa = NULL;
	if (hInputFile == INVALID_HANDLE_VALUE || hInputFile == NULL) {
		rsa = GetCachedRSAPrivateKey(nRSASize);
	}

	if (!rsa && hInputFile != NULL && hInputFile != INVALID_HANDLE_VALUE) {
		DWORD dwFileSize = GetFileSize(hInputFile, NULL);

		AutoBlob<> buffer(4096);

		DWORD dwRead = 0;
		ReadFile(hInputFile, buffer, min((int)dwFileSize, buffer.length), &dwRead, NULL);

		::CloseHandle(hInputFile);
		hInputFile = NULL;

		BYTE* pNewBuffer = buffer;
		rsa = d2i_RSAPrivateKey(NULL, (const unsigned char**)&pNewBuffer, dwRead);
	}

	if (hInputFile != NULL && hInputFile != INVALID_HANDLE_VALUE) {
		::CloseHandle(hInputFile);
	}

	if (rsa == NULL) {
		DebugLog(_T("Could not load RSA key!\r\n"));
		return GenerateNewRSAPrivateKey(nRSASize);
	}

	if (RSA_check_key(rsa) != 1) {
		DebugLog(_T("Invalid RSA key!\r\n"));
		return GenerateNewRSAPrivateKey(nRSASize);			
	}

	if (RSA_size(rsa) != nRSASize) {
		DebugLog(_T("Invalid RSA size!\r\n"));
		return GenerateNewRSAPrivateKey(nRSASize);			
	}

	return rsa;
}

RSA* LoadClientAuthPrivateKey(TCHAR* szDesiredIdentifier)
{
	HANDLE hInputFile = FindClientAuthPrivateKeyFile(szDesiredIdentifier);

	if (hInputFile != INVALID_HANDLE_VALUE && hInputFile != NULL) {
		DWORD dwFileSize = GetFileSize(hInputFile, NULL);

		const long cnBufferSize = 2048;
		unsigned char* pBuffer = new unsigned char[cnBufferSize];

		DWORD dwRead = 0;
		ReadFile(hInputFile, pBuffer, min(dwFileSize, cnBufferSize), &dwRead, NULL);

		::CloseHandle(hInputFile);
		hInputFile = NULL;

		BYTE* pNewBuffer = pBuffer;
		RSA* rsa = d2i_RSAPrivateKey(NULL, (const unsigned char**)&pNewBuffer, dwFileSize);
		delete[] pBuffer;

		if (rsa == NULL) {
			DebugLog(_T("Could not load client auth private RSA key!\r\n"));
			return NULL;
		}

		if (RSA_check_key(rsa) != 1) {
			DebugLog(_T("Invalid client auth private RSA key!\r\n"));
			return NULL;
		}

		return rsa;
	} else {
		return NULL;
	}
}

RSA* LoadClientAuthPublicKey(TCHAR* szIdentifier)
{
	HANDLE hInputFile = FindClientAuthPublicKeyFile(szIdentifier);

	if (hInputFile != INVALID_HANDLE_VALUE && hInputFile != NULL) {
		DWORD dwFileSize = GetFileSize(hInputFile, NULL);

		const long cnBufferSize = 2048;
		unsigned char* pBuffer = new unsigned char[cnBufferSize];

		DWORD dwRead = 0;
		ReadFile(hInputFile, pBuffer, min(dwFileSize, cnBufferSize), &dwRead, NULL);

		::CloseHandle(hInputFile);
		hInputFile = NULL;
		
		BYTE* pNewBuffer = pBuffer;
		RSA* rsa = d2i_RSAPublicKey(NULL, (const unsigned char**)&pNewBuffer, dwFileSize);
		delete[] pBuffer;

		if (rsa == NULL) {
			DebugLog(_T("Could not load client auth private RSA key!\r\n"));
			return NULL;
		}

		return rsa;
	} else {
		return NULL;
	}
}

RSA* GetCachedRSAPrivateKey(int nRSASize)
{	
	DebugLog(_T("GetCachedRSAPrivateKey(%li)\r\n"), nRSASize);

	LockCriticalSection lock(g_csKeys);

	if (!g_keyphrase.data) {
		g_keyphrase.Alloc(64);
		RAND_bytes(g_keyphrase.data, g_keyphrase.length);
	}

	IntegratedSecureVNCPlugin plugin;

	AutoBlob<>& rsaEncryptedBuffer(g_keys[nRSASize]);

	if (!rsaEncryptedBuffer.data) 
	{
		AutoBlob<> rsaBuffer;
		{
			RSA* rsa = GenerateNewRSAPrivateKey(nRSASize);
		
			BYTE* pOutputBuffer = NULL;
			int nOutputLength = i2d_RSAPrivateKey(rsa, &pOutputBuffer);

			rsaBuffer.Alloc(nOutputLength, pOutputBuffer);

			delete[] pOutputBuffer;
			RSA_free(rsa);
			rsa = NULL;
		}

		if (!plugin.EncryptBytesWithKey(rsaBuffer.data, rsaBuffer.length, g_keyphrase.data, g_keyphrase.length, rsaEncryptedBuffer.data, rsaEncryptedBuffer.length, true)) {
			DebugLog(_T("GetCachedRSAPrivateKey - could not encrypt new RSA: %s\r\n"), plugin.GetLastErrorString());
			return NULL;
		}
	}

	// now decrypt our cached RSA key
	RSA* cachedRSA = NULL;
	{
		AutoBlob<> rsaDecryptedBuffer;
		if (!plugin.DecryptBytesWithKey(rsaEncryptedBuffer.data, rsaEncryptedBuffer.length, g_keyphrase.data, g_keyphrase.length, rsaDecryptedBuffer.data, rsaDecryptedBuffer.length, true)) {
			DebugLog(_T("GetCachedRSAPrivateKey - could not decrypt new RSA: %s\r\n"), plugin.GetLastErrorString());
			return NULL;
		}

		BYTE* pOutputBuffer = rsaDecryptedBuffer.data;
		cachedRSA = d2i_RSAPrivateKey(NULL, (const unsigned char**)&pOutputBuffer, rsaDecryptedBuffer.length);		
	}
	
	return cachedRSA;
}

DWORD WINAPI ThreadCreateCachedRSAKeys(LPVOID lpParameter)
{
	LockCriticalSection lock(g_csKeys);

	RSA* rsa = NULL;

	rsa = GetCachedRSAPrivateKey(384);
	if (rsa) {
		RSA_free(rsa);
	}

	rsa = GetCachedRSAPrivateKey(256);
	if (rsa) {
		RSA_free(rsa);
	}

	rsa = GetCachedRSAPrivateKey(128);
	if (rsa) {
		RSA_free(rsa);
	}

	rsa = GetCachedRSAPrivateKey(64);
	if (rsa) {
		RSA_free(rsa);
	}

	return 0;
}

void CacheRSAKeys()
{
	LockCriticalSection lock(g_csKeys);
	
	HANDLE hInputFile = FindPrivateKeyFile();
	bool bPrivateKeyFileExists = hInputFile != NULL && hInputFile != INVALID_HANDLE_VALUE;
	if (bPrivateKeyFileExists) {
		::CloseHandle(hInputFile);
	}

	if (!bPrivateKeyFileExists && g_keys.empty()) {
		HANDLE hThreadCreateCachedRSAKeys = CreateThread(NULL, 0, ThreadCreateCachedRSAKeys, NULL, 0, NULL);
		::CloseHandle(hThreadCreateCachedRSAKeys);
	}
}

void ClearRSAKeys()
{
	DebugLog(_T("ClearRSAKeys\r\n"));

	LockCriticalSection lock(g_csKeys);

	g_keys.clear();
}

BOOL FindKey(HANDLE *hKeyFile, TCHAR* szFind, TCHAR* szExclude = NULL, TCHAR* szIdentifier = NULL);

HANDLE FindPrivateKeyFile()
{
	HANDLE hFile = NULL;
	if (FindKey(&hFile, _T("*.pkey"), _T("ClientAuth"))) {
		return hFile;
	} else {
		return INVALID_HANDLE_VALUE;
	}
}

HANDLE FindClientAuthPublicKeyFile(TCHAR* szIdentifier)
{
	HANDLE hFile = NULL;
	if (FindKey(&hFile, _T("*ClientAuth.pubkey"), NULL, szIdentifier)) {
		return hFile;
	} else {
		return INVALID_HANDLE_VALUE;
	}
}

HANDLE FindClientAuthPrivateKeyFile(TCHAR* szDesiredIdentifier)
{
	HANDLE hFile = NULL;

	if (szDesiredIdentifier && strlen(szDesiredIdentifier) > 0) {
		TCHAR szPattern[_MAX_PATH];

		_snprintf_s(szPattern, _MAX_PATH - 1 - 1, _TRUNCATE, "%s_*ClientAuth.pkey", szDesiredIdentifier);
		
		if (FindKey(&hFile, szPattern)) {
			return hFile;
		} else {
			hFile = NULL;
			// fallback to find anything
		}
	}

	if (FindKey(&hFile, _T("*ClientAuth.pkey"))) {
		return hFile;
	} else {
		return INVALID_HANDLE_VALUE;
	}
}

BOOL FindKeyInFileString(const char* szBasePath, char* szFindPath, HANDLE* hKeyFile, TCHAR* szExclude = NULL, TCHAR* szFinalFilePath = NULL)
{	
	if (szBasePath) {
		WIN32_FIND_DATA findData;
		HANDLE hFind = FindFirstFile(szFindPath, &findData);

		if (hFind) {
			if (szExclude) {
				while (hFind != NULL && _tcsstr(findData.cFileName, szExclude) != NULL) {
					if (!FindNextFile(hFind, &findData)) {
						FindClose(hFind);
						hFind = NULL;
					}
				}
			}

			if (hFind) {
				char szFilePath[_MAX_PATH];
				_snprintf_s(szFilePath, _MAX_PATH - 1 - 1, _TRUNCATE, "%s\\%s", szBasePath, findData.cFileName);			

				FindClose(hFind);
				hFind = NULL;

				HANDLE h = CreateFile(szFilePath, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
				if (h != 0 && h != INVALID_HANDLE_VALUE) {
					*hKeyFile = h;
					if (szFinalFilePath) {
						strcpy_s(szFinalFilePath, _MAX_PATH, szFilePath);
					}
					return TRUE;
				}
			}
		}
	} else {
		// NULL base path basically means that szFindPath is a file itself
		HANDLE h = CreateFile(szFindPath, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (h != 0 && h != INVALID_HANDLE_VALUE) {
			*hKeyFile = h;
			if (szFinalFilePath) {
				strcpy_s(szFinalFilePath, _MAX_PATH, szFindPath);
			}
			return TRUE;
		}
	}

	return FALSE;
}

BOOL FindKeyInPath(const char* szPath, HANDLE* hKeyFile, TCHAR* szFind, TCHAR* szExclude = NULL, TCHAR* szFilePath = NULL)
{
	TCHAR szFindPath[_MAX_PATH];

	int n = (int)_tcslen(szPath);
	if (n > 0 && szPath[n - 1] != '\\') {
		_snprintf_s(szFindPath, _MAX_PATH - 1 - 1, _TRUNCATE, "%s\\%s", szPath, szFind);
	} else {
		_snprintf_s(szFindPath, _MAX_PATH - 1 - 1, _TRUNCATE, "%s%s", szPath, szFind);
	}

	return FindKeyInFileString(szPath, szFindPath, hKeyFile, szExclude, szFilePath);
}

BOOL FindKey(HANDLE *hKeyFile, TCHAR* szFind, TCHAR* szExclude, TCHAR* szIdentifier)
{
	TCHAR szPath[_MAX_PATH];
	TCHAR szDrive[_MAX_DRIVE];
	TCHAR szDirectory[_MAX_DIR];

	// Environment variable
	/*
	if (GetEnvironmentVariable(_T("SECUREVNC_PRIVATEKEY"), szPath, _MAX_PATH - 1)) {
		if (FindKeyInFileString(NULL, szPath, hKeyFile)) return TRUE;
	}
	
	if (GetEnvironmentVariable(_T("SECUREVNC_PATH"), szPath, _MAX_PATH - 1)) {
		if (FindKeyInPath(szPath, hKeyFile)) return TRUE;
	}
	*/

	BOOL bFound = FALSE;
	TCHAR szFoundFilePath[_MAX_PATH];

	// this module's directory
	if (!bFound && g_hInstance && GetModuleFileName(g_hInstance, szPath, _MAX_PATH - 1 - 1)) {
		_tsplitpath_s(szPath, szDrive, _MAX_DRIVE, szDirectory, _MAX_DIR, NULL, NULL, NULL, NULL);
		_tmakepath_s(szPath, _MAX_PATH, szDrive, szDirectory, NULL, NULL);
		if (FindKeyInPath(szPath, hKeyFile, szFind, szExclude, szFoundFilePath)) bFound = TRUE;
	}

	// process module's directory
	if (!bFound && g_hInstance && GetModuleFileName(NULL, szPath, _MAX_PATH - 1 - 1)) {
		_tsplitpath_s(szPath, szDrive, _MAX_DRIVE, szDirectory, _MAX_DIR, NULL, NULL, NULL, NULL);
		_tmakepath_s(szPath, _MAX_PATH, szDrive, szDirectory, NULL, NULL);
		if (FindKeyInPath(szPath, hKeyFile, szFind, szExclude, szFoundFilePath)) bFound = TRUE;
	}

	// current directory
	if (!bFound && GetCurrentDirectory(MAX_PATH - 1 - 1, szPath)) {
		if (FindKeyInPath(szPath, hKeyFile, szFind, szExclude, szFoundFilePath)) bFound = TRUE;
	}	
	
	if (bFound && szIdentifier != NULL) {
		TCHAR szFile[_MAX_FNAME];
		_tsplitpath_s(szFoundFilePath, NULL, 0, NULL, 0, szFile, _MAX_FNAME, NULL, NULL);
		strcpy_s(szIdentifier, _MAX_FNAME, szFile);
		int nIdentifierLen = (int)strlen(szIdentifier);

		bool bFoundUnderscore = false;
		for (int i = 0; i < nIdentifierLen; i++) {
			char c = ::tolower((unsigned char)szIdentifier[i]);

			if (c == '_') {
				bFoundUnderscore = true;
				szIdentifier[i] = '\0';
			} else {
				szIdentifier[i] = c;
			}
		}

		// ignore standard names
		if (!bFoundUnderscore || (0 == strcmp(szIdentifier, "server")) || (0 == strcmp(szIdentifier, "viewer")) || (0 == strcmp(szIdentifier, "clientauth")) ) {
			szIdentifier[0] = '\0';
		}
	}

	return bFound;
}



