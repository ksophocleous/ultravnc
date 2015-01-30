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

// SecureVNCPlugin.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "SecureVNCPlugin.h"
#include "SecureVNCPluginObject.h"
#include "IntegratedSecureVNCPluginObject.h"
#include "Dialogs.h"
#include "Base64.h"

//adzm - 2009-06-20 - for legacy applications, we have a global instance of the IPlugin interface
SecureVNCPlugin* g_LegacyPlugin = NULL;
bool g_bDisableLegacySupport = false;
CriticalSection g_csLegacyPluginLock;
bool g_bSupportsIntegrated = false;

char g_szConfig[512];
char g_szNewConfig[512];
EHostType g_hostType = hostTypeUndetermined;

//////////////////////////////////////////////////////////////////////////

// Plugin Description
// Please use the following format (with ',' (comma) as separator)
// Name,Version,Date,Author,FileName
// For the version, we recommend the following format: x.y.z
// The other fields (Name, Date, Author, FileName) are format free (don't use ',' in them, of course)

#define PLUGIN_NAME "SecureVNCPlugin.dsm"
#define PLUGIN_DESCRIPTION  "SecureVNCPlugin," VER_VERSION_STR ",May 10 2010,Adam D. Walling," PLUGIN_NAME

// ----------------------------------------------------------------------
//
// A VNC DSM Plugin MUST export (extern "C" (__cdecl)) all the following
// functions (same names, same signatures)
//
// For return values, the rule is:
//    < 0, 0, and NULL pointer mean Error
//    > 0 and pointer != NULL mean Ok
//
// ----------------------------------------------------------------------
//

// Returns the ID string of the Plugin
//
PLUGIN_API char* Description(void)
{
	return PLUGIN_DESCRIPTION;
}


//
// Initialize the plugin and all its internals
// Return -1 if error
//


CRITICAL_SECTION g_csLocks[CRYPTO_NUM_LOCKS];
//adzm - 2009-06-20 - OpenSSL support multithreaded operation provided
//we give the library a callback function which handles locks.
void CryptoLockingCallback(int mode, int type, const char *file,int line)
{
	if (mode & CRYPTO_LOCK) {
		EnterCriticalSection(&g_csLocks[type]);
	} else {
		LeaveCriticalSection(&g_csLocks[type]);
	}
}

void InitializeCriticalSections()
{
	//adzm - 2009-06-20 - OpenSSL support multithreaded operation provided
	//we give the library a callback function which handles locks.
	CRYPTO_set_locking_callback(CryptoLockingCallback);

	for (int i = 0; i < CRYPTO_NUM_LOCKS; i++) {
		InitializeCriticalSection(&g_csLocks[i]);
	}
}

void DeleteCriticalSections()
{
	//adzm - 2009-06-20 - cleanup locks
	for (int i = 0; i < CRYPTO_NUM_LOCKS; i++) {
		DeleteCriticalSection(&g_csLocks[i]);
	}
}

PLUGIN_API int Startup(void)
{
	/*
	DWORD dwTicks = GetTickCount();
	RAND_add(&dwTicks, 4, 4);

	char szBuffer[256];
	{
		DWORD dwSize = sizeof(szBuffer);
		if (GetComputerName(szBuffer, &dwSize)) {
			RAND_add(szBuffer, dwSize, dwSize);
		}
	}
	{
		DWORD dwSize = sizeof(szBuffer);
		if (GetUserName(szBuffer, &dwSize)) {
			RAND_add(szBuffer, dwSize, dwSize);
		}
	}

	{
		LPTSTR lpszVariable;
		LPTCH lpvEnv = GetEnvironmentStrings();

		if (lpvEnv)	{
	 		lpszVariable = (LPTSTR)lpvEnv;

			while (*lpszVariable)
			{
				int nLength = lstrlen(lpszVariable);

				RAND_add(lpszVariable, nLength, nLength);

				lpszVariable += nLength + 1;
			}
			FreeEnvironmentStrings(lpvEnv);
		}
	}
	*/

	CacheRSAKeys();

    return 1;
}


//
// Stop and Clean up the plugin 
// Return -1 if error
// 
PLUGIN_API int Shutdown(void)
{
    // Terminate Threads if any
    // Cleanup everything
	ClearRSAKeys();

	//adzm - 2009-06-20 - cleanup legacy instance
	{
		LockCriticalSection lock(g_csLegacyPluginLock);
		if (g_LegacyPlugin) {
			delete g_LegacyPlugin;
			g_LegacyPlugin = NULL;
		}
	}

	return 1;
}


//
// Stop and Clean up the plugin 
// Return -1 if error
// 
PLUGIN_API int Reset(void)
{
	LockCriticalSection lock(g_csLegacyPluginLock);

	if (g_LegacyPlugin) {
		delete g_LegacyPlugin;
		g_LegacyPlugin = NULL;
	}

	return 1;
}


//
// Set the plugin params (Key or password )
// If several params are needed, they can be transmitted separated with ',' (comma)
// then translated if necessary. They also can be taken from the internal Plugin config
// 
// WARNING: The plugin is responsible for implementing necessary GUI or File/Registry reading
// to acquire additionnal parameters and to ensure their persistence if necessary.
// Same thing for events/errors logging.
// 
// This function can be called 2 times, both from vncviewer and WinVNC:
// 
// 1.If the user clicks on the Plugin's "config" button in vncviewer and WinVNC dialog boxes
//   In this case this function is called with hVNC != 0 (CASE 1)
//
//   -> szParams is a string formatted as follow: "Part1,Part2"
//   Part1 = "NoPassword"
//   Part2 = type of application that has loaded the plugin
//     "viewer"     : for vncviewer
//     "server-svc" : for WinVNC run as a service
//     "server-app" : for WINVNC run as an application
//
//   -> The Plugin Config dialog box is displayed if any.
// 
// 2.When then plugin is Inited from VNC viewer or Server, right after Startup() call (CASE 2);
//   In this case, this function is called with hVNC = 0 and
//   szParams is a string formatted as follows: "part1,Part2"
//   Part1 = The VNC password, if required by the GetParams() function return value
//   Part2 = type of application that has loaded the plugin
//      "viewer"     : for vncviewer
//      "server-svc" : for WinVNC run as a service
//      "server-app" : for WINVNC run as an application
//   (this info can be used for application/environnement dependent
//    operations (config saving...))
//   
// 
PLUGIN_API int SetParams(HWND hVNC, char* szParams)
{
	return DoConfig(hVNC, szParams, NULL, NULL, false);
}

PLUGIN_API int Config(HWND hVNC, char* szParams, char* szConfig, char** pszConfig)
{
	return DoConfig(hVNC, szParams, szConfig, pszConfig, true);
}

int DoConfig(HWND hVNC, char* szParams, char* szConfig, char** pszConfig, bool bEx)
{    
	if (bEx) {
		g_bSupportsIntegrated = true;
		if (szConfig && strlen(szConfig) > 0) {
			strncpy_s(g_szConfig, sizeof(g_szConfig) - 1, szConfig, _TRUNCATE);
		} else {
			g_szConfig[0] = '\0';
		}
	}

	{
		EHostType hostType = hostTypeUndetermined;

		if (szParams) {
			char* szHostType = strchr(szParams, ',');
			if (szHostType) {
				szHostType += 1;
				if (0 == _strnicmp(szHostType, "viewer", 6)) {
					hostType = hostTypeViewer; 
				} else if (0 == _strnicmp(szHostType, "server-app", 10)) {
					hostType = hostTypeServerApplication;
				} else if (0 == _strnicmp(szHostType, "server-svc", 10)) {
					hostType = hostTypeServerService;
				}
			}
		}

		if (g_hostType == hostTypeUndetermined || hostType != hostTypeUndetermined) {
			g_hostType = hostType;
		}
	}
// ***CASE 1 - CONFIG***
    // If hVNC != 0, display for instance the Plugin Config Dialog box 
    if (hVNC)
    {        
        // Display the Plugin Config dialog box
        DoConfigDialog(hVNC);
		if (bEx && pszConfig) {
			*pszConfig = g_szNewConfig;
		}
    } 
    else 
    {
// ***CASE 2: - INITIALIZE PLUGIN***
	}

    return 1;
}

//
// Return the current plugin params
// As the plugin is basically a blackbox, VNC doesn't need to know 
// the Plugin parameters. Should not often be used...
//
PLUGIN_API char* GetParams(void)
{
	static char* params = "NothingNeeded";
	return params;
}

//adzm - 2009-06-20 - Return the legacy instance (create if necessary)
SecureVNCPlugin* GetLegacyPlugin()
{
	if (g_LegacyPlugin == NULL) {
		g_LegacyPlugin = new SecureVNCPlugin();
		g_LegacyPlugin->SetLegacyMode(true);
	}
	return g_LegacyPlugin;
}

// 
// TransformBuffer function
//
// Transform the data given in pDataBuffer then return the pointer on the allocated 
// buffer containing the resulting data.
// The length of the resulting data is given by pnTransformedDataLen
//	
//adzm - 2009-06-20 - Use the legacy plugin instance
PLUGIN_API BYTE* TransformBuffer(BYTE* pDataBuffer, int nDataLen, int* pnTransformedDataLen)
{
	if (g_bDisableLegacySupport) return NULL;
	LockCriticalSection lock(g_csLegacyPluginLock);
    return GetLegacyPlugin()->TransformBuffer(pDataBuffer, nDataLen, pnTransformedDataLen); 
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
//adzm - 2009-06-20 - Use the legacy plugin instance
PLUGIN_API BYTE* RestoreBuffer(BYTE* pRestoredDataBuffer, int nDataLen, int* pnRestoredDataLen)
{
	if (g_bDisableLegacySupport) return NULL;
	LockCriticalSection lock(g_csLegacyPluginLock);
    return GetLegacyPlugin()->RestoreBuffer(pRestoredDataBuffer, nDataLen, pnRestoredDataLen); 
}


//
// Free the DataBuffer and TransBuffer than have been allocated
// in TransformBuffer and RestoreBuffer, using the method adapted
// to the used allocation method.
//
//adzm - 2009-06-20 - Use the legacy plugin instance (although we maintain our own memory)
PLUGIN_API void FreeBuffer(BYTE* pBuffer)
{
    return;
}

//adzm - 2009-06-20 - return a new instance of the plugin
PLUGIN_API IPlugin* CreatePluginInterface()
{
	g_bDisableLegacySupport = true;

	SecureVNCPlugin* pPlugin = new SecureVNCPlugin();

	return pPlugin;
}

//adzm - 2009-06-20 - return a new instance of the plugin
PLUGIN_API IIntegratedPlugin* CreateIntegratedPluginInterface()
{
	return CreateIntegratedPluginInterfaceEx();
}

PLUGIN_API IIntegratedPluginEx* CreateIntegratedPluginInterfaceEx()
{
	g_bDisableLegacySupport = true;

	IntegratedSecureVNCPlugin* pPlugin = new IntegratedSecureVNCPlugin();

	return pPlugin;
}

ConfigHelper::ConfigHelper(DWORD dwFlags, char* szPassphrase)
	: m_szConfig(NULL)
	, m_szPassphrase(NULL)
	, m_dwFlags(dwFlags)
{
	m_szConfig = new char[512];
	m_szConfig[0] = '\0';

	char szEncoded[256];
	szEncoded[0] = '\0';
	if (szPassphrase[0] != '\0') {
		Base64::encode(szPassphrase, szEncoded);
	}

	_snprintf_s(m_szConfig, 512 - 1 - 1, _TRUNCATE, "SecureVNC;0;0x%08x;%s", dwFlags, szEncoded);
}

ConfigHelper::ConfigHelper(const char* szConfig)
	: m_szConfig(NULL)
	, m_szPassphrase(NULL)
	, m_dwFlags(IntegratedSecureVNCPlugin::svncCipherAES | IntegratedSecureVNCPlugin::svncKey256 | IntegratedSecureVNCPlugin::svncConfigNewKey)
{
	if (szConfig == NULL) return;

	const char* szHeader = "SecureVNC;0;";

	if (strncmp(szConfig, "SecureVNC;0;", strlen(szHeader)) != 0) {
		return;
	}
	
	szConfig += strlen(szHeader);

	char* szEnd = NULL;
	DWORD dwFlags = strtoul(szConfig, &szEnd, 16);

	if (dwFlags != ULONG_MAX) {
		m_dwFlags = dwFlags;

		if (szEnd && szEnd != szConfig) {
			m_szPassphrase = new char[256];
			m_szPassphrase[0] = '\0';

			char szEncoded[256];
			szEncoded[0] = '\0';

			strcpy_s(szEncoded, 256 - 1, szEnd + 1);

			if (szEncoded[0] != '\0') {
				Base64::decode(szEncoded, m_szPassphrase);
			}
		}
	}
}

ConfigHelper::~ConfigHelper()
{
	if (m_szConfig) {
		delete[] m_szConfig;
		m_szConfig = NULL;
	}

	if (m_szPassphrase) {
		delete[] m_szPassphrase;
		m_szPassphrase = NULL;
	}
}
