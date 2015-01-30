/////////////////////////////////////////////////////////////////////////////
//  Copyright (C) 2005 Ultr@Vnc.  All Rights Reserved.
//  Copyright (C) 2010 Adam D. Walling aka Adzm.  All Rights Reserved.
//
//  (2009)
//  Multithreaded DSM plugin framework created by Adam D. Walling
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

#pragma once


//adzm - 2009-06-20 - IPlugin abstract base class interface for generic plugins.
//For easy and efficient multithreaded support, the plugin manages its own memory
//using thread local storage. Memory should be cleared when the IPlugin is destroyed.
//IPlugin instances should be created via the exported CreatePluginInterface function
//and destroyed via delete
class IPlugin
{
public:
	virtual ~IPlugin() {};

	virtual BYTE* TransformBuffer(BYTE* pDataBuffer, int nDataLen, int* pnTransformedDataLen) = 0;
	virtual BYTE* RestoreBuffer(BYTE* pTransBuffer, int nTransDataLen, int* pnRestoredDataLen) = 0;
};

class IIntegratedPlugin : public IPlugin
{
public:
	virtual ~IIntegratedPlugin() {};

	// Free memory allocated by the plugin
	virtual void FreeMemory(void* pMemory) = 0;

	// Get the last error string
	virtual LPCSTR GetLastErrorString() = 0; // volatile, must be copied or may be invalidated

	// Describe the current encryption settings
	virtual LPCSTR DescribeCurrentSettings() = 0; // volatile, must be copied or may be invalidated

	// Set handshake complete and start to transform/restore buffers
	virtual void SetHandshakeComplete() = 0;

	// Helper methods to decrypt or encrypt an arbitrary array of bytes with a given passphrase
	virtual bool EncryptBytesWithKey(const BYTE* pPlainData, int nPlainDataLength, const BYTE* pPassphrase, int nPassphraseLength, BYTE*& pEncryptedData, int& nEncryptedDataLength, bool bIncludeHash) = 0;
	virtual bool DecryptBytesWithKey(const BYTE* pEncryptedData, int nEncryptedDataLength, const BYTE* pPassphrase, int nPassphraseLength, BYTE*& pPlainData, int& nPlainDataLength, bool bIncludeHash) = 0;

	// server
	virtual void SetServerIdentification(const BYTE* pIdentification, int nLength) = 0;
	virtual void SetServerOptions(LPCSTR szOptions) = 0;
	virtual void SetPasswordData(const BYTE* pPasswordData, int nLength) = 0;
	virtual bool GetChallenge(BYTE*& pChallenge, int& nChallengeLength, int nSequenceNumber) = 0;
	virtual bool HandleResponse(const BYTE* pResponse, int nResponseLength, int nSequenceNumber, bool& bSendChallenge) = 0;

	// client
	virtual void SetViewerOptions(LPCSTR szOptions) = 0;
	virtual bool HandleChallenge(const BYTE* pChallenge, int nChallengeLength, int nSequenceNumber, bool& bPasswordOK, bool& bPassphraseRequired) = 0;
	virtual bool GetResponse(BYTE*& pResponse, int& nResponseLength, int nSequenceNumber, bool& bExpectChallenge) = 0;

};


class IIntegratedPluginEx : public IIntegratedPlugin
{
public:
	virtual ~IIntegratedPluginEx() {};

	virtual void Destroy() = 0; // Safe destruction (not using delete!)

	virtual int InterfaceVersion() = 0; // 2 == IIntegratedPluginEx
	
	// Transformations and restorations are guaranteed to be the same size as the input data
	virtual void TransformBufferTo(const BYTE* pDataBuffer, int nDataLen, BYTE* pOutputBuffer) = 0;
	virtual void RestoreBufferTo(const BYTE* pDataBuffer, int nDataLen, BYTE* pOutputBuffer) = 0;
};


//
// A DSM MT Plugin MUST export (extern "C" - __cdecl) the following functions
/*
extern "C"
{
PLUGIN_API char* Description(void);
PLUGIN_API int Startup(void);
PLUGIN_API int Shutdown(void);
PLUGIN_API int SetParams(HWND hVNC, char* szParams);
PLUGIN_API char* GetParams(void);
PLUGIN_API BYTE* TransformBuffer(BYTE* pDataBuffer, int nDataLen, int* pnTransformedDataLen);
PLUGIN_API BYTE* RestoreBuffer(BYTE* pTransBuffer, int nTransDataLen, int* pnRestoredDataLen);
PLUGIN_API void FreeBuffer(BYTE* pBuffer);
PLUGIN_API int Reset(void);

//adzm - 2009-06-20 - For the new plugins, simply use the interface. TransformBuffer/RestoreBuffer above
//simply call a static (single-threaded) version of the plugin interface for backwards compatibility.
PLUGIN_API IPlugin* CreatePluginInterface();

PLUGIN_API IIntegratedPlugin* CreateIntegratedPluginInterface();

PLUGIN_API IIntegratedPluginEx* CreateIntegratedPluginInterfaceEx();

PLUGIN_API int Config(HWND hVNC, char* szParams, char* szConfig, char** pszConfig);
}
*/