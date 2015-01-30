#pragma once

/////////////////////////////////////////////////////////////////////////

//
// A DSM Plugin MUST export (extern "C" - __cdecl) all the following functions
// (same names, same signatures)

void InitializeCriticalSections();
void DeleteCriticalSections();

extern char g_szConfig[512];
extern char g_szNewConfig[512];
extern bool g_bSupportsIntegrated;

enum EHostType
{	
	hostTypeViewer = -1,
	hostTypeUndetermined = 0,
	hostTypeServerApplication = 1,
	hostTypeServerService = 2,
};

extern EHostType g_hostType;

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

int DoConfig(HWND hVNC, char* szParams, char* szConfig, char** pszConfig, bool bEx);

class ConfigHelper
{
public:
	ConfigHelper(DWORD dwFlags, char* szPassphrase);
	ConfigHelper(const char* szConfig);
	~ConfigHelper();



	DWORD m_dwFlags;
	char* m_szConfig;
	char* m_szPassphrase;
};
