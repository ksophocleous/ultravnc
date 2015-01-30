// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#ifdef SECUREVNCPLUGIN_EXPORTS
#define SECUREVNCPLUGIN_API __declspec(dllexport)
#else
#define SECUREVNCPLUGIN_API __declspec(dllimport)
#endif

#define PLUGIN_API SECUREVNCPLUGIN_API

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
#include <windows.h>
#include "TCHAR.h"

#include "version.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include "plugin.h"
#include "utils.h"
#include "cryptutils.h"

#pragma comment(lib, "libeay32.lib")

extern HINSTANCE g_hInstance;



// TODO: reference additional headers your program requires here
