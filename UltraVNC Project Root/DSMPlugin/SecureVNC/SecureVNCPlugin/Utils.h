#pragma once

//adzm - 2009-06-20 - Simple critical section class
struct CriticalSection
{
	CriticalSection() {
		InitializeCriticalSection(&m_CriticalSection);
	};

	~CriticalSection() {
		DeleteCriticalSection(&m_CriticalSection);
	};

	operator LPCRITICAL_SECTION() {
		return &m_CriticalSection;
	};

	CRITICAL_SECTION m_CriticalSection;
};

//adzm - 2009-06-20 - Simple critical section holder
struct LockCriticalSection
{
	LockCriticalSection(LPCRITICAL_SECTION lpcs) :
		m_lpcs(lpcs) {
		EnterCriticalSection(m_lpcs);
	};

	~LockCriticalSection() {
		LeaveCriticalSection(m_lpcs);
	};

	LPCRITICAL_SECTION m_lpcs;
};

#define FILETIME_SECOND ((unsigned __int64) 10000000)
#define FILETIME_MINUTE (60 * FILETIME_SECOND)
#define FILETIME_HOUR   (60 * FILETIME_MINUTE)
#define FILETIME_DAY    (24 * FILETIME_HOUR)

#if defined(_DEBUG)
#define DebugLog g_Log.LogFormat
#define DebugLogBinary g_Log.LogBinary
#define DebugLogVerbose g_Log.LogFormat
#elif defined(LOG_VERBOSE)
#define DebugLog g_Log.LogFormat
#define DebugLogBinary g_Log.LogBinary
#define DebugLogVerbose g_Log.LogFormat
#else
#define DebugLog __noop
#define DebugLogBinary __noop
#define DebugLogVerbose __noop
#endif

#if defined(LOG_SENSITIVE)
#pragma message("WARNING! Sensitive data will be logged! This should be used strictly for debugging purposes only!")
#define DebugLogSensitive g_Log.LogFormat
#define DebugLogBinarySensitive g_Log.LogBinary
#else
#define DebugLogSensitive __noop
#define DebugLogBinarySensitive __noop
#endif

struct LogFile {
	LogFile() : 
		m_hLogFile(NULL) {
	};

	~LogFile();

	DWORD LogFormat(LPCTSTR szFormat, ...);
	DWORD LogTimestamp();
	DWORD Log(LPCTSTR sz);
	DWORD LogBinary(const BYTE* pData, DWORD nLength);

	operator HANDLE() {
		return GetLogFile();
	};

	HANDLE GetLogFile();

	CriticalSection m_cs;

	HANDLE m_hLogFile;
};

extern LogFile g_Log;