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
#include "Utils.h"

LogFile g_Log;

DWORD LogFile::LogFormat(LPCTSTR szFormat, ...)
{
#define LOG_BUFFER_SIZE 2048
	TCHAR szLogBuffer[LOG_BUFFER_SIZE];

	va_list args;
	va_start(args, szFormat);

	int nSize = _vsntprintf_s(szLogBuffer, LOG_BUFFER_SIZE - 2, _TRUNCATE, szFormat, args);

	LogTimestamp();

	return Log(szLogBuffer);
}

DWORD LogFile::LogTimestamp()
{
	SYSTEMTIME localtime;
	GetLocalTime(&localtime);

#define LOG_TIMESTAMP_BUFFER_SIZE 256
	TCHAR szLogTimestamp[LOG_TIMESTAMP_BUFFER_SIZE];

	int nSize = _sntprintf_s(szLogTimestamp, LOG_TIMESTAMP_BUFFER_SIZE - 2, _TRUNCATE, _T("%li:%li:%li.%li: \t"), long(localtime.wHour), long(localtime.wMinute), long(localtime.wSecond), long(localtime.wMilliseconds));

	return Log(szLogTimestamp);
}

DWORD LogFile::Log(LPCTSTR sz)
{
	DWORD nLength = (DWORD)_tcslen(sz);

	DWORD dwWritten = 0;
	WriteFile(g_Log.GetLogFile(), sz, nLength * sizeof(TCHAR), &dwWritten, NULL);

	::OutputDebugString(sz);
	::OutputDebugString("\n");

	return nLength;
}

DWORD LogFile::LogBinary(const BYTE* pData, DWORD nLength)
{
#ifdef UNICODE
#error LogBinary not implemented for UNICODE yet!
#endif

	const TCHAR HexChars[0x10] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

#define LOG_BINARY_BUFFER_SIZE ((0x10 * 3) + (2) + (0x10) + (3))
	TCHAR szLogBuffer[LOG_BINARY_BUFFER_SIZE];

	for (DWORD i = 0; i < nLength; i += 0x10) {
		::ZeroMemory(szLogBuffer, sizeof(szLogBuffer));
		DWORD nCurPos = 0;
		DWORD n = 0;
		for (n = i; n < (i + 0x10); n++) {
			if (n < nLength) {
				BYTE byte = pData[n];

				BYTE low = byte % 0x10;
				BYTE high = byte >> 4;

				szLogBuffer[nCurPos] = (HexChars[high]);
				nCurPos++;
				szLogBuffer[nCurPos] = (HexChars[low]);
				nCurPos++;
				szLogBuffer[nCurPos] = (' ');
				nCurPos++;
			} else {
				szLogBuffer[nCurPos] = (' ');
				nCurPos++;
				szLogBuffer[nCurPos] = (' ');
				nCurPos++;
				szLogBuffer[nCurPos] = (' ');
				nCurPos++;
			}
		}
		
		szLogBuffer[nCurPos] = ('\t');
		nCurPos++;
		szLogBuffer[nCurPos] = ('\t');
		nCurPos++;
		
		for (n = i; n < (i + 0x10); n++) {
			if (n < nLength) {
				BYTE byte = pData[n];

				switch(byte) {
					case 0:
					case '\t':
					case '\r':
					case '\n':
						szLogBuffer[nCurPos] = (' ');
						break;
					default:
						szLogBuffer[nCurPos] = byte;
						break;
				}

				nCurPos++;
			} else {
				szLogBuffer[nCurPos] = (' ');
				nCurPos++;
			}
		}

		szLogBuffer[nCurPos] = '\r';
		nCurPos++;
		szLogBuffer[nCurPos] = '\n';
		nCurPos++;
		szLogBuffer[nCurPos] = '\0';
		nCurPos++;

		Log(szLogBuffer);
	}

	Log(_T("\r\n"));

	return nLength;
}

HANDLE LogFile::GetLogFile() {
	LockCriticalSection lock(m_cs);
	if (!m_hLogFile) {		
		SYSTEMTIME st, lt;	    
		GetSystemTime(&st);
		GetLocalTime(&lt);

		TCHAR szLogName[96];
		_stprintf_s(szLogName, 96 - 1, _T("SecureVNCPlugin_%04d%02d%02d_%02d%02d%02d_%03d.log"), lt.wYear, lt.wMonth, lt.wDay, lt.wHour, lt.wMinute, lt.wSecond, lt.wMilliseconds);
		
		TCHAR szLogFile[_MAX_PATH];

		if (GetTempPath(_MAX_PATH - 1, szLogFile)) {
			_tcscat_s(szLogFile, _MAX_PATH - 1, szLogName);
		} else {
			_tcscpy_s(szLogFile, _MAX_PATH - 1, szLogName);
		}

		m_hLogFile = CreateFile(szLogFile, GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (m_hLogFile) {
			SetFilePointer(m_hLogFile, 0, NULL, FILE_END);

			TCHAR* szHeader = _T("\r\n* Opened log\r\n\r\n");
			DWORD dwWritten = 0;
			WriteFile(m_hLogFile, szHeader, (DWORD)_tcslen(szHeader) * sizeof(TCHAR), &dwWritten, NULL);
		}
	}
	
	return m_hLogFile;
};

LogFile::~LogFile() {
	LockCriticalSection lock(m_cs);
	if (m_hLogFile) {			
		TCHAR* szHeader = _T("\r\n\r\n* Closed log\r\n");
		DWORD dwWritten = 0;
		WriteFile(m_hLogFile, szHeader, (DWORD)_tcslen(szHeader) * sizeof(TCHAR), &dwWritten, NULL);

		::CloseHandle(m_hLogFile);
	}
	m_hLogFile = NULL;
};