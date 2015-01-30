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
#include "MultithreadedPlugin.h"
#include "malloc.h"

#define BUFFER_EXTENT 256

MultithreadedPlugin::MultithreadedPlugin(void)
{
	m_bLegacyMode = false;

	//adzm - 2009-06-20 - Get our thread local storage index to store our per-thread local memory structure
	m_nMemorySlot = TlsAlloc();
	//adzm - 2009-06-20 - and initialize our interlocked linked list
	//m_pListHead = (PSLIST_HEADER)_aligned_malloc(sizeof(SLIST_HEADER), MEMORY_ALLOCATION_ALIGNMENT);
	//InitializeSListHead(m_pListHead);

	m_pFirstReference = NULL;
}

MultithreadedPlugin::~MultithreadedPlugin(void)
{
	FreeThreadLocalMemoryInfo();
	//_aligned_free(m_pListHead);

	TlsFree(m_nMemorySlot);
}



//
// Allocate more space for the local transformation buffer if necessary
// and returns the pointer to this buffer
//
BYTE* MultithreadedPlugin::EnsureLocalTransformBufferSize(int nBufferSize)
{	
	//adzm - 2009-06-20 - use the thread local memory
	if (nBufferSize == 0) return NULL;

	MultithreadedPlugin::ThreadLocalMemoryInfo* pMemory = GetThreadLocalMemoryInfo();

	if (pMemory->m_nTransBufferLen >= nBufferSize) {
		return pMemory->m_pTransBuffer;
	}
	
	pMemory->m_nTransBufferLen = nBufferSize + BUFFER_EXTENT;
	if (pMemory->m_pTransBuffer) {
		pMemory->m_pTransBuffer = (BYTE*)_aligned_realloc(pMemory->m_pTransBuffer, nBufferSize + BUFFER_EXTENT, 32);
	} else {
		pMemory->m_pTransBuffer = (BYTE*)_aligned_malloc((nBufferSize + BUFFER_EXTENT), 32);
	}

	return pMemory->m_pTransBuffer;
}

BYTE* MultithreadedPlugin::EnsureLocalTransformTempBufferSize(int nBufferSize)
{	
	//adzm - 2009-06-20 - use the thread local memory
	if (nBufferSize == 0) return NULL;

	MultithreadedPlugin::ThreadLocalMemoryInfo* pMemory = GetThreadLocalMemoryInfo();

	if (pMemory->m_nTransTempBufferLen >= nBufferSize) {
		return pMemory->m_pTransTempBuffer;
	}
	
	pMemory->m_nTransTempBufferLen = nBufferSize + BUFFER_EXTENT;
	if (pMemory->m_pTransTempBuffer) {
		pMemory->m_pTransTempBuffer = (BYTE*)_aligned_realloc(pMemory->m_pTransTempBuffer, nBufferSize + BUFFER_EXTENT, 32);
	} else {
		pMemory->m_pTransTempBuffer = (BYTE*)_aligned_malloc((nBufferSize + BUFFER_EXTENT), 32);
	}

	return pMemory->m_pTransTempBuffer;
}


//
// Allocate more space for the local restoration buffer if necessary
// and returns the pointer to this buffer
//
BYTE* MultithreadedPlugin::EnsureLocalRestoreBufferSize(int nBufferSize)
{
	//adzm - 2009-06-20 - use the thread local memory
	if (nBufferSize == 0) return NULL;
	
	MultithreadedPlugin::ThreadLocalMemoryInfo* pMemory = GetThreadLocalMemoryInfo();

	if (pMemory->m_nRestBufferLen >= nBufferSize) {
		return pMemory->m_pRestBuffer;
	}

	pMemory->m_nRestBufferLen = nBufferSize + BUFFER_EXTENT;
	if (pMemory->m_pRestBuffer) {
		pMemory->m_pRestBuffer = (BYTE*)_aligned_realloc(pMemory->m_pRestBuffer, nBufferSize + BUFFER_EXTENT, 32);
	} else {
		pMemory->m_pRestBuffer = (BYTE*)_aligned_malloc((nBufferSize + BUFFER_EXTENT), 32);
	}

	return pMemory->m_pRestBuffer;
}

BYTE* MultithreadedPlugin::EnsureLocalRestoreTempBufferSize(int nBufferSize)
{
	//adzm - 2009-06-20 - use the thread local memory
	if (nBufferSize == 0) return NULL;
	
	MultithreadedPlugin::ThreadLocalMemoryInfo* pMemory = GetThreadLocalMemoryInfo();

	if (pMemory->m_nRestTempBufferLen >= nBufferSize) {
		return pMemory->m_pRestTempBuffer;
	}

	pMemory->m_nRestTempBufferLen = nBufferSize + BUFFER_EXTENT;
	if (pMemory->m_pRestTempBuffer) {
		pMemory->m_pRestTempBuffer = (BYTE*)_aligned_realloc(pMemory->m_pRestTempBuffer, nBufferSize + BUFFER_EXTENT, 32);
	} else {
		pMemory->m_pRestTempBuffer = (BYTE*)_aligned_malloc((nBufferSize + BUFFER_EXTENT), 32);
	}

	return pMemory->m_pRestTempBuffer;
}

//adzm - 2009-06-20 - return the thread local memory structure (which is created if it does not exist)
MultithreadedPlugin::ThreadLocalMemoryInfo* MultithreadedPlugin::GetThreadLocalMemoryInfo()
{
	MultithreadedPlugin::ThreadLocalMemoryInfo* pMemory = NULL;

	LPVOID pValue = TlsGetValue(m_nMemorySlot);
	if (pValue == NULL) {
		pMemory = new MultithreadedPlugin::ThreadLocalMemoryInfo();
		TlsSetValue(m_nMemorySlot, pMemory);

		if (!m_bLegacyMode) {
			//MultithreadedPlugin::ThreadLocalMemoryReference* pMemoryReference = (MultithreadedPlugin::ThreadLocalMemoryReference*)_aligned_malloc(sizeof(MultithreadedPlugin::ThreadLocalMemoryReference), MEMORY_ALLOCATION_ALIGNMENT);
			
			MultithreadedPlugin::ThreadLocalMemoryReference* pMemoryReference = new MultithreadedPlugin::ThreadLocalMemoryReference;
			//ZeroMemory(pMemoryReference, sizeof(MultithreadedPlugin::ThreadLocalMemoryReference));

			{
				LockCriticalSection lock(m_csMemoryReferences);				
			
				pMemoryReference->pThreadLocalMemory = pMemory;

				if (m_pFirstReference) {
					pMemoryReference->pNext = m_pFirstReference;
					m_pFirstReference = pMemoryReference;
				} else {
					pMemoryReference->pNext = NULL;
					m_pFirstReference = pMemoryReference;
				}

				//InterlockedPushEntrySList(m_pListHead, (PSINGLE_LIST_ENTRY)pMemoryReference);
				//InterlockedPushEntrySList(m_pListHead, (PSLIST_ENTRY)pMemoryReference);
			}
		}
	} else {
		pMemory = (MultithreadedPlugin::ThreadLocalMemoryInfo*)pValue;
	}

	return pMemory;
}

//adzm - 2009-06-20 - free thread local memory (and therefore also the buffers) for all threads, and the list
void MultithreadedPlugin::FreeThreadLocalMemoryInfo()
{
	LockCriticalSection lock(m_csMemoryReferences);		

	//MultithreadedPlugin::ThreadLocalMemoryReference* pMemoryReference = (MultithreadedPlugin::ThreadLocalMemoryReference*)InterlockedFlushSList(m_pListHead);
	MultithreadedPlugin::ThreadLocalMemoryReference* pMemoryReference = m_pFirstReference;
	while (pMemoryReference) {
		//MultithreadedPlugin::ThreadLocalMemoryReference* pNextMemoryReference = (MultithreadedPlugin::ThreadLocalMemoryReference*)pMemoryReference->ItemEntry.Next;
		MultithreadedPlugin::ThreadLocalMemoryReference* pNextMemoryReference = pMemoryReference->pNext;

		delete pMemoryReference->pThreadLocalMemory;
		//_aligned_free(pMemoryReference);
		delete pMemoryReference;

		pMemoryReference = pNextMemoryReference;
	}
}