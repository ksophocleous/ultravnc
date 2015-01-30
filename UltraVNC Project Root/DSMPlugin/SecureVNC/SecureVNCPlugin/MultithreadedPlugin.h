/////////////////////////////////////////////////////////////////////////////
//  Copyright (C) 2005 Ultr@Vnc.  All Rights Reserved.
//  Copyright (C) 2010 Adam D. Walling aka Adzm.  All Rights Reserved.
//
//  (2009)
//  Multithreaded DSM plugin framework created by Adam D. Walling
//
////////////////////////////////////////////////////////////////////////////

#pragma once
#include "plugin.h"
#include "utils.h"


//adzm - 2009-06-20 - Derived classes are responsible for handling their own synchronization
class MultithreadedPlugin
{
public:
	//adzm - 2009-06-20 - The plugin maintains its own memory. This keeps track of memory
	//local to the current thread. When allocated, it is added to our linked list and
	//freed in the MultithreadedPlugin destructor.
	struct ThreadLocalMemoryInfo {
		ThreadLocalMemoryInfo() {
			m_pTransBuffer = NULL;
			m_pRestBuffer = NULL;
			m_nTransBufferLen = 0;
			m_nRestBufferLen = 0;
			m_pTransTempBuffer = NULL;
			m_pRestTempBuffer = NULL;
			m_nTransTempBufferLen = 0;
			m_nRestTempBufferLen = 0;
		};

		~ThreadLocalMemoryInfo() {
			if (m_pTransBuffer) {
				_aligned_free(m_pTransBuffer);
				m_pTransBuffer = NULL;
			}
			if (m_pRestBuffer) {
				_aligned_free(m_pRestBuffer);
				m_pRestBuffer = NULL;
			}
			if (m_pTransTempBuffer) {
				_aligned_free(m_pTransTempBuffer);
				m_pTransTempBuffer = NULL;
			}
			if (m_pRestTempBuffer) {
				_aligned_free(m_pRestTempBuffer);
				m_pRestTempBuffer = NULL;
			}
		};

		BYTE* m_pTransBuffer;
		long m_nTransBufferLen;
		BYTE* m_pRestBuffer;
		long m_nRestBufferLen;
		BYTE* m_pTransTempBuffer;
		long m_nTransTempBufferLen;
		BYTE* m_pRestTempBuffer;
		long m_nRestTempBufferLen;
	};	

	//adzm - 2009-06-20 - Used for the interlocked single list functions
	struct ThreadLocalMemoryReference {
		//SLIST_ENTRY ItemEntry;
		ThreadLocalMemoryInfo* pThreadLocalMemory;
		ThreadLocalMemoryReference* pNext;
	};

	MultithreadedPlugin(void);
	~MultithreadedPlugin(void);

	void SetLegacyMode(bool bLegacyMode) {m_bLegacyMode = bLegacyMode;};

protected:	
	bool m_bLegacyMode; //it is terrible, but useful. in legacy mode we do not try to clean up any of our memory.
	// a small price to pay for some backwards compatibility.

	
	BYTE* EnsureLocalTransformBufferSize(int nBufferSize);
	BYTE* EnsureLocalRestoreBufferSize(int nBufferSize);
	
	BYTE* EnsureLocalTransformTempBufferSize(int nBufferSize);
	BYTE* EnsureLocalRestoreTempBufferSize(int nBufferSize);

	//adzm - 2009-06-20 - return the thread local memory structure (which is created if it does not exist)
	ThreadLocalMemoryInfo* GetThreadLocalMemoryInfo();
	//adzm - 2009-06-20 - free thread local memory (and therefore also the buffers) for all threads, and the list
	void FreeThreadLocalMemoryInfo();
	DWORD m_nMemorySlot;
	//PSLIST_HEADER m_pListHead;
	ThreadLocalMemoryReference* m_pFirstReference;
	CriticalSection m_csMemoryReferences;
};
