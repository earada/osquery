//
//	The MIT License
//
//	Copyright (c) 2010 James E Beveridge
//
//	Permission is hereby granted, free of charge, to any person obtaining a copy
//	of this software and associated documentation files (the "Software"), to deal
//	in the Software without restriction, including without limitation the rights
//	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//	copies of the Software, and to permit persons to whom the Software is
//	furnished to do so, subject to the following conditions:
//
//	The above copyright notice and this permission notice shall be included in
//	all copies or substantial portions of the Software.
//
//	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//	THE SOFTWARE.

#pragma once

#define _CRT_SECURE_NO_DEPRECATE

#include <stdio.h>
#include <windows.h>

#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS      // some CString constructors will be explicit

#include <atlbase.h>
#include <atlstr.h>

#include <vector>
#include <list>

namespace ReadDirectoryChangesPrivate
{

class CReadChangesServer;

///////////////////////////////////////////////////////////////////////////

// All functions in CReadChangesRequest run in the context of the worker thread.
// One instance of this object is created for each call to AddDirectory().
class CReadChangesRequest
{
public:
	CReadChangesRequest(CReadChangesServer* pServer, LPCTSTR sz, BOOL b, DWORD dw, DWORD size);

	~CReadChangesRequest();

	bool OpenDirectory();

	void BeginRead();

	// The dwSize is the actual number of bytes sent to the APC.
	void BackupBuffer(DWORD dwSize)
	{
		// We could just swap back and forth between the two
		// buffers, but this code is easier to understand and debug.
		memcpy(&m_BackupBuffer[0], &m_Buffer[0], dwSize);
	}

	void ProcessNotification();

	void RequestTermination()
	{
		::CancelIo(m_hDirectory);
		::CloseHandle(m_hDirectory);
		m_hDirectory = nullptr;
	}

	CReadChangesServer* m_pServer;

protected:

	static VOID CALLBACK NotificationCompletion(
			DWORD dwErrorCode,							// completion code
			DWORD dwNumberOfBytesTransfered,			// number of bytes transferred
			LPOVERLAPPED lpOverlapped);					// I/O information buffer

	// Parameters from the caller for ReadDirectoryChangesW().
	DWORD		m_dwFilterFlags;
	BOOL		m_bIncludeChildren;
	CStringW	m_wstrDirectory;

	// Result of calling CreateFile().
	HANDLE		m_hDirectory;

	// Required parameter for ReadDirectoryChangesW().
	OVERLAPPED	m_Overlapped;

	// Data buffer for the request.
	// Since the memory is allocated by malloc, it will always
	// be aligned as required by ReadDirectoryChangesW().
	std::vector<BYTE> m_Buffer;

	// Double buffer strategy so that we can issue a new read
	// request before we process the current buffer.
	std::vector<BYTE> m_BackupBuffer;
};

template <typename C>
class CThreadSafeQueue : protected std::list<C>
{
public:
	CThreadSafeQueue(int nMaxCount)
	{
		m_bOverflow = false;

		m_hSemaphore = ::CreateSemaphore(
			NULL,		// no security attributes
			0,			// initial count
			nMaxCount,	// max count
			NULL);		// anonymous
	}

	~CThreadSafeQueue()
	{
		::CloseHandle(m_hSemaphore);
		m_hSemaphore = NULL;
	}

	void push(C& c)
	{
		CComCritSecLock<CComAutoCriticalSection> lock( m_Crit, true );
		push_back( c );
		lock.Unlock();

		if (!::ReleaseSemaphore(m_hSemaphore, 1, NULL))
		{
			// If the semaphore is full, then take back the entry.
			lock.Lock();
			pop_back();
			if (GetLastError() == ERROR_TOO_MANY_POSTS)
			{
				m_bOverflow = true;
			}
		}
	}

	bool pop(C& c)
	{
		CComCritSecLock<CComAutoCriticalSection> lock( m_Crit, true );

		// If the user calls pop() more than once after the
		// semaphore is signaled, then the semaphore count will
		// get out of sync.  We fix that when the queue empties.
		if (empty())
		{
			while (::WaitForSingleObject(m_hSemaphore, 0) != WAIT_TIMEOUT)
				1;
			return false;
		}

		c = front();
		pop_front();

		return true;
	}

	// If overflow, use this to clear the queue.
	void clear()
	{
		CComCritSecLock<CComAutoCriticalSection> lock( m_Crit, true );

		for (DWORD i=0; i<size(); i++)
			WaitForSingleObject(m_hSemaphore, 0);

		__super::clear();

		m_bOverflow = false;
	}

	bool overflow()
	{
		return m_bOverflow;
	}

	HANDLE GetWaitHandle() { return m_hSemaphore; }

protected:
	HANDLE m_hSemaphore;

	CComAutoCriticalSection m_Crit;

	bool m_bOverflow;
};

class CReadChangesServer
{
public:

	CReadChangesServer(CThreadSafeQueue<std::pair<DWORD,CStringW>>* pParent)
	{
		m_bTerminate=false; m_nOutstandingRequests=0;queue=pParent;
	}

	static unsigned int WINAPI ThreadStartProc(LPVOID arg)
	{
		CReadChangesServer* pServer = (CReadChangesServer*)arg;
		pServer->Run();
		return 0;
	}

	// Called by QueueUserAPC to start orderly shutdown.
	static void CALLBACK TerminateProc(__in  ULONG_PTR arg)
	{
		CReadChangesServer* pServer = (CReadChangesServer*)arg;
		pServer->RequestTermination();
	}

	// Called by QueueUserAPC to add another directory.
	static void CALLBACK AddDirectoryProc(__in  ULONG_PTR arg)
	{
		CReadChangesRequest* pRequest = (CReadChangesRequest*)arg;
		pRequest->m_pServer->AddDirectory(pRequest);
	}

	CThreadSafeQueue<std::pair<DWORD,CStringW>>* queue;

	volatile DWORD m_nOutstandingRequests;

protected:

	void Run()
	{
		while (m_nOutstandingRequests || !m_bTerminate)
		{
			DWORD rc = ::SleepEx(INFINITE, true);
		}
	}

	void AddDirectory( CReadChangesRequest* pBlock )
	{
		if (pBlock->OpenDirectory())
		{
			::InterlockedIncrement(&pBlock->m_pServer->m_nOutstandingRequests);
			m_pBlocks.push_back(pBlock);
			pBlock->BeginRead();
		}
		else
			delete pBlock;
	}

	void RequestTermination()
	{
		m_bTerminate = true;

		for (DWORD i=0; i<m_pBlocks.size(); ++i)
		{
			// Each Request object will delete itself.
			m_pBlocks[i]->RequestTermination();
		}

		m_pBlocks.clear();
	}

	std::vector<CReadChangesRequest*> m_pBlocks;

	bool m_bTerminate;
};
}
