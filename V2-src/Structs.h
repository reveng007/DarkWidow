#pragma once
#include <Windows.h>
//#include <winternl.h>
#include <ctype.h> 

typedef struct
{
    PVOID       Fixup;             // 0
    PVOID       OG_retaddr;        // 8
    PVOID       rbx;               // 16    // rbx (PRM.rbx) : Contains addr of this PRM struct
    PVOID       rdi;               // 24
    PVOID       BTIT_ss;           // 32
    PVOID       BTIT_retaddr;      // 40
    PVOID       Gadget_ss;         // 48
    PVOID       RUTS_ss;           // 56
    PVOID       RUTS_retaddr;      // 64
    PVOID       ssn;               // 72  
    PVOID       trampoline;        // 80
    PVOID       rsi;               // 88
    PVOID       r12;               // 96
    PVOID       r13;               // 104
    PVOID       r14;               // 112
    PVOID       r15;               // 120
} PRM, * PPRM;

/* God Bless Vulcan Raven*/
typedef struct
{
    LPCWSTR dllPath;
    ULONG offset;
    ULONG totalStackSize;
    BOOL requiresLoadLibrary;
    BOOL setsFramePointer;
    PVOID returnAddress;
    BOOL pushRbp;
    ULONG countOfCodes;
    BOOL pushRbpIndex;
} StackFrame, * PStackFrame;

typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0, /* info == register number */
    UWOP_ALLOC_LARGE,     /* no info, alloc size in next 2 slots */
    UWOP_ALLOC_SMALL,     /* info == size of allocation / 8 - 1 */
    UWOP_SET_FPREG,       /* no info, FP = RSP + UNWIND_INFO.FPRegOffset*16 */
    UWOP_SAVE_NONVOL,     /* info == register number, offset in next slot */
    UWOP_SAVE_NONVOL_FAR, /* info == register number, offset in next 2 slots */
    UWOP_SAVE_XMM128 = 8, /* info == XMM reg number, offset in next slot */
    UWOP_SAVE_XMM128_FAR, /* info == XMM reg number, offset in next 2 slots */
    UWOP_PUSH_MACHFRAME   /* info == 0: no error-code, 1: error-code */
} UNWIND_CODE_OPS;

typedef union _UNWIND_CODE {
    struct {
        BYTE CodeOffset;
        BYTE UnwindOp : 4;
        BYTE OpInfo : 4;
    };
    USHORT FrameOffset;
} UNWIND_CODE, * PUNWIND_CODE;

typedef struct _UNWIND_INFO {
    BYTE Version : 3;
    BYTE Flags : 5;
    BYTE SizeOfProlog;
    BYTE CountOfCodes;
    BYTE FrameRegister : 4;
    BYTE FrameOffset : 4;
    UNWIND_CODE UnwindCode[1];
    /*  UNWIND_CODE MoreUnwindCode[((CountOfCodes + 1) & ~1) - 1];
    *   union {
    *       OPTIONAL ULONG ExceptionHandler;
    *       OPTIONAL ULONG FunctionEntry;
    *   };
    *   OPTIONAL ULONG ExceptionData[]; */
} UNWIND_INFO, * PUNWIND_INFO;

// For NtOpenFile:
/*
#define InitializeObjectAttributes( p, n, a, r, s ) { \
(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
(p)->RootDirectory = r;                           \
(p)->Attributes = a;                              \
(p)->ObjectName = n;                              \
(p)->SecurityDescriptor = s;                      \
(p)->SecurityQualityOfService = NULL;             \
}
*/
// Process Hacker: https://processhacker.sourceforge.io/doc/ntbasic_8h.html
#define OBJ_CASE_INSENSITIVE 0x00000040

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

//extern void RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);

// For NtMapViewOfSection:

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;

// For PEB and TEB:

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef struct _CLIENT_ID {
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _API_SET_NAMESPACE {
	ULONG Version;
	ULONG Size;
	ULONG Flags;
	ULONG Count;
	ULONG EntryOffset;
	ULONG HashOffset;
	ULONG HashFactor;
} API_SET_NAMESPACE, * PAPI_SET_NAMESPACE;

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

// Partial PEB
typedef struct _PEB {
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsLegacyProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN SpareBits : 3;
		};
	};
	HANDLE Mutant;

	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
	PVOID IFEOKey;
	PSLIST_HEADER AtlThunkSListPtr;
	union
	{
		ULONG CrossProcessFlags;
		struct
		{
			ULONG ProcessInJob : 1;
			ULONG ProcessInitializing : 1;
			ULONG ProcessUsingVEH : 1;
			ULONG ProcessUsingVCH : 1;
			ULONG ProcessUsingFTH : 1;
			ULONG ProcessPreviouslyThrottled : 1;
			ULONG ProcessCurrentlyThrottled : 1;
			ULONG ProcessImagesHotPatched : 1;
			ULONG ReservedBits0 : 24;
		};
	};
	union
	{
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	};
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PAPI_SET_NAMESPACE ApiSetMap;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID SharedData;
	PVOID* ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	ULARGE_INTEGER CriticalSectionTimeout;
	SIZE_T HeapSegmentReserve;
	SIZE_T HeapSegmentCommit;
	SIZE_T HeapDeCommitTotalFreeThreshold;
	SIZE_T HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID* ProcessHeaps;
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;
	PRTL_CRITICAL_SECTION LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	USHORT OSBuildNumber;
} PEB, * PPEB;

/*
// From: https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-list_entry
typedef struct _LIST_ENTRY {
	struct _LIST_ENTRY* Flink;	// Next Object -> *next 
	struct _LIST_ENTRY* Blink;	// Previous Object -> *prev
} LIST_ENTRY, * PLIST_ENTRY, PRLIST_ENTRY;
*/

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	union
	{
		LIST_ENTRY InInitializationOrderLinks;
		LIST_ENTRY InProgressLinks;
	};
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _TEB {
	PVOID Reserved1[12];
	PPEB  ProcessEnvironmentBlock;
	PVOID Reserved2[399];
	BYTE  Reserved3[1952];
	PVOID TlsSlots[64];
	BYTE  Reserved4[8];
	PVOID Reserved5[26];
	PVOID ReservedForOle;
	PVOID Reserved6[4];
	PVOID TlsExpansionSlots;
} TEB, * PTEB;

typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS    exitStatus;
	PVOID       pTebBaseAddress;
	CLIENT_ID   clientId;
	KAFFINITY   AffinityMask;
	int			Priority;
	int			BasePriority;
	int			v;

} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;


// NtOpenProcess:

#define InitializeObjectAttributes( p, n, a, r, s ) { \
(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
(p)->RootDirectory = r;                           \
(p)->Attributes = a;                              \
(p)->ObjectName = n;                              \
(p)->SecurityDescriptor = s;                      \
(p)->SecurityQualityOfService = NULL;             \
}

#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON   0x0000100000000000
#define PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON 0x0000001000000000
#define PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY 0x00020007
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS    0x00020000

typedef BOOL(WINAPI *InitializeProcThreadAttributeListFunc)(
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
    DWORD dwAttributeCount,
    DWORD dwFlags,
    PSIZE_T lpSize
);

typedef BOOL(WINAPI *UpdateProcThreadAttributeFunc)(
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
    DWORD dwFlags,
    DWORD_PTR Attribute,
    PVOID lpValue,
    SIZE_T cbSize,
    PVOID lpPreviousValue,
    PSIZE_T lpReturnSize
);

typedef struct _STARTUPINFOEXA {
    STARTUPINFOA StartupInfo;
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
} STARTUPINFOEXA, *LPSTARTUPINFOEXA;


/* NtCreateUserProcess: Thanks to: MalDevAcademy Module 91 */

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001 // NtCreateUserProcess & NtCreateThreadEx
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH 0x00000002 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_LOADER_WORKER 0x00000010 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_SKIP_LOADER_INIT 0x00000020 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE 0x00000040 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_INITIAL_THREAD 0x00000080 // ?

// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h#L1934

typedef enum _PS_ATTRIBUTE_NUM
{
    PsAttributeParentProcess, // in HANDLE
    PsAttributeDebugObject, // in HANDLE
    PsAttributeToken, // in HANDLE
    PsAttributeClientId, // out PCLIENT_ID
    PsAttributeTebAddress, // out PTEB *
    PsAttributeImageName, // in PWSTR
    PsAttributeImageInfo, // out PSECTION_IMAGE_INFORMATION
    PsAttributeMemoryReserve, // in PPS_MEMORY_RESERVE
    PsAttributePriorityClass, // in UCHAR
    PsAttributeErrorMode, // in ULONG
    PsAttributeStdHandleInfo, // 10, in PPS_STD_HANDLE_INFO
    PsAttributeHandleList, // in HANDLE[]
    PsAttributeGroupAffinity, // in PGROUP_AFFINITY
    PsAttributePreferredNode, // in PUSHORT
    PsAttributeIdealProcessor, // in PPROCESSOR_NUMBER
    PsAttributeUmsThread, // ? in PUMS_CREATE_THREAD_ATTRIBUTES
    PsAttributeMitigationOptions, // in PPS_MITIGATION_OPTIONS_MAP (PROCESS_CREATION_MITIGATION_POLICY_*) // since WIN8
    PsAttributeProtectionLevel, // in PS_PROTECTION // since WINBLUE
    PsAttributeSecureProcess, // in PPS_TRUSTLET_CREATE_ATTRIBUTES, since THRESHOLD
    PsAttributeJobList, // in HANDLE[]
    PsAttributeChildProcessPolicy, // 20, in PULONG (PROCESS_CREATION_CHILD_PROCESS_*) // since THRESHOLD2
    PsAttributeAllApplicationPackagesPolicy, // in PULONG (PROCESS_CREATION_ALL_APPLICATION_PACKAGES_*) // since REDSTONE
    PsAttributeWin32kFilter, // in PWIN32K_SYSCALL_FILTER
    PsAttributeSafeOpenPromptOriginClaim, // in SE_SAFE_OPEN_PROMPT_RESULTS
    PsAttributeBnoIsolation, // in PPS_BNO_ISOLATION_PARAMETERS // since REDSTONE2
    PsAttributeDesktopAppPolicy, // in PULONG (PROCESS_CREATION_DESKTOP_APP_*)
    PsAttributeChpe, // in BOOLEAN // since REDSTONE3
    PsAttributeMitigationAuditOptions, // in PPS_MITIGATION_AUDIT_OPTIONS_MAP (PROCESS_CREATION_MITIGATION_AUDIT_POLICY_*) // since 21H1
    PsAttributeMachineType, // in USHORT // since 21H2
    PsAttributeComponentFilter,
    PsAttributeEnableOptionalXStateFeatures, // since WIN11
    PsAttributeMax
} PS_ATTRIBUTE_NUM;

// private
#define PS_ATTRIBUTE_NUMBER_MASK 0x0000ffff
#define PS_ATTRIBUTE_THREAD 0x00010000 // may be used with thread creation
#define PS_ATTRIBUTE_INPUT 0x00020000 // input only
#define PS_ATTRIBUTE_ADDITIVE 0x00040000 // "accumulated" e.g. bitmasks, counters, etc.

#define PsAttributeValue(Number, Thread, Input, Additive) \
    (((Number) & PS_ATTRIBUTE_NUMBER_MASK) | \
    ((Thread) ? PS_ATTRIBUTE_THREAD : 0) | \
    ((Input) ? PS_ATTRIBUTE_INPUT : 0) | \
    ((Additive) ? PS_ATTRIBUTE_ADDITIVE : 0))

#define PS_ATTRIBUTE_PARENT_PROCESS PsAttributeValue(PsAttributeParentProcess, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_DEBUG_PORT PsAttributeValue(PsAttributeDebugPort, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_TOKEN PsAttributeValue(PsAttributeToken, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_CLIENT_ID PsAttributeValue(PsAttributeClientId, TRUE, FALSE, FALSE)
#define PS_ATTRIBUTE_TEB_ADDRESS PsAttributeValue(PsAttributeTebAddress, TRUE, FALSE, FALSE)
#define PS_ATTRIBUTE_IMAGE_NAME PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_IMAGE_INFO PsAttributeValue(PsAttributeImageInfo, FALSE, FALSE, FALSE)
#define PS_ATTRIBUTE_MEMORY_RESERVE PsAttributeValue(PsAttributeMemoryReserve, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_PRIORITY_CLASS PsAttributeValue(PsAttributePriorityClass, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_ERROR_MODE PsAttributeValue(PsAttributeErrorMode, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_STD_HANDLE_INFO PsAttributeValue(PsAttributeStdHandleInfo, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_HANDLE_LIST PsAttributeValue(PsAttributeHandleList, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_GROUP_AFFINITY PsAttributeValue(PsAttributeGroupAffinity, TRUE, TRUE, FALSE)
#define PS_ATTRIBUTE_PREFERRED_NODE PsAttributeValue(PsAttributePreferredNode, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_IDEAL_PROCESSOR PsAttributeValue(PsAttributeIdealProcessor, TRUE, TRUE, FALSE)
#define PS_ATTRIBUTE_UMS_THREAD PsAttributeValue(PsAttributeUmsThread, TRUE, TRUE, FALSE)
#define PS_ATTRIBUTE_MITIGATION_OPTIONS PsAttributeValue(PsAttributeMitigationOptions, FALSE, TRUE, FALSE)

#define PS_ATTRIBUTE_PROTECTION_LEVEL PsAttributeValue(PsAttributeProtectionLevel, FALSE, TRUE, TRUE)


//#define PS_ATTRIBUTE_PROTECTION_LEVEL PsAttributeValue(PsAttributeProtectionLevel, FALSE, TRUE, FALSE)

#define PS_ATTRIBUTE_SECURE_PROCESS PsAttributeValue(PsAttributeSecureProcess, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_JOB_LIST PsAttributeValue(PsAttributeJobList, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_CHILD_PROCESS_POLICY PsAttributeValue(PsAttributeChildProcessPolicy, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY PsAttributeValue(PsAttributeAllApplicationPackagesPolicy, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_WIN32K_FILTER PsAttributeValue(PsAttributeWin32kFilter, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_SAFE_OPEN_PROMPT_ORIGIN_CLAIM PsAttributeValue(PsAttributeSafeOpenPromptOriginClaim, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_BNO_ISOLATION PsAttributeValue(PsAttributeBnoIsolation, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_DESKTOP_APP_POLICY PsAttributeValue(PsAttributeDesktopAppPolicy, FALSE, TRUE, FALSE)

// 

#define PS_ATTRIBUTE_CHPE PsAttributeValue(PsAttributeChpe, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_MITIGATION_AUDIT_OPTIONS PsAttributeValue(PsAttributeMitigationAuditOptions, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_MACHINE_TYPE PsAttributeValue(PsAttributeMachineType, FALSE, TRUE, TRUE)

// 

#define RTL_USER_PROC_PARAMS_NORMALIZED 0x00000001      // indicates that the parameters passed to the process are already in a normalized form
#define RTL_USER_PROC_PROFILE_USER 0x00000002           // enables user-mode profiling for the process
#define RTL_USER_PROC_PROFILE_KERNEL 0x00000004         // enables kernel-mode profiling for the process
#define RTL_USER_PROC_PROFILE_SERVER 0x00000008         // enables server-mode profiling for the process
#define RTL_USER_PROC_RESERVE_1MB 0x00000020            // reserves 1 megabyte (MB) of virtual address space for the process
#define RTL_USER_PROC_RESERVE_16MB 0x00000040           // reserves 16 MB of virtual address space for the process
#define RTL_USER_PROC_CASE_SENSITIVE 0x00000080         // sets the process to be case-sensitive
#define RTL_USER_PROC_DISABLE_HEAP_DECOMMIT 0x00000100  // disables heap decommitting for the process
#define RTL_USER_PROC_DLL_REDIRECTION_LOCAL 0x00001000  // enables local DLL redirection for the process
#define RTL_USER_PROC_APP_MANIFEST_PRESENT 0x00002000   // indicates that an application manifest is present for the process
#define RTL_USER_PROC_IMAGE_KEY_MISSING 0x00004000      // indicates that the image key is missing for the process
#define RTL_USER_PROC_OPTIN_PROCESS 0x00020000          // indicates that the process has opted in to some specific behavior or feature


// From : https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h

typedef enum _PS_CREATE_STATE
{
    PsCreateInitialState,
    PsCreateFailOnFileOpen,
    PsCreateFailOnSectionCreate,
    PsCreateFailExeFormat,
    PsCreateFailMachineMismatch,
    PsCreateFailExeName, // Debugger specified
    PsCreateSuccess,
    PsCreateMaximumStates
} PS_CREATE_STATE;

typedef struct _PS_CREATE_INFO
{
    SIZE_T Size;
    PS_CREATE_STATE State;
    union
    {
        // PsCreateInitialState
        struct
        {
            union
            {
                ULONG InitFlags;
                struct
                {
                    UCHAR WriteOutputOnExit : 1;
                    UCHAR DetectManifest : 1;
                    UCHAR IFEOSkipDebugger : 1;
                    UCHAR IFEODoNotPropagateKeyState : 1;
                    UCHAR SpareBits1 : 4;
                    UCHAR SpareBits2 : 8;
                    USHORT ProhibitedImageCharacteristics : 16;
                };
            };
            ACCESS_MASK AdditionalFileAccess;
        } InitState;

        // PsCreateFailOnSectionCreate
        struct
        {
            HANDLE FileHandle;
        } FailSection;

        // PsCreateFailExeFormat
        struct
        {
            USHORT DllCharacteristics;
        } ExeFormat;

        // PsCreateFailExeName
        struct
        {
            HANDLE IFEOKey;
        } ExeName;

        // PsCreateSuccess
        struct
        {
            union
            {
                ULONG OutputFlags;
                struct
                {
                    UCHAR ProtectedProcess : 1;
                    UCHAR AddressSpaceOverride : 1;
                    UCHAR DevOverrideEnabled : 1; // from Image File Execution Options
                    UCHAR ManifestDetected : 1;
                    UCHAR ProtectedProcessLight : 1;
                    UCHAR SpareBits1 : 3;
                    UCHAR SpareBits2 : 8;
                    USHORT SpareBits3 : 16;
                };
            };
            HANDLE FileHandle;
            HANDLE SectionHandle;
            ULONGLONG UserProcessParametersNative;
            ULONG UserProcessParametersWow64;
            ULONG CurrentParameterFlags;
            ULONGLONG PebAddressNative;
            ULONG PebAddressWow64;
            ULONGLONG ManifestAddress;
            ULONG ManifestSize;
        } SuccessState;
    };
} PS_CREATE_INFO, * PPS_CREATE_INFO;

typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    //PS_ATTRIBUTE Attributes[1];
    //PS_ATTRIBUTE Attributes[2];
    PS_ATTRIBUTE Attributes[3];         // For Assinging 3 attributes: Image of SPAWN Process (1) + PPID spoof (2) + (Block Non MS DLL + ACG) (3)
    //PS_ATTRIBUTE Attributes[4];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

// CUSTOM FUNCTION FOR OG RtlInitUnicodeString: CREDIT MalDevAcademy

VOID _RtlInitUnicodeString(OUT PUNICODE_STRING UsStruct, IN OPTIONAL PCWSTR Buffer)
{
    if ((UsStruct->Buffer = (PWSTR)Buffer)) {

        unsigned int Length = wcslen(Buffer) * sizeof(WCHAR);
        if (Length > 0xfffc)
            Length = 0xfffc;

        UsStruct->Length = Length;
        UsStruct->MaximumLength = UsStruct->Length + sizeof(WCHAR);
    }

    else UsStruct->Length = UsStruct->MaximumLength = 0;
}

// For NtCreateUserProcess:
typedef NTSTATUS(WINAPI* fnNtCreateUserProcess)(PHANDLE, PHANDLE, 
                                                ACCESS_MASK, ACCESS_MASK, 
                                                POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, 
                                                ULONG, ULONG,
                                                PRTL_USER_PROCESS_PARAMETERS,
                                                PPS_CREATE_INFO, 
                                                PPS_ATTRIBUTE_LIST);

// For RtlCreateProcessParametersEx:
typedef NTSTATUS(WINAPI* fnRtlCreateProcessParametersEx)(PRTL_USER_PROCESS_PARAMETERS*, 
                                                PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, 
                                                PVOID,
                                                PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING,
                                                ULONG);

#define PROCESS_CREATE_FLAGS_SUSPENDED 0x00000200
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001

//fnNtCreateUserProcess NtCreateUserProcess = (fnNtCreateUserProcess)GetProcAddress(GetModuleHandleW(L"NTDLL"), "NtCreateUserProcess");
//fnRtlCreateProcessParametersEx RtlCreateProcessParametersEx = (fnRtlCreateProcessParametersEx)GetProcAddress(GetModuleHandleW(L"NTDLL"), "RtlCreateProcessParametersEx");

// Try This:
//fnNtCreateUserProcess NtCreateUserProcess = (fnNtCreateUserProcess)(GetProcAddress(GetModuleHandle(L"NTDLL"), "NtCreateUserProcess"));
//fnRtlCreateProcessParametersEx RtlCreateProcessParametersEx = (fnRtlCreateProcessParametersEx)(GetProcAddress(GetModuleHandle(L"NTDLL"), "RtlCreateProcessParametersEx"));

