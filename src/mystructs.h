#pragma once
// Taken From : https://github.com/reveng007/AQUARMOURY/blob/1923e65190875f7c61c76fb430d526e5deaa062a/Wraith/Src/Syscalls.h
#include <Windows.h>

#define InitializeObjectAttributes( p, n, a, r, s ) { \
(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
(p)->RootDirectory = r;                           \
(p)->Attributes = a;                              \
(p)->ObjectName = n;                              \
(p)->SecurityDescriptor = s;                      \
(p)->SecurityQualityOfService = NULL;             \
}

/*
#define InitializeObjectAttributes1(p,n,a,r,s) { \
	(p)->Length = sizeof(OBJECT_ATTRIBUTES); \
	(p)->RootDirectory = (r); \
	(p)->Attributes = (a); \
	(p)->ObjectName = (n); \
	(p)->SecurityDescriptor = (s); \
	(p)->SecurityQualityOfService = NULL; \
}
*/

//	From: https://learn.microsoft.com/en-us/windows/win32/api/ntdef/nf-ntdef-initializeobjectattributes
/*
VOID InitializeObjectAttributes(
	[out]		   POBJECT_ATTRIBUTES   p,
	[in]           PUNICODE_STRING      n,
	[in]           ULONG                a,
	[in]           HANDLE               r,
	[in, optional] PSECURITY_DESCRIPTOR s
);
*/
// From ntapi.h

typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation = 0,
	ProcessDebugPort = 7,
	ProcessWow64Information = 26,
	ProcessImageFileName = 27,
	ProcessBreakOnTermination = 29
} PROCESSINFOCLASS, * PPROCESSINFOCLASS;

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


// ====================== Structures for svchost =============================

typedef enum _SC_SERVICE_TAG_QUERY_TYPE {
	ServiceNameFromTagInformation = 1,
	ServiceNameReferencingModuleInformation,
	ServiceNameTagMappingInformation,
} SC_SERVICE_TAG_QUERY_TYPE, * PSC_SERVICE_TAG_QUERY_TYPE;

typedef struct _SC_SERVICE_TAG_QUERY {
	ULONG   processId;
	ULONG   serviceTag;
	ULONG   reserved;
	PVOID   pBuffer;
} SC_SERVICE_TAG_QUERY, * PSC_SERVICE_TAG_QUERY;

// ====================== Structures for svchost =============================

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

/*
typedef struct tagTHREADENTRY32 {
	DWORD dwSize;
	DWORD cntUsage;
	DWORD th32ThreadID;
	DWORD th32OwnerProcessID;
	LONG tpBasePri;
	LONG tpDeltaPri;
	DWORD dwFlags;
	DWORD th32AccessKey;
	DWORD th32CurrentProcessID;
} THREADENTRY32;
*/
//typedef THREADENTRY32* PTHREADENTRY32;
//typedef THREADENTRY32* LPTHREADENTRY32;


// ========================================== For NtQueryInformationThread ========================================== 

// Taken From: https://github.com/reveng007/AQUARMOURY/blob/master/Goblin/Src/EventLog.h

typedef enum _THREADINFOCLASS {
	ThreadBasicInformation, // q: THREAD_BASIC_INFORMATION
	ThreadTimes, // q: KERNEL_USER_TIMES
	ThreadPriority, // s: KPRIORITY
	ThreadBasePriority, // s: LONG
	ThreadAffinityMask, // s: KAFFINITY
	ThreadImpersonationToken, // s: HANDLE
	ThreadDescriptorTableEntry, // q: DESCRIPTOR_TABLE_ENTRY (or WOW64_DESCRIPTOR_TABLE_ENTRY)
	ThreadEnableAlignmentFaultFixup, // s: BOOLEAN
	ThreadEventPair,
	ThreadQuerySetWin32StartAddress, // q: PVOID
	ThreadZeroTlsCell, // 10
	ThreadPerformanceCount, // q: LARGE_INTEGER
	ThreadAmILastThread, // q: ULONG
	ThreadIdealProcessor, // s: ULONG
	ThreadPriorityBoost, // qs: ULONG
	ThreadSetTlsArrayAddress,
	ThreadIsIoPending, // q: ULONG
	ThreadHideFromDebugger, // s: void
	ThreadBreakOnTermination, // qs: ULONG
	ThreadSwitchLegacyState,
	ThreadIsTerminated, // q: ULONG // 20
	ThreadLastSystemCall, // q: THREAD_LAST_SYSCALL_INFORMATION
	ThreadIoPriority, // qs: IO_PRIORITY_HINT
	ThreadCycleTime, // q: THREAD_CYCLE_TIME_INFORMATION
	ThreadPagePriority, // q: ULONG
	ThreadActualBasePriority,
	ThreadTebInformation, // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_SET_CONTEXT)
	ThreadCSwitchMon,
	ThreadCSwitchPmu,
	ThreadWow64Context, // q: WOW64_CONTEXT
	ThreadGroupInformation, // q: GROUP_AFFINITY // 30
	ThreadUmsInformation, // q: THREAD_UMS_INFORMATION
	ThreadCounterProfiling,
	ThreadIdealProcessorEx, // q: PROCESSOR_NUMBER
	ThreadCpuAccountingInformation, // since WIN8
	ThreadSuspendCount, // since WINBLUE
	ThreadHeterogeneousCpuPolicy, // q: KHETERO_CPU_POLICY // since THRESHOLD
	ThreadContainerId, // q: GUID
	ThreadNameInformation, // qs: THREAD_NAME_INFORMATION
	ThreadSelectedCpuSets,
	ThreadSystemThreadInformation, // q: SYSTEM_THREAD_INFORMATION // 40
	ThreadActualGroupAffinity, // since THRESHOLD2
	ThreadDynamicCodePolicyInfo,
	ThreadExplicitCaseSensitivity, // qs: ULONG; s: 0 disables, otherwise enables
	ThreadWorkOnBehalfTicket,
	ThreadSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
	ThreadDbgkWerReportActive,
	ThreadAttachContainer,
	ThreadManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
	ThreadPowerThrottlingState, // THREAD_POWER_THROTTLING_STATE
	ThreadWorkloadClass, // THREAD_WORKLOAD_CLASS // since REDSTONE5 // 50
	MaxThreadInfoClass
} THREADINFOCLASS;

// ==================================================== For NtQueryInformationThread =====================================================
