/************************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015, translated from Microsoft sources/debugger
*
*  TITLE:       NTOS.H
*
*  VERSION:     1.11
*
*  DATE:        10 Mar 2015
*
*  Common header file for the ntos API functions and definitions.
*
*  ONLY program required types and definitions listed.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
************************************************************************************/

#pragma comment(lib, "ntdll.lib")

#pragma warning(disable: 4214) // nonstandard extension used : bit field types other than int

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

/*
** Processes START
*/
typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;
/*
** Processes END
*/

#ifndef _SYSTEM_INFORMATION_CLASS
typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation = 0,
	SystemProcessorInformation = 1,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemPathInformation = 4,
	SystemProcessInformation = 5,
	SystemCallCountInformation = 6,
	SystemDeviceInformation = 7,
	SystemProcessorPerformanceInformation = 8,
	SystemFlagsInformation = 9,
	SystemCallTimeInformation = 10,
	SystemModuleInformation = 11,
	SystemLocksInformation = 12,
	SystemStackTraceInformation = 13,
	SystemPagedPoolInformation = 14,
	SystemNonPagedPoolInformation = 15,
	SystemHandleInformation = 16,
	SystemObjectInformation = 17,
	SystemPageFileInformation = 18,
	SystemVdmInstemulInformation = 19,
	SystemVdmBopInformation = 20,
	SystemFileCacheInformation = 21,
	SystemPoolTagInformation = 22,
	SystemInterruptInformation = 23,
	SystemDpcBehaviorInformation = 24,
	SystemFullMemoryInformation = 25,
	SystemLoadGdiDriverInformation = 26,
	SystemUnloadGdiDriverInformation = 27,
	SystemTimeAdjustmentInformation = 28,
	SystemSummaryMemoryInformation = 29,
	SystemMirrorMemoryInformation = 30,
	SystemPerformanceTraceInformation = 31,
	SystemObsolete0 = 32,
	SystemExceptionInformation = 33,
	SystemCrashDumpStateInformation = 34,
	SystemKernelDebuggerInformation = 35,
	SystemContextSwitchInformation = 36,
	SystemRegistryQuotaInformation = 37,
	SystemExtendServiceTableInformation = 38,
	SystemPrioritySeperation = 39,
	SystemVerifierAddDriverInformation = 40,
	SystemVerifierRemoveDriverInformation = 41,
	SystemProcessorIdleInformation = 42,
	SystemLegacyDriverInformation = 43,
	SystemCurrentTimeZoneInformation = 44,
	SystemLookasideInformation = 45,
	SystemTimeSlipNotification = 46,
	SystemSessionCreate = 47,
	SystemSessionDetach = 48,
	SystemSessionInformation = 49,
	SystemRangeStartInformation = 50,
	SystemVerifierInformation = 51,
	SystemVerifierThunkExtend = 52,
	SystemSessionProcessInformation = 53,
	SystemLoadGdiDriverInSystemSpace = 54,
	SystemNumaProcessorMap = 55,
	SystemPrefetcherInformation = 56,
	SystemExtendedProcessInformation = 57,
	SystemRecommendedSharedDataAlignment = 58,
	SystemComPlusPackage = 59,
	SystemNumaAvailableMemory = 60,
	SystemProcessorPowerInformation = 61,
	SystemEmulationBasicInformation = 62,
	SystemEmulationProcessorInformation = 63,
	SystemExtendedHandleInformation = 64,
	SystemLostDelayedWriteInformation = 65,
	SystemBigPoolInformation = 66,
	SystemSessionPoolTagInformation = 67,
	SystemSessionMappedViewInformation = 68,
	SystemHotpatchInformation = 69,
	SystemObjectSecurityMode = 70,
	SystemWatchdogTimerHandler = 71,
	SystemWatchdogTimerInformation = 72,
	SystemLogicalProcessorInformation = 73,
	SystemWow64SharedInformationObsolete = 74,
	SystemRegisterFirmwareTableInformationHandler = 75,
	SystemFirmwareTableInformation = 76,
	SystemModuleInformationEx = 77,
	SystemVerifierTriageInformation = 78,
	SystemSuperfetchInformation = 79,
	SystemMemoryListInformation = 80,
	SystemFileCacheInformationEx = 81,
	SystemThreadPriorityClientIdInformation = 82,
	SystemProcessorIdleCycleTimeInformation = 83,
	SystemVerifierCancellationInformation = 84,
	SystemProcessorPowerInformationEx = 85,
	SystemRefTraceInformation = 86,
	SystemSpecialPoolInformation = 87,
	SystemProcessIdInformation = 88,
	SystemErrorPortInformation = 89,
	SystemBootEnvironmentInformation = 90,
	SystemHypervisorInformation = 91,
	SystemVerifierInformationEx = 92,
	SystemTimeZoneInformation = 93,
	SystemImageFileExecutionOptionsInformation = 94,
	SystemCoverageInformation = 95,
	SystemPrefetchPatchInformation = 96,
	SystemVerifierFaultsInformation = 97,
	SystemSystemPartitionInformation = 98,
	SystemSystemDiskInformation = 99,
	SystemProcessorPerformanceDistribution = 100,
	SystemNumaProximityNodeInformation = 101,
	SystemDynamicTimeZoneInformation = 102,
	SystemCodeIntegrityInformation = 103,
	SystemProcessorMicrocodeUpdateInformation = 104,
	SystemProcessorBrandString = 105,
	SystemVirtualAddressInformation = 106,
	SystemLogicalProcessorAndGroupInformation = 107,
	SystemProcessorCycleTimeInformation = 108,
	SystemStoreInformation = 109,
	SystemRegistryAppendString = 110,
	SystemAitSamplingValue = 111,
	SystemVhdBootInformation = 112,
	SystemCpuQuotaInformation = 113,
	SystemNativeBasicInformation = 114,
	SystemErrorPortTimeouts = 115,
	SystemLowPriorityIoInformation = 116,
	SystemBootEntropyInformation = 117,
	SystemVerifierCountersInformation = 118,
	SystemPagedPoolInformationEx = 119,
	SystemSystemPtesInformationEx = 120,
	SystemNodeDistanceInformation = 121,
	SystemAcpiAuditInformation = 122,
	SystemBasicPerformanceInformation = 123,
	SystemQueryPerformanceCounterInformation = 124,
	SystemSessionBigPoolInformation = 125,
	SystemBootGraphicsInformation = 126,
	SystemScrubPhysicalMemoryInformation = 127,
	SystemBadPageInformation = 128,
	SystemProcessorProfileControlArea = 129,
	SystemCombinePhysicalMemoryInformation = 130,
	SystemEntropyInterruptTimingInformation = 131,
	SystemConsoleInformation = 132,
	SystemPlatformBinaryInformation = 133,
	SystemPolicyInformation = 134,
	SystemHypervisorProcessorCountInformation = 135,
	SystemDeviceDataInformation = 136,
	SystemDeviceDataEnumerationInformation = 137,
	SystemMemoryTopologyInformation = 138,
	SystemMemoryChannelInformation = 139,
	SystemBootLogoInformation = 140,
	SystemProcessorPerformanceInformationEx = 141,
	SystemSpare0 = 142,
	SystemSecureBootPolicyInformation = 143,
	SystemPageFileInformationEx = 144,
	SystemSecureBootInformation = 145,
	SystemEntropyInterruptTimingRawInformation = 146,
	SystemPortableWorkspaceEfiLauncherInformation = 147,
	SystemFullProcessInformation = 148,
	SystemKernelDebuggerInformationEx = 149,
	SystemBootMetadataInformation = 150,
	SystemSoftRebootInformation = 151,
	SystemElamCertificateInformation = 152,
	SystemOfflineDumpConfigInformation = 153,
	SystemProcessorFeaturesInformation = 154,
	SystemRegistryReconciliationInformation = 155,
	SystemEdidInformation = 156,
	MaxSystemInfoClass = 157
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;
#endif

typedef struct _LDR_DATA_TABLE_ENTRY_COMPATIBLE {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	union
	{
		LIST_ENTRY InInitializationOrderLinks;
		LIST_ENTRY InProgressLinks;
	} DUMMYUNION0;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD ObsoleteLoadCount;
	WORD TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	} DUMMYUNION1;
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	} DUMMYUNION2;
	//fields below removed for compatibility
} LDR_DATA_TABLE_ENTRY_COMPATIBLE, *PLDR_DATA_TABLE_ENTRY_COMPATIBLE, *PLDR_DATA_TABLE_ENTRY;
typedef LDR_DATA_TABLE_ENTRY_COMPATIBLE LDR_DATA_TABLE_ENTRY;
/*
* WDM END
*/

/*
*  NTQSI Modules START
*/

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

/*
*	NTQSI Modules END
*/

//
//  PEB/TEB
//
typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _GDI_HANDLE_ENTRY
{
	union
	{
		PVOID Object;
		PVOID NextFree;
	};
	union
	{
		struct
		{
			USHORT ProcessId;
			USHORT Lock : 1;
			USHORT Count : 15;
		};
		ULONG Value;
	} Owner;
	USHORT Unique;
	UCHAR Type;
	UCHAR Flags;
	PVOID UserPointer;
} GDI_HANDLE_ENTRY, *PGDI_HANDLE_ENTRY;

#define GDI_MAX_HANDLE_COUNT 0x4000

typedef struct _GDI_SHARED_MEMORY
{
	GDI_HANDLE_ENTRY Handles[GDI_MAX_HANDLE_COUNT];
} GDI_SHARED_MEMORY, *PGDI_SHARED_MEMORY;

#define FLS_MAXIMUM_AVAILABLE 128
#define TLS_MINIMUM_AVAILABLE 64
#define TLS_EXPANSION_SLOTS 1024

#define DOS_MAX_COMPONENT_LENGTH 255
#define DOS_MAX_PATH_LENGTH (DOS_MAX_COMPONENT_LENGTH + 5)

typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	HANDLE Handle;
} CURDIR, *PCURDIR;

#define RTL_USER_PROC_CURDIR_CLOSE 0x00000002
#define RTL_USER_PROC_CURDIR_INHERIT 0x00000003

typedef struct _STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PCHAR Buffer;
} STRING;
typedef STRING *PSTRING;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

#define RTL_MAX_DRIVE_LETTERS 32
#define RTL_DRIVE_LETTER_VALID (USHORT)0x0001

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;
	ULONG Length;

	ULONG Flags;
	ULONG DebugFlags;

	HANDLE ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;

	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;

	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;

	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

	ULONG EnvironmentSize;
	ULONG EnvironmentVersion;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

#define GDI_HANDLE_BUFFER_SIZE32  34
#define GDI_HANDLE_BUFFER_SIZE64  60

#if !defined(_M_X64)
#define GDI_HANDLE_BUFFER_SIZE      GDI_HANDLE_BUFFER_SIZE32
#else
#define GDI_HANDLE_BUFFER_SIZE      GDI_HANDLE_BUFFER_SIZE64
#endif

typedef ULONG GDI_HANDLE_BUFFER32[GDI_HANDLE_BUFFER_SIZE32];
typedef ULONG GDI_HANDLE_BUFFER64[GDI_HANDLE_BUFFER_SIZE64];
typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];

typedef struct _PEB
{
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
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
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
			ULONG ReservedBits0 : 27;
		};
		ULONG EnvironmentUpdateCount;
	};
	union
	{
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	};
	ULONG SystemReserved[1];
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID HotpatchInformation;
	PVOID *ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;

	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;

	LARGE_INTEGER CriticalSectionTimeout;
	SIZE_T HeapSegmentReserve;
	SIZE_T HeapSegmentCommit;
	SIZE_T HeapDeCommitTotalFreeThreshold;
	SIZE_T HeapDeCommitFreeBlockThreshold;

	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID *ProcessHeaps;

	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;

	PRTL_CRITICAL_SECTION LoaderLock;

	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	USHORT OSBuildNumber;
	USHORT OSCSDVersion;
	ULONG OSPlatformId;
	ULONG ImageSubsystem;
	ULONG ImageSubsystemMajorVersion;
	ULONG ImageSubsystemMinorVersion;
	ULONG_PTR ImageProcessAffinityMask;
	GDI_HANDLE_BUFFER GdiHandleBuffer;
	PVOID PostProcessInitRoutine;

	PVOID TlsExpansionBitmap;
	ULONG TlsExpansionBitmapBits[32];

	ULONG SessionId;

	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	PVOID pShimData;
	PVOID AppCompatInfo;

	UNICODE_STRING CSDVersion;

	PVOID ActivationContextData;
	PVOID ProcessAssemblyStorageMap;
	PVOID SystemDefaultActivationContextData;
	PVOID SystemAssemblyStorageMap;

	SIZE_T MinimumStackCommit;

	PVOID *FlsCallback;
	LIST_ENTRY FlsListHead;
	PVOID FlsBitmap;
	ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
	ULONG FlsHighIndex;

	PVOID WerRegistrationData;
	PVOID WerShipAssertPtr;
	PVOID pContextData;
	PVOID pImageHeaderHash;
	union
	{
		ULONG TracingFlags;
		struct
		{
			ULONG HeapTracingEnabled : 1;
			ULONG CritSecTracingEnabled : 1;
			ULONG SpareTracingBits : 30;
		};
	};
} PEB, *PPEB;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT
{
	ULONG Flags;
	PSTR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, *PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME
{
	ULONG Flags;
	struct _TEB_ACTIVE_FRAME *Previous;
	PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, *PTEB_ACTIVE_FRAME;

#define GDI_BATCH_BUFFER_SIZE 310

typedef struct _GDI_TEB_BATCH {
	ULONG	Offset;
	UCHAR	Alignment[4];
	ULONG_PTR HDC;
	ULONG	Buffer[GDI_BATCH_BUFFER_SIZE];
} GDI_TEB_BATCH, *PGDI_TEB_BATCH;

typedef struct _TEB
{
	NT_TIB NtTib;

	PVOID EnvironmentPointer;
	CLIENT_ID ClientId;
	PVOID ActiveRpcHandle;
	PVOID ThreadLocalStoragePointer;
	PPEB ProcessEnvironmentBlock;

	ULONG LastErrorValue;
	ULONG CountOfOwnedCriticalSections;
	PVOID CsrClientThread;
	PVOID Win32ThreadInfo;
	ULONG User32Reserved[26];
	ULONG UserReserved[5];
	PVOID WOW32Reserved;
	LCID CurrentLocale;
	ULONG FpSoftwareStatusRegister;
	PVOID SystemReserved1[54];
	NTSTATUS ExceptionCode;
	PVOID ActivationContextStackPointer;
#if defined(_M_X64)
	UCHAR SpareBytes[24];
#else
	UCHAR SpareBytes[36];
#endif
	ULONG TxFsContext;

	GDI_TEB_BATCH GdiTebBatch;
	CLIENT_ID RealClientId;
	HANDLE GdiCachedProcessHandle;
	ULONG GdiClientPID;
	ULONG GdiClientTID;
	PVOID GdiThreadLocalInfo;
	ULONG_PTR Win32ClientInfo[62];
	PVOID glDispatchTable[233];
	ULONG_PTR glReserved1[29];
	PVOID glReserved2;
	PVOID glSectionInfo;
	PVOID glSection;
	PVOID glTable;
	PVOID glCurrentRC;
	PVOID glContext;

	NTSTATUS LastStatusValue;
	UNICODE_STRING StaticUnicodeString;
	WCHAR StaticUnicodeBuffer[261];

	PVOID DeallocationStack;
	PVOID TlsSlots[64];
	LIST_ENTRY TlsLinks;

	PVOID Vdm;
	PVOID ReservedForNtRpc;
	PVOID DbgSsReserved[2];

	ULONG HardErrorMode;
#if defined(_M_X64)
	PVOID Instrumentation[11];
#else
	PVOID Instrumentation[9];
#endif
	GUID ActivityId;

	PVOID SubProcessTag;
	PVOID EtwLocalData;
	PVOID EtwTraceData;
	PVOID WinSockData;
	ULONG GdiBatchCount;

	union
	{
		PROCESSOR_NUMBER CurrentIdealProcessor;
		ULONG IdealProcessorValue;
		struct
		{
			UCHAR ReservedPad0;
			UCHAR ReservedPad1;
			UCHAR ReservedPad2;
			UCHAR IdealProcessor;
		};
	};

	ULONG GuaranteedStackBytes;
	PVOID ReservedForPerf;
	PVOID ReservedForOle;
	ULONG WaitingOnLoaderLock;
	PVOID SavedPriorityState;
	ULONG_PTR SoftPatchPtr1;
	PVOID ThreadPoolData;
	PVOID *TlsExpansionSlots;
#if defined(_M_X64)
	PVOID DeallocationBStore;
	PVOID BStoreLimit;
#endif
	ULONG MuiGeneration;
	ULONG IsImpersonating;
	PVOID NlsCache;
	PVOID pShimData;
	ULONG HeapVirtualAffinity;
	HANDLE CurrentTransactionHandle;
	PTEB_ACTIVE_FRAME ActiveFrame;
	PVOID FlsData;

	PVOID PreferredLanguages;
	PVOID UserPrefLanguages;
	PVOID MergedPrefLanguages;
	ULONG MuiImpersonation;

	union
	{
		USHORT CrossTebFlags;
		USHORT SpareCrossTebBits : 16;
	};
	union
	{
		USHORT SameTebFlags;
		struct
		{
			USHORT SafeThunkCall : 1;
			USHORT InDebugPrint : 1;
			USHORT HasFiberData : 1;
			USHORT SkipThreadAttach : 1;
			USHORT WerInShipAssertCode : 1;
			USHORT RanProcessInit : 1;
			USHORT ClonedThread : 1;
			USHORT SuppressDebugMsg : 1;
			USHORT DisableUserStackWalk : 1;
			USHORT RtlExceptionAttached : 1;
			USHORT InitialThread : 1;
			USHORT SpareSameTebBits : 1;
		};
	};

	PVOID TxnScopeEnterCallback;
	PVOID TxnScopeExitCallback;
	PVOID TxnScopeContext;
	ULONG LockCount;
	ULONG SpareUlong0;
	PVOID ResourceRetValue;
} TEB, *PTEB;

__inline struct _PEB * NtCurrentPeb() { return NtCurrentTeb()->ProcessEnvironmentBlock; }

/*
** PEB/TEB END
*/


/*
** Runtime Library API START
*/

NTSTATUS RtlGetVersion(
	_Inout_	PRTL_OSVERSIONINFOW lpVersionInformation
	);

/*
** Runtime Library API END
*/

/*
** Native API START
*/

NTSTATUS WINAPI NtQuerySystemInformation(
	_In_       SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_    PVOID SystemInformation,
	_In_       ULONG SystemInformationLength,
	_Out_opt_  PULONG ReturnLength
	);

/*
** Native API END
*/
