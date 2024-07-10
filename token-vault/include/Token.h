#ifndef TOKEN_H
#define TOKEN_H

#include <Defs.h>
#include <Ntlm.h>

#define TOKEN_VAULT_KEY "TOKEN_VAULT"

typedef struct _TOKEN_ENTRY {
	USHORT Id;
	HANDLE PrimaryToken;
	HANDLE ImpersonationToken;
	BOOL   Elevated;
	BOOL   PidStolen;

	struct _TOKEN_ENTRY *Next;

	PWSTR Username;
	PWSTR Domain;

	// if the token was created using token make
	// in order to be able to call CreateProcessWithLogonW if needed
	PWSTR Password;
} TOKEN_ENTRY, *PTOKEN_ENTRY;

typedef struct _TOKEN_VAULT {
	USHORT       LastId;
	USHORT       NbEntry;
	PTOKEN_ENTRY Current;
	PTOKEN_ENTRY First;
} TOKEN_VAULT, *PTOKEN_VAULT;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE {
	ULONG64        Version;
	UNICODE_STRING Name;
} TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE, *PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE {
	PVOID pValue;
	ULONG ValueLength;
} TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE, *PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_V1 {
	UNICODE_STRING Name;
	USHORT         ValueType;
	USHORT         Reserved;
	ULONG          Flags;
	ULONG          ValueCount;

	union {
		PLONG64                                      pInt64;
		PULONG64                                     pUint64;
		PUNICODE_STRING                              pString;
		PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE         pFqbn;
		PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE pOctetString;
	} Values;
} TOKEN_SECURITY_ATTRIBUTE_V1, *PTOKEN_SECURITY_ATTRIBUTE_V1;

typedef struct _TOKEN_SECURITY_ATTRIBUTES_INFORMATION {
	USHORT Version;
	USHORT Reserved;
	ULONG  AttributeCount;

	union {
		PTOKEN_SECURITY_ATTRIBUTE_V1 pAttributeV1;
	} Attribute;
} TOKEN_SECURITY_ATTRIBUTES_INFORMATION, *PTOKEN_SECURITY_ATTRIBUTES_INFORMATION;

typedef struct _TOKEN_GROUPS_MULTI {
	DWORD               GroupCount;
	PSID_AND_ATTRIBUTES Groups;
} TOKEN_GROUPS_MULTI, *PTOKEN_GROUPS_MULTI;

typedef struct _TOKEN_PRIVILEGES_MULTI {
	DWORD                PrivilegeCount;
	PLUID_AND_ATTRIBUTES Privileges;
} TOKEN_PRIVILEGES_MULTI, *PTOKEN_PRIVILEGES_MULTI;

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};

	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef LONG KPRIORITY, *PKPRIORITY;

typedef enum _KTHREAD_STATE {
	Initialized,
	Ready,
	Running,
	Standby,
	Terminated,
	Waiting,
	Transition,
	DeferredReady,
	GateWaitObsolete,
	WaitingForProcessInSwap,
	MaximumThreadState
} KTHREAD_STATE, *PKTHREAD_STATE;

typedef enum _KWAIT_REASON {
	Executive,
	FreePage,
	PageIn,
	PoolAllocation,
	DelayExecution,
	Suspended,
	UserRequest,
	WrExecutive,
	WrFreePage,
	WrPageIn,
	WrPoolAllocation,
	WrDelayExecution,
	WrSuspended,
	WrUserRequest,
	WrEventPair,
	WrQueue,
	WrLpcReceive,
	WrLpcReply,
	WrVirtualMemory,
	WrPageOut,
	WrRendezvous,
	WrKeyedEvent,
	WrTerminated,
	WrProcessInSwap,
	WrCpuRateControl,
	WrCalloutStack,
	WrKernel,
	WrResource,
	WrPushLock,
	WrMutex,
	WrQuantumEnd,
	WrDispatchInt,
	WrPreempted,
	WrYieldExecution,
	WrFastMutex,
	WrGuardedMutex,
	WrRundown,
	WrAlertByThreadId,
	WrDeferredPreempt,
	WrPhysicalFault,
	WrIoRing,
	WrMdlCache,
	MaximumWaitReason
} KWAIT_REASON, *PKWAIT_REASON;

typedef struct _SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG         WaitTime;
	ULONG_PTR     StartAddress;
	CLIENT_ID     ClientId;
	KPRIORITY     Priority;
	KPRIORITY     BasePriority;
	ULONG         ContextSwitches;
	KTHREAD_STATE ThreadState;
	KWAIT_REASON  WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;


typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG                     NextEntryOffset;
	ULONG                     NumberOfThreads;
	LARGE_INTEGER             WorkingSetPrivateSize;        // since VISTA
	ULONG                     HardFaultCount;               // since WIN7
	ULONG                     NumberOfThreadsHighWatermark; // since WIN7
	ULONGLONG                 CycleTime;                    // since WIN7
	LARGE_INTEGER             CreateTime;
	LARGE_INTEGER             UserTime;
	LARGE_INTEGER             KernelTime;
	UNICODE_STRING            ImageName;
	KPRIORITY                 BasePriority;
	HANDLE                    UniqueProcessId;
	HANDLE                    InheritedFromUniqueProcessId;
	ULONG                     HandleCount;
	ULONG                     SessionId;
	ULONG_PTR                 UniqueProcessKey; // since VISTA (requires SystemExtendedProcessInformation)
	SIZE_T                    PeakVirtualSize;
	SIZE_T                    VirtualSize;
	ULONG                     PageFaultCount;
	SIZE_T                    PeakWorkingSetSize;
	SIZE_T                    WorkingSetSize;
	SIZE_T                    QuotaPeakPagedPoolUsage;
	SIZE_T                    QuotaPagedPoolUsage;
	SIZE_T                    QuotaPeakNonPagedPoolUsage;
	SIZE_T                    QuotaNonPagedPoolUsage;
	SIZE_T                    PagefileUsage;
	SIZE_T                    PeakPagefileUsage;
	SIZE_T                    PrivatePageCount;
	LARGE_INTEGER             ReadOperationCount;
	LARGE_INTEGER             WriteOperationCount;
	LARGE_INTEGER             OtherOperationCount;
	LARGE_INTEGER             ReadTransferCount;
	LARGE_INTEGER             WriteTransferCount;
	LARGE_INTEGER             OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[ 1 ]; // SystemProcessInformation
	// SYSTEM_EXTENDED_THREAD_INFORMATION Threads[1]; // SystemExtendedProcessinformation
	// SYSTEM_EXTENDED_THREAD_INFORMATION + SYSTEM_PROCESS_INFORMATION_EXTENSION // SystemFullProcessInformation
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;


typedef VOID ( NTAPI *PIO_APC_ROUTINE )(
	_In_ PVOID            ApcContext,
	_In_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_ ULONG            Reserved
);

typedef enum _THREADINFOCLASS {
	ThreadBasicInformation,          // q: THREAD_BASIC_INFORMATION
	ThreadTimes,                     // q: KERNEL_USER_TIMES
	ThreadPriority,                  // s: KPRIORITY (requires SeIncreaseBasePriorityPrivilege)
	ThreadBasePriority,              // s: KPRIORITY
	ThreadAffinityMask,              // s: KAFFINITY
	ThreadImpersonationToken,        // s: HANDLE
	ThreadDescriptorTableEntry,      // q: DESCRIPTOR_TABLE_ENTRY (or WOW64_DESCRIPTOR_TABLE_ENTRY)
	ThreadEnableAlignmentFaultFixup, // s: BOOLEAN
	ThreadEventPair,
	ThreadQuerySetWin32StartAddress, // q: ULONG_PTR
	ThreadZeroTlsCell,               // s: ULONG // TlsIndex // 10
	ThreadPerformanceCount,          // q: LARGE_INTEGER
	ThreadAmILastThread,             // q: ULONG
	ThreadIdealProcessor,            // s: ULONG
	ThreadPriorityBoost,             // qs: ULONG
	ThreadSetTlsArrayAddress,        // s: ULONG_PTR // Obsolete
	ThreadIsIoPending,               // q: ULONG
	ThreadHideFromDebugger,          // q: BOOLEAN; s: void
	ThreadBreakOnTermination,        // qs: ULONG
	ThreadSwitchLegacyState,         // s: void // NtCurrentThread // NPX/FPU
	ThreadIsTerminated,              // q: ULONG // 20
	ThreadLastSystemCall,            // q: THREAD_LAST_SYSCALL_INFORMATION
	ThreadIoPriority,                // qs: IO_PRIORITY_HINT (requires SeIncreaseBasePriorityPrivilege)
	ThreadCycleTime,                 // q: THREAD_CYCLE_TIME_INFORMATION
	ThreadPagePriority,              // qs: PAGE_PRIORITY_INFORMATION
	ThreadActualBasePriority,        // s: LONG (requires SeIncreaseBasePriorityPrivilege)
	ThreadTebInformation,            // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_SET_CONTEXT)
	ThreadCSwitchMon,                // Obsolete
	ThreadCSwitchPmu,
	ThreadWow64Context,             // qs: WOW64_CONTEXT, ARM_NT_CONTEXT since 20H1
	ThreadGroupInformation,         // qs: GROUP_AFFINITY // 30
	ThreadUmsInformation,           // q: THREAD_UMS_INFORMATION // Obsolete
	ThreadCounterProfiling,         // q: BOOLEAN; s: THREAD_PROFILING_INFORMATION?
	ThreadIdealProcessorEx,         // qs: PROCESSOR_NUMBER; s: previous PROCESSOR_NUMBER on return
	ThreadCpuAccountingInformation, // q: BOOLEAN; s: HANDLE (NtOpenSession) // NtCurrentThread // since WIN8
	ThreadSuspendCount,             // q: ULONG // since WINBLUE
	ThreadHeterogeneousCpuPolicy,   // q: KHETERO_CPU_POLICY // since THRESHOLD
	ThreadContainerId,              // q: GUID
	ThreadNameInformation,          // qs: THREAD_NAME_INFORMATION
	ThreadSelectedCpuSets,
	ThreadSystemThreadInformation,        // q: SYSTEM_THREAD_INFORMATION // 40
	ThreadActualGroupAffinity,            // q: GROUP_AFFINITY // since THRESHOLD2
	ThreadDynamicCodePolicyInfo,          // q: ULONG; s: ULONG (NtCurrentThread)
	ThreadExplicitCaseSensitivity,        // qs: ULONG; s: 0 disables, otherwise enables
	ThreadWorkOnBehalfTicket,             // RTL_WORK_ON_BEHALF_TICKET_EX
	ThreadSubsystemInformation,           // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
	ThreadDbgkWerReportActive,            // s: ULONG; s: 0 disables, otherwise enables
	ThreadAttachContainer,                // s: HANDLE (job object) // NtCurrentThread
	ThreadManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
	ThreadPowerThrottlingState,           // POWER_THROTTLING_THREAD_STATE // since REDSTONE3 (set), WIN11 22H2 (query)
	ThreadWorkloadClass,                  // THREAD_WORKLOAD_CLASS // since REDSTONE5 // 50
	ThreadCreateStateChange,              // since WIN11
	ThreadApplyStateChange,
	ThreadStrongerBadHandleChecks, // since 22H1
	ThreadEffectiveIoPriority,     // q: IO_PRIORITY_HINT
	ThreadEffectivePagePriority,   // q: ULONG
	ThreadUpdateLockOwnership,     // since 24H2
	ThreadSchedulerSharedDataSlot, // SCHEDULER_SHARED_DATA_SLOT_INFORMATION
	ThreadTebInformationAtomic,    // THREAD_TEB_INFORMATION
	ThreadIndexInformation,        // THREAD_INDEX_INFORMATION
	MaxThreadInfoClass
} THREADINFOCLASS;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,                // q: SYSTEM_BASIC_INFORMATION
	SystemProcessorInformation,            // q: SYSTEM_PROCESSOR_INFORMATION
	SystemPerformanceInformation,          // q: SYSTEM_PERFORMANCE_INFORMATION
	SystemTimeOfDayInformation,            // q: SYSTEM_TIMEOFDAY_INFORMATION
	SystemPathInformation,                 // not implemented
	SystemProcessInformation,              // q: SYSTEM_PROCESS_INFORMATION
	SystemCallCountInformation,            // q: SYSTEM_CALL_COUNT_INFORMATION
	SystemDeviceInformation,               // q: SYSTEM_DEVICE_INFORMATION
	SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION (EX in: USHORT ProcessorGroup)
	SystemFlagsInformation,                // q: SYSTEM_FLAGS_INFORMATION
	SystemCallTimeInformation,             // not implemented // SYSTEM_CALL_TIME_INFORMATION // 10
	SystemModuleInformation,               // q: RTL_PROCESS_MODULES
	SystemLocksInformation,                // q: RTL_PROCESS_LOCKS
	SystemStackTraceInformation,           // q: RTL_PROCESS_BACKTRACES
	SystemPagedPoolInformation,            // not implemented
	SystemNonPagedPoolInformation,         // not implemented
	SystemHandleInformation,               // q: SYSTEM_HANDLE_INFORMATION
	SystemObjectInformation,               // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
	SystemPageFileInformation,             // q: SYSTEM_PAGEFILE_INFORMATION
	SystemVdmInstemulInformation,          // q: SYSTEM_VDM_INSTEMUL_INFO
	SystemVdmBopInformation,               // not implemented // 20
	SystemFileCacheInformation,
	// q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
	SystemPoolTagInformation,   // q: SYSTEM_POOLTAG_INFORMATION
	SystemInterruptInformation, // q: SYSTEM_INTERRUPT_INFORMATION (EX in: USHORT ProcessorGroup)
	SystemDpcBehaviorInformation,
	// q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
	SystemFullMemoryInformation,      // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
	SystemLoadGdiDriverInformation,   // s (kernel-mode only)
	SystemUnloadGdiDriverInformation, // s (kernel-mode only)
	SystemTimeAdjustmentInformation,
	// q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
	SystemSummaryMemoryInformation, // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
	SystemMirrorMemoryInformation,
	// s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
	SystemPerformanceTraceInformation, // q; s: (type depends on EVENT_TRACE_INFORMATION_CLASS)
	SystemObsolete0, // not implemented
	SystemExceptionInformation, // q: SYSTEM_EXCEPTION_INFORMATION
	SystemCrashDumpStateInformation, // s: SYSTEM_CRASH_DUMP_STATE_INFORMATION (requires SeDebugPrivilege)
	SystemKernelDebuggerInformation, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
	SystemContextSwitchInformation, // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
	SystemRegistryQuotaInformation, // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
	SystemExtendServiceTableInformation, // s (requires SeLoadDriverPrivilege) // loads win32k only
	SystemPrioritySeperation, // s (requires SeTcbPrivilege)
	SystemVerifierAddDriverInformation, // s (requires SeDebugPrivilege) // 40
	SystemVerifierRemoveDriverInformation, // s (requires SeDebugPrivilege)
	SystemProcessorIdleInformation, // q: SYSTEM_PROCESSOR_IDLE_INFORMATION (EX in: USHORT ProcessorGroup)
	SystemLegacyDriverInformation, // q: SYSTEM_LEGACY_DRIVER_INFORMATION
	SystemCurrentTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION
	SystemLookasideInformation, // q: SYSTEM_LOOKASIDE_INFORMATION
	SystemTimeSlipNotification, // s: HANDLE (NtCreateEvent) (requires SeSystemtimePrivilege)
	SystemSessionCreate, // not implemented
	SystemSessionDetach, // not implemented
	SystemSessionInformation, // not implemented (SYSTEM_SESSION_INFORMATION)
	SystemRangeStartInformation, // q: SYSTEM_RANGE_START_INFORMATION // 50
	SystemVerifierInformation, // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
	SystemVerifierThunkExtend, // s (kernel-mode only)
	SystemSessionProcessInformation, // q: SYSTEM_SESSION_PROCESS_INFORMATION
	SystemLoadGdiDriverInSystemSpace,
	// s: SYSTEM_GDI_DRIVER_INFORMATION (kernel-mode only) (same as SystemLoadGdiDriverInformation)
	SystemNumaProcessorMap, // q: SYSTEM_NUMA_INFORMATION
	SystemPrefetcherInformation, // q; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
	SystemExtendedProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
	SystemRecommendedSharedDataAlignment, // q: ULONG // KeGetRecommendedSharedDataAlignment
	SystemComPlusPackage, // q; s: ULONG
	SystemNumaAvailableMemory, // q: SYSTEM_NUMA_INFORMATION // 60
	SystemProcessorPowerInformation, // q: SYSTEM_PROCESSOR_POWER_INFORMATION (EX in: USHORT ProcessorGroup)
	SystemEmulationBasicInformation, // q: SYSTEM_BASIC_INFORMATION
	SystemEmulationProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
	SystemExtendedHandleInformation, // q: SYSTEM_HANDLE_INFORMATION_EX
	SystemLostDelayedWriteInformation, // q: ULONG
	SystemBigPoolInformation, // q: SYSTEM_BIGPOOL_INFORMATION
	SystemSessionPoolTagInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION
	SystemSessionMappedViewInformation, // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
	SystemHotpatchInformation, // q; s: SYSTEM_HOTPATCH_CODE_INFORMATION
	SystemObjectSecurityMode, // q: ULONG // 70
	SystemWatchdogTimerHandler, // s: SYSTEM_WATCHDOG_HANDLER_INFORMATION // (kernel-mode only)
	SystemWatchdogTimerInformation, // q: SYSTEM_WATCHDOG_TIMER_INFORMATION // (kernel-mode only)
	SystemLogicalProcessorInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION (EX in: USHORT ProcessorGroup)
	SystemWow64SharedInformationObsolete, // not implemented
	SystemRegisterFirmwareTableInformationHandler, // s: SYSTEM_FIRMWARE_TABLE_HANDLER // (kernel-mode only)
	SystemFirmwareTableInformation, // SYSTEM_FIRMWARE_TABLE_INFORMATION
	SystemModuleInformationEx, // q: RTL_PROCESS_MODULE_INFORMATION_EX
	SystemVerifierTriageInformation, // not implemented
	SystemSuperfetchInformation, // q; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
	SystemMemoryListInformation,
	// q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
	SystemFileCacheInformationEx,
	// q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
	SystemThreadPriorityClientIdInformation,
	// s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege)
	SystemProcessorIdleCycleTimeInformation,
	// q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup)
	SystemVerifierCancellationInformation,
	// SYSTEM_VERIFIER_CANCELLATION_INFORMATION // name:wow64:whNT32QuerySystemVerifierCancellationInformation
	SystemProcessorPowerInformationEx, // not implemented
	SystemRefTraceInformation,         // q; s: SYSTEM_REF_TRACE_INFORMATION // ObQueryRefTraceInformation
	SystemSpecialPoolInformation,
	// q; s: SYSTEM_SPECIAL_POOL_INFORMATION (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
	SystemProcessIdInformation,       // q: SYSTEM_PROCESS_ID_INFORMATION
	SystemErrorPortInformation,       // s (requires SeTcbPrivilege)
	SystemBootEnvironmentInformation, // q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
	SystemHypervisorInformation,      // q: SYSTEM_HYPERVISOR_QUERY_INFORMATION
	SystemVerifierInformationEx,      // q; s: SYSTEM_VERIFIER_INFORMATION_EX
	SystemTimeZoneInformation,        // q; s: RTL_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
	SystemImageFileExecutionOptionsInformation,
	// s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
	SystemCoverageInformation,
	// q: COVERAGE_MODULES s: COVERAGE_MODULE_REQUEST // ExpCovQueryInformation (requires SeDebugPrivilege)
	SystemPrefetchPatchInformation,   // SYSTEM_PREFETCH_PATCH_INFORMATION
	SystemVerifierFaultsInformation,  // s: SYSTEM_VERIFIER_FAULTS_INFORMATION (requires SeDebugPrivilege)
	SystemSystemPartitionInformation, // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
	SystemSystemDiskInformation,      // q: SYSTEM_SYSTEM_DISK_INFORMATION
	SystemProcessorPerformanceDistribution,
	// q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION (EX in: USHORT ProcessorGroup) // 100
	SystemNumaProximityNodeInformation, // q; s: SYSTEM_NUMA_PROXIMITY_MAP
	SystemDynamicTimeZoneInformation, // q; s: RTL_DYNAMIC_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
	SystemCodeIntegrityInformation, // q: SYSTEM_CODEINTEGRITY_INFORMATION // SeCodeIntegrityQueryInformation
	SystemProcessorMicrocodeUpdateInformation, // s: SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION
	SystemProcessorBrandString, // q: CHAR[] // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
	SystemVirtualAddressInformation,
	// q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
	SystemLogicalProcessorAndGroupInformation,
	// q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX (EX in: LOGICAL_PROCESSOR_RELATIONSHIP RelationshipType) // since WIN7 // KeQueryLogicalProcessorRelationship
	SystemProcessorCycleTimeInformation, // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup)
	SystemStoreInformation,
	// q; s: SYSTEM_STORE_INFORMATION (requires SeProfileSingleProcessPrivilege) // SmQueryStoreInformation
	SystemRegistryAppendString,        // s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
	SystemAitSamplingValue,            // s: ULONG (requires SeProfileSingleProcessPrivilege)
	SystemVhdBootInformation,          // q: SYSTEM_VHD_BOOT_INFORMATION
	SystemCpuQuotaInformation,         // q; s: PS_CPU_QUOTA_QUERY_INFORMATION
	SystemNativeBasicInformation,      // q: SYSTEM_BASIC_INFORMATION
	SystemErrorPortTimeouts,           // SYSTEM_ERROR_PORT_TIMEOUTS
	SystemLowPriorityIoInformation,    // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
	SystemTpmBootEntropyInformation,   // q: TPM_BOOT_ENTROPY_NT_RESULT // ExQueryTpmBootEntropyInformation
	SystemVerifierCountersInformation, // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
	SystemPagedPoolInformationEx,
	// q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
	SystemSystemPtesInformationEx,
	// q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
	SystemNodeDistanceInformation, // q: USHORT[4*NumaNodes] // (EX in: USHORT NodeNumber)
	SystemAcpiAuditInformation,
	// q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
	SystemBasicPerformanceInformation,
	// q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
	SystemQueryPerformanceCounterInformation, // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
	SystemSessionBigPoolInformation,          // q: SYSTEM_SESSION_POOLTAG_INFORMATION // since WIN8
	SystemBootGraphicsInformation,            // q; s: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only)
	SystemScrubPhysicalMemoryInformation,     // q; s: MEMORY_SCRUB_INFORMATION
	SystemBadPageInformation,                 // SYSTEM_BAD_PAGE_INFORMATION
	SystemProcessorProfileControlArea,        // q; s: SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
	SystemCombinePhysicalMemoryInformation,
	// s: MEMORY_COMBINE_INFORMATION, MEMORY_COMBINE_INFORMATION_EX, MEMORY_COMBINE_INFORMATION_EX2 // 130
	SystemEntropyInterruptTimingInformation,   // q; s: SYSTEM_ENTROPY_TIMING_INFORMATION
	SystemConsoleInformation,                  // q; s: SYSTEM_CONSOLE_INFORMATION
	SystemPlatformBinaryInformation,           // q: SYSTEM_PLATFORM_BINARY_INFORMATION (requires SeTcbPrivilege)
	SystemPolicyInformation,                   // q: SYSTEM_POLICY_INFORMATION (Warbird/Encrypt/Decrypt/Execute)
	SystemHypervisorProcessorCountInformation, // q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
	SystemDeviceDataInformation,               // q: SYSTEM_DEVICE_DATA_INFORMATION
	SystemDeviceDataEnumerationInformation,    // q: SYSTEM_DEVICE_DATA_INFORMATION
	SystemMemoryTopologyInformation,           // q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION
	SystemMemoryChannelInformation,            // q: SYSTEM_MEMORY_CHANNEL_INFORMATION
	SystemBootLogoInformation,                 // q: SYSTEM_BOOT_LOGO_INFORMATION // 140
	SystemProcessorPerformanceInformationEx,
	// q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // (EX in: USHORT ProcessorGroup) // since WINBLUE
	SystemCriticalProcessErrorLogInformation,
	SystemSecureBootPolicyInformation, // q: SYSTEM_SECUREBOOT_POLICY_INFORMATION
	SystemPageFileInformationEx,       // q: SYSTEM_PAGEFILE_INFORMATION_EX
	SystemSecureBootInformation,       // q: SYSTEM_SECUREBOOT_INFORMATION
	SystemEntropyInterruptTimingRawInformation,
	SystemPortableWorkspaceEfiLauncherInformation, // q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
	SystemFullProcessInformation,
	// q: SYSTEM_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
	SystemKernelDebuggerInformationEx,       // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
	SystemBootMetadataInformation,           // 150
	SystemSoftRebootInformation,             // q: ULONG
	SystemElamCertificateInformation,        // s: SYSTEM_ELAM_CERTIFICATE_INFORMATION
	SystemOfflineDumpConfigInformation,      // q: OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2
	SystemProcessorFeaturesInformation,      // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
	SystemRegistryReconciliationInformation, // s: NULL (requires admin) (flushes registry hives)
	SystemEdidInformation,                   // q: SYSTEM_EDID_INFORMATION
	SystemManufacturingInformation,          // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
	SystemEnergyEstimationConfigInformation, // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
	SystemHypervisorDetailInformation,       // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
	SystemProcessorCycleStatsInformation,
	// q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION (EX in: USHORT ProcessorGroup) // 160
	SystemVmGenerationCountInformation,
	SystemTrustedPlatformModuleInformation, // q: SYSTEM_TPM_INFORMATION
	SystemKernelDebuggerFlags,              // SYSTEM_KERNEL_DEBUGGER_FLAGS
	SystemCodeIntegrityPolicyInformation,   // q; s: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
	SystemIsolatedUserModeInformation,      // q: SYSTEM_ISOLATED_USER_MODE_INFORMATION
	SystemHardwareSecurityTestInterfaceResultsInformation,
	SystemSingleModuleInformation, // q: SYSTEM_SINGLE_MODULE_INFORMATION
	SystemAllowedCpuSetsInformation, // s: SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION
	SystemVsmProtectionInformation, // q: SYSTEM_VSM_PROTECTION_INFORMATION (previously SystemDmaProtectionInformation)
	SystemInterruptCpuSetsInformation, // q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION // 170
	SystemSecureBootPolicyFullInformation, // q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
	SystemCodeIntegrityPolicyFullInformation,
	SystemAffinitizedInterruptProcessorInformation, // (requires SeIncreaseBasePriorityPrivilege)
	SystemRootSiloInformation,                      // q: SYSTEM_ROOT_SILO_INFORMATION
	SystemCpuSetInformation,                        // q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
	SystemCpuSetTagInformation,                     // q: SYSTEM_CPU_SET_TAG_INFORMATION
	SystemWin32WerStartCallout,
	SystemSecureKernelProfileInformation, // q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
	SystemCodeIntegrityPlatformManifestInformation,
	// q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION // since REDSTONE
	SystemInterruptSteeringInformation,
	// q: in: SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT, out: SYSTEM_INTERRUPT_STEERING_INFORMATION_OUTPUT // NtQuerySystemInformationEx // 180
	SystemSupportedProcessorArchitectures,
	// p: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx
	SystemMemoryUsageInformation,              // q: SYSTEM_MEMORY_USAGE_INFORMATION
	SystemCodeIntegrityCertificateInformation, // q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
	SystemPhysicalMemoryInformation,           // q: SYSTEM_PHYSICAL_MEMORY_INFORMATION // since REDSTONE2
	SystemControlFlowTransition,               // (Warbird/Encrypt/Decrypt/Execute)
	SystemKernelDebuggingAllowed,              // s: ULONG
	SystemActivityModerationExeState,          // SYSTEM_ACTIVITY_MODERATION_EXE_STATE
	SystemActivityModerationUserSettings,      // SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
	SystemCodeIntegrityPoliciesFullInformation,
	SystemCodeIntegrityUnlockInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION // 190
	SystemIntegrityQuotaInformation,
	SystemFlushInformation,             // q: SYSTEM_FLUSH_INFORMATION
	SystemProcessorIdleMaskInformation, // q: ULONG_PTR[ActiveGroupCount] // since REDSTONE3
	SystemSecureDumpEncryptionInformation,
	SystemWriteConstraintInformation,      // SYSTEM_WRITE_CONSTRAINT_INFORMATION
	SystemKernelVaShadowInformation,       // SYSTEM_KERNEL_VA_SHADOW_INFORMATION
	SystemHypervisorSharedPageInformation, // SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION // since REDSTONE4
	SystemFirmwareBootPerformanceInformation,
	SystemCodeIntegrityVerificationInformation, // SYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION
	SystemFirmwarePartitionInformation,         // SYSTEM_FIRMWARE_PARTITION_INFORMATION // 200
	SystemSpeculationControlInformation,
	// SYSTEM_SPECULATION_CONTROL_INFORMATION // (CVE-2017-5715) REDSTONE3 and above.
	SystemDmaGuardPolicyInformation,          // SYSTEM_DMA_GUARD_POLICY_INFORMATION
	SystemEnclaveLaunchControlInformation,    // SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION
	SystemWorkloadAllowedCpuSetsInformation,  // SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION // since REDSTONE5
	SystemCodeIntegrityUnlockModeInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION
	SystemLeapSecondInformation,              // SYSTEM_LEAP_SECOND_INFORMATION
	SystemFlags2Information,                  // q: SYSTEM_FLAGS_INFORMATION
	SystemSecurityModelInformation,           // SYSTEM_SECURITY_MODEL_INFORMATION // since 19H1
	SystemCodeIntegritySyntheticCacheInformation,
	SystemFeatureConfigurationInformation,
	// q: in: SYSTEM_FEATURE_CONFIGURATION_QUERY, out: SYSTEM_FEATURE_CONFIGURATION_INFORMATION; s: SYSTEM_FEATURE_CONFIGURATION_UPDATE // NtQuerySystemInformationEx // since 20H1 // 210
	SystemFeatureConfigurationSectionInformation,
	// q: in: SYSTEM_FEATURE_CONFIGURATION_SECTIONS_REQUEST, out: SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION // NtQuerySystemInformationEx
	SystemFeatureUsageSubscriptionInformation,
	// q: SYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS; s: SYSTEM_FEATURE_USAGE_SUBSCRIPTION_UPDATE
	SystemSecureSpeculationControlInformation, // SECURE_SPECULATION_CONTROL_INFORMATION
	SystemSpacesBootInformation,               // since 20H2
	SystemFwRamdiskInformation,                // SYSTEM_FIRMWARE_RAMDISK_INFORMATION
	SystemWheaIpmiHardwareInformation,
	SystemDifSetRuleClassInformation, // SYSTEM_DIF_VOLATILE_INFORMATION
	SystemDifClearRuleClassInformation,
	SystemDifApplyPluginVerificationOnDriver,  // SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION
	SystemDifRemovePluginVerificationOnDriver, // SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION // 220
	SystemShadowStackInformation,              // SYSTEM_SHADOW_STACK_INFORMATION
	SystemBuildVersionInformation,
	// q: in: ULONG (LayerNumber), out: SYSTEM_BUILD_VERSION_INFORMATION // NtQuerySystemInformationEx // 222
	SystemPoolLimitInformation, // SYSTEM_POOL_LIMIT_INFORMATION (requires SeIncreaseQuotaPrivilege)
	SystemCodeIntegrityAddDynamicStore,
	SystemCodeIntegrityClearDynamicStores,
	SystemDifPoolTrackingInformation,
	SystemPoolZeroingInformation,  // q: SYSTEM_POOL_ZEROING_INFORMATION
	SystemDpcWatchdogInformation,  // q; s: SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION
	SystemDpcWatchdogInformation2, // q; s: SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION_V2
	SystemSupportedProcessorArchitectures2,
	// q: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx // 230
	SystemSingleProcessorRelationshipInformation,
	// q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // (EX in: PROCESSOR_NUMBER Processor)
	SystemXfgCheckFailureInformation,     // q: SYSTEM_XFG_FAILURE_INFORMATION
	SystemIommuStateInformation,          // SYSTEM_IOMMU_STATE_INFORMATION // since 22H1
	SystemHypervisorMinrootInformation,   // SYSTEM_HYPERVISOR_MINROOT_INFORMATION
	SystemHypervisorBootPagesInformation, // SYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION
	SystemPointerAuthInformation,         // SYSTEM_POINTER_AUTH_INFORMATION
	SystemSecureKernelDebuggerInformation,
	SystemOriginalImageFeatureInformation,
	// q: in: SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_INPUT, out: SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_OUTPUT // NtQuerySystemInformationEx
	SystemMemoryNumaInformation,
	SystemMemoryNumaPerformanceInformation,
	// SYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_INPUT, SYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_OUTPUT // since 24H2 // 240
	SystemCodeIntegritySignedPoliciesFullInformation,
	SystemSecureSecretsInformation,
	SystemTrustedAppsRuntimeInformation, // SYSTEM_TRUSTEDAPPS_RUNTIME_INFORMATION
	SystemBadPageInformationEx,          // SYSTEM_BAD_PAGE_INFORMATION
	SystemResourceDeadlockTimeout,
	SystemBreakOnContextUnwindFailureInformation,
	SystemOslRamdiskInformation, // SYSTEM_OSL_RAMDISK_INFORMATION
	MaxSystemInfoClass
} SYSTEM_INFORMATION_CLASS;

DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtCreateFile(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	PLARGE_INTEGER     AllocationSize,
	ULONG              FileAttributes,
	ULONG              ShareAccess,
	ULONG              CreateDisposition,
	ULONG              CreateOptions,
	PVOID              EaBuffer,
	ULONG              EaLength
);

DECLSPEC_IMPORT BOOL ADVAPI32$LookupAccountSidA(
	IN OPTIONAL LPCSTR lpSystemName,
	IN PSID            Sid,
	OUT OPTIONAL LPSTR Name,
	IN OUT LPDWORD     cchName,
	OUT OPTIONAL LPSTR ReferencedDomainName,
	IN OUT LPDWORD     cchReferencedDomainName,
	OUT PSID_NAME_USE  peUse
);

DECLSPEC_IMPORT BOOL ADVAPI32$LookupAccountSidW(
	IN OPTIONAL LPCWSTR lpSystemName,
	IN PSID             Sid,
	OUT OPTIONAL LPWSTR Name,
	IN OUT LPDWORD      cchName,
	OUT OPTIONAL LPWSTR ReferencedDomainName,
	IN OUT LPDWORD      cchReferencedDomainName,
	OUT PSID_NAME_USE   peUse
);

DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtClose( HANDLE Handle );

DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtFsControlFile(
	HANDLE           FileHandle,
	HANDLE           Event,
	PIO_APC_ROUTINE  ApcRoutine,
	PVOID            ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG            IoControlCode,
	PVOID            InputBuffer,
	ULONG            InputBufferLength,
	PVOID            OutputBuffer,
	ULONG            OutputBufferLength
);

DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtOpenProcess(
	OUT PHANDLE            ProcessHandle,
	IN ACCESS_MASK         DesiredAccess,
	IN POBJECT_ATTRIBUTES  ObjectAttributes,
	IN OPTIONAL PCLIENT_ID ClientId
);

DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtOpenProcessTokenEx(
	IN HANDLE      ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG       HandleAttributes,
	OUT PHANDLE    TokenHandle
);

DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtOpenThreadTokenEx(
	IN HANDLE      ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN BOOLEAN     OpenAsSelf,
	IN ULONG       HandleAttributes,
	OUT PHANDLE    TokenHandle
);

DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtQueryInformationToken(
	IN HANDLE                  TokenHandle,
	IN TOKEN_INFORMATION_CLASS TokenInformationClass,
	OUT OPTIONAL PVOID         TokenInformation,
	IN ULONG                   TokenInformationLength,
	OUT PULONG                 ReturnLength
);

DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT OPTIONAL PVOID          SystemInformation,
	IN ULONG                    SystemInformationLength,
	OUT OPTIONAL PULONG         ReturnLength
);

DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtDuplicateToken(
	IN HANDLE                      ExistingTokenHandle,
	IN ACCESS_MASK                 DesiredAccess,
	IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
	IN BOOLEAN                     EffectiveOnly,
	IN TOKEN_TYPE                  Type,
	OUT PHANDLE                    NewTokenHandle
);

DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtSetInformationToken(
	IN HANDLE                  TokenHandle,
	IN TOKEN_INFORMATION_CLASS TokenInformationClass,
	IN PVOID                   TokenInformation,
	IN ULONG                   TokenInformationLength
);

DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtSetInformationThread(
	IN HANDLE          ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	IN PVOID           ThreadInformation,
	IN ULONG           ThreadInformationLength
);

DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$RtlConvertSidToUnicodeString(
	IN OUT PUNICODE_STRING UnicodeString,
	IN PSID                Sid,
	IN BOOLEAN             AllocateDestinationString
);

DECLSPEC_IMPORT VOID NTAPI NTDLL$RtlFreeUnicodeString(
	IN OUT PUNICODE_STRING UnicodeString
);

DECLSPEC_IMPORT PVOID NTAPI NTDLL$RtlCreateHeap(
	IN ULONG           Flags,
	IN OPTIONAL PVOID  HeapBase,
	IN OPTIONAL SIZE_T ReserveSize,
	IN OPTIONAL SIZE_T CommitSize,
	IN OPTIONAL PVOID  Lock,
	IN OPTIONAL PVOID  Parameters
);

DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtCreateToken(
	OUT PHANDLE                     TokenHandle,
	IN ACCESS_MASK                  DesiredAccess,
	IN OPTIONAL POBJECT_ATTRIBUTES  ObjectAttributes,
	IN TOKEN_TYPE                   Type,
	IN PLUID                        AuthenticationId,
	IN PLARGE_INTEGER               ExpirationTime,
	IN PTOKEN_USER                  User,
	IN PTOKEN_GROUPS                Groups,
	IN PTOKEN_PRIVILEGES            Privileges,
	IN OPTIONAL PTOKEN_OWNER        Owner,
	IN PTOKEN_PRIMARY_GROUP         PrimaryGroup,
	IN OPTIONAL PTOKEN_DEFAULT_DACL DefaultDacl,
	IN PTOKEN_SOURCE                Source
);

DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtCreateTokenEx(
	OUT PHANDLE                                        TokenHandle,
	IN ACCESS_MASK                                     DesiredAccess,
	IN OPTIONAL POBJECT_ATTRIBUTES                     ObjectAttributes,
	IN TOKEN_TYPE                                      Type,
	IN PLUID                                           AuthenticationId,
	IN PLARGE_INTEGER                                  ExpirationTime,
	IN PTOKEN_USER                                     User,
	IN PTOKEN_GROUPS                                   Groups,
	IN PTOKEN_PRIVILEGES                               Privileges,
	IN OPTIONAL PTOKEN_SECURITY_ATTRIBUTES_INFORMATION UserAttributes,
	IN OPTIONAL PTOKEN_SECURITY_ATTRIBUTES_INFORMATION DeviceAttributes,
	IN OPTIONAL PTOKEN_GROUPS                          DeviceGroups,
	IN OPTIONAL PTOKEN_MANDATORY_POLICY                MandatoryPolicy,
	IN OPTIONAL PTOKEN_OWNER                           Owner,
	IN PTOKEN_PRIMARY_GROUP                            PrimaryGroup,
	IN OPTIONAL PTOKEN_DEFAULT_DACL                    DefaultDacl,
	IN PTOKEN_SOURCE                                   Source
);

DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$RtlAllocateAndInitializeSid(
	IN PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
	IN UCHAR                     SubAuthorityCount,
	IN ULONG                     SubAuthority0,
	IN ULONG                     SubAuthority1,
	IN ULONG                     SubAuthority2,
	IN ULONG                     SubAuthority3,
	IN ULONG                     SubAuthority4,
	IN ULONG                     SubAuthority5,
	IN ULONG                     SubAuthority6,
	IN ULONG                     SubAuthority7,
	OUT PSID *                   Sid
);

DECLSPEC_IMPORT LUID NTAPI NTDLL$RtlConvertUlongToLuid(
	ULONG Ulong
);


#endif //TOKEN_H
