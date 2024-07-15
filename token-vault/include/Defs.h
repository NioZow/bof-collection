#ifndef DEFS_H
#define DEFS_H

#include <windows.h>
#include <ntstatus.h>
#include <beacon.h>

#define NtCurrentProcess()              ( ( HANDLE ) ( LONG_PTR ) ( -1 ) )
#define NtCurrentThread()               ( ( HANDLE ) ( LONG_PTR ) ( -2 ) )
#define NtCurrentProcessToken()         ( ( HANDLE ) ( LONG_PTR ) ( -4 ) )
#define NtCurrentThreadToken()          ( ( HANDLE ) ( LONG_PTR ) ( -5 ) )
#define NtCurrentThreadEffectiveToken() ( ( HANDLE ) ( LONG_PTR ) ( -6 ) )
#define NtLastError()                   ( NtCurrentTeb()->LastErrorValue  )
#define NtLastStatus()	                ( NtCurrentTeb()->LastStatusValue )
#define NtCurrentPeb()                  ( ( PPEB ) NtCurrentTeb()->ProcessEnvironmentBlock )
#define NtCurrentHeap()                 ( ( PVOID ) NtCurrentPeb()->ProcessHeap            )
#define ZwCurrentProcess()              NtCurrentProcess()
#define ZwCurrentThread()               NtCurrentThread()

#if _WIN64
#define NtCurrentProcessId() ( ( DWORD ) ( __readgsdword( 0x40 ) ) )
#elif _WIN32
#define NtCurrentProcessId() ( ( DWORD ) ( __readfsdword( 0x20 ) ) )
#endif

#if _WIN64
#define NtCurrentThreadId() ( ( DWORD ) ( __readgsdword( 0x48 ) ) )
#elif _WIN32
#define NtCurrentThreadId() ( ( DWORD ) ( __readgsdword( 0x24 ) ) )
#endif

// casting macros
#define C_PTR( x )   ( ( PVOID    ) ( x ) )
#define C_BYTE( x )  ( ( PBYTE    ) ( x ) )
#define U_PTR( x )   ( ( UINT_PTR ) ( x ) )
#define U_PTR32( x ) ( ( ULONG    ) ( x ) )
#define U_PTR64( x ) ( ( ULONG64  ) ( x ) )
#define A_PTR( x )   ( ( PCHAR    ) ( x ) )
#define W_PTR( x )   ( ( PWCHAR   ) ( x ) )

// dereference memory macros
#define C_DEF( x )   ( * ( PVOID* )  ( x ) )
#define C_DEF08( x ) ( * ( UINT8*  ) ( x ) )
#define C_DEF16( x ) ( * ( UINT16* ) ( x ) )
#define C_DEF32( x ) ( * ( UINT32* ) ( x ) )
#define C_DEF64( x ) ( * ( UINT64* ) ( x ) )

// Memory allocation NTDLL APIs
DECLSPEC_IMPORT PVOID NTAPI NTDLL$RtlCreateHeap(
    IN ULONG           Flags,
    IN OPTIONAL PVOID  HeapBase,
    IN OPTIONAL SIZE_T ReserveSize,
    IN OPTIONAL SIZE_T CommitSize,
    IN OPTIONAL PVOID  Lock,
    IN OPTIONAL PVOID  Parameters
);

DECLSPEC_IMPORT PVOID NTAPI NTDLL$RtlReAllocateHeap(
    IN PVOID          HeapHandle,
    IN ULONG          Flags,
    IN OPTIONAL PVOID BaseAddress,
    IN SIZE_T         Size
);

DECLSPEC_IMPORT PVOID NTAPI NTDLL$RtlAllocateHeap(
    IN PVOID          HeapHandle,
    IN OPTIONAL ULONG Flags,
    IN SIZE_T         Size
);

DECLSPEC_IMPORT VOID NTAPI NTDLL$RtlFreeHeap(
    IN PVOID          HeapHandle,
    IN OPTIONAL ULONG Flags,
    IN PVOID          BaseAddress
);

// MSVCRT
WINBASEAPI int __cdecl MSVCRT$printf( const char *__format, ... );

#define NT_SUCCESS( Status )     ( ( NTSTATUS ) ( Status ) >= 0 )
#define NT_INFORMATION( Status ) ( ( ULONG ) ( Status ) >> 30 == 1 )
#define NT_WARNING( Status )     ( ( ULONG ) ( Status ) >> 30 == 2 )
#define NT_ERROR( Status )       ( ( ULONG ) ( Status ) >> 30 == 3 )

// printing
//#define PRINTF( text, ... )             MSVCRT$printf( text, ##__VA_ARGS__ );
//#define PRINTF_ERROR( text, ... )       MSVCRT$printf( "[!] " text, ##__VA_ARGS__);
#define PRINTF( text, ... )             BeaconPrintf( CALLBACK_OUTPUT, text, ##__VA_ARGS__ );
#define PRINTF_ERROR( text, ... )       BeaconPrintf( CALLBACK_ERROR, text, ##__VA_ARGS__);
#define PRINT_NT_ERROR( ntapi, status ) PRINTF_ERROR( "%s failed with error: 0x%08X\n", ntapi, status )
#define PRINT_WIN32_ERROR( win32api )   PRINTF_ERROR( "%s failed with error: %ld\n", win32api, NtLastError() )

// init unicode string
#define INIT_UNICODE_STRING( wstr ) { .Buffer = wstr, .MaximumLength = sizeof( wstr ), .Length = sizeof( wstr ) - sizeof( WCHAR ) }

#define RTL_MAX_DRIVE_LETTERS 32
typedef PVOID *PPVOID;

#define GDI_HANDLE_BUFFER_SIZE32  34
#define GDI_HANDLE_BUFFER_SIZE64  60

#if !defined(_M_X64)
#define GDI_HANDLE_BUFFER_SIZE      GDI_HANDLE_BUFFER_SIZE32
#else
#define GDI_HANDLE_BUFFER_SIZE      GDI_HANDLE_BUFFER_SIZE64
#endif

typedef ULONG GDI_HANDLE_BUFFER32[ GDI_HANDLE_BUFFER_SIZE32 ];
typedef ULONG GDI_HANDLE_BUFFER64[ GDI_HANDLE_BUFFER_SIZE64 ];
typedef ULONG GDI_HANDLE_BUFFER[ GDI_HANDLE_BUFFER_SIZE ];

#define InitializeObjectAttributes( p, n, a, r, s ) { \
(p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
(p)->RootDirectory = r;                             \
(p)->Attributes = a;                                \
(p)->ObjectName = n;                                \
(p)->SecurityDescriptor = s;                        \
(p)->SecurityQualityOfService = NULL;               \
}

typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR  Buffer;
} STRING, *PSTRING;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _CURDIR {
    UNICODE_STRING DosPath;
    HANDLE         Handle;
} CURDIR, *PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
    USHORT         Flags;
    USHORT         Length;
    ULONG          TimeStamp;
    UNICODE_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG  ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR         CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PWCHAR         Environment;

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG                   WindowFlags;
    ULONG                   ShowWindowFlags;
    UNICODE_STRING          WindowTitle;
    UNICODE_STRING          DesktopInfo;
    UNICODE_STRING          ShellInfo;
    UNICODE_STRING          RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[ RTL_MAX_DRIVE_LETTERS ];

    ULONG_PTR EnvironmentSize;
    ULONG_PTR EnvironmentVersion;
    PVOID     PackageDependencyData;
    ULONG     ProcessGroupId;
    ULONG     LoaderThreads;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA {
    ULONG      Length;
    BOOLEAN    Initialized;
    HANDLE     SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID      EntryInProgress;
    BOOLEAN    ShutdownInProgress;
    HANDLE     ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

#define GDI_BATCH_BUFFER_SIZE 310

typedef struct _GDI_TEB_BATCH {
    ULONG     Offset;
    ULONG_PTR HDC;
    ULONG     Buffer[ GDI_BATCH_BUFFER_SIZE ];
} GDI_TEB_BATCH, *PGDI_TEB_BATCH;

#define STATIC_UNICODE_BUFFER_LENGTH 261
#define WIN32_CLIENT_INFO_LENGTH 62

typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
    ULONG Flags;
    PSTR  FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, *PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _ACTIVATION_CONTEXT_DATA {
    ULONG Magic;
    ULONG HeaderSize;
    ULONG FormatVersion;
    ULONG TotalSize;
    ULONG DefaultTocOffset;     // to ACTIVATION_CONTEXT_DATA_TOC_HEADER
    ULONG ExtendedTocOffset;    // to ACTIVATION_CONTEXT_DATA_EXTENDED_TOC_HEADER
    ULONG AssemblyRosterOffset; // to ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER
    ULONG Flags;                // ACTIVATION_CONTEXT_FLAG_*
} ACTIVATION_CONTEXT_DATA, *PACTIVATION_CONTEXT_DATA;

typedef struct _ASSEMBLY_STORAGE_MAP_ENTRY {
    ULONG          Flags;
    UNICODE_STRING DosPath;
    HANDLE         Handle;
} ASSEMBLY_STORAGE_MAP_ENTRY, *PASSEMBLY_STORAGE_MAP_ENTRY;

typedef struct _ASSEMBLY_STORAGE_MAP {
    ULONG                        Flags;
    ULONG                        AssemblyCount;
    PASSEMBLY_STORAGE_MAP_ENTRY *AssemblyArray;
} ASSEMBLY_STORAGE_MAP, *PASSEMBLY_STORAGE_MAP;

typedef struct _ACTIVATION_CONTEXT {
    LONG                        RefCount;
    ULONG                       Flags;
    PACTIVATION_CONTEXT_DATA    ActivationContextData;
    PVOID                       NotificationRoutine; //PACTIVATION_CONTEXT_NOTIFY_ROUTINE
    PVOID                       NotificationContext;
    ULONG                       SentNotifications[ 8 ];
    ULONG                       DisabledNotifications[ 8 ];
    ASSEMBLY_STORAGE_MAP        StorageMap;
    PASSEMBLY_STORAGE_MAP_ENTRY InlineStorageMapEntries[ 32 ];
} ACTIVATION_CONTEXT, *PACTIVATION_CONTEXT;

typedef VOID ( NTAPI *PACTIVATION_CONTEXT_NOTIFY_ROUTINE )(
    IN ULONG                    NotificationType, // ACTIVATION_CONTEXT_NOTIFICATION_*
    IN PACTIVATION_CONTEXT      ActivationContext,
    IN PACTIVATION_CONTEXT_DATA ActivationContextData,
    IN OPTIONAL PVOID           NotificationContext,
    IN OPTIONAL PVOID           NotificationData,
    IN OUT PBOOLEAN             DisableThisNotification
);

typedef struct _TEB_ACTIVE_FRAME {
    ULONG                     Flags;
    struct _TEB_ACTIVE_FRAME *Previous;
    PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, *PTEB_ACTIVE_FRAME;

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME {
    struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME *Previous;
    PACTIVATION_CONTEXT                         ActivationContext;
    ULONG                                       Flags; // RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_*
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, *PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _ACTIVATION_CONTEXT_STACK {
    PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
    LIST_ENTRY                          FrameListCache;
    ULONG                               Flags; // ACTIVATION_CONTEXT_STACK_FLAG_*
    ULONG                               NextCookieSequenceNumber;
    ULONG                               StackId;
} ACTIVATION_CONTEXT_STACK, *PACTIVATION_CONTEXT_STACK;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;

    union {
        BOOLEAN BitField;

        struct {
            BOOLEAN ImageUsesLargePages          : 1;
            BOOLEAN IsProtectedProcess           : 1;
            BOOLEAN IsLegacyProcess              : 1;
            BOOLEAN IsImageDynamicallyRelocated  : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN SpareBits                    : 3;
        };
    };

    HANDLE Mutant;

    PVOID                        ImageBaseAddress;
    PPEB_LDR_DATA                Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID                        SubSystemData;
    PVOID                        ProcessHeap;
    PRTL_CRITICAL_SECTION        FastPebLock;
    PVOID                        AtlThunkSListPtr;
    PVOID                        IFEOKey;

    union {
        ULONG CrossProcessFlags;

        struct {
            ULONG ProcessInJob        : 1;
            ULONG ProcessInitializing : 1;
            ULONG ProcessUsingVEH     : 1;
            ULONG ProcessUsingVCH     : 1;
            ULONG ProcessUsingFTH     : 1;
            ULONG ReservedBits0       : 27;
        };

        ULONG EnvironmentUpdateCount;
    };

    union {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    };

    ULONG  SystemReserved[ 1 ];
    ULONG  AtlThunkSListPtr32;
    PVOID  ApiSetMap;
    ULONG  TlsExpansionCounter;
    PVOID  TlsBitmap;
    ULONG  TlsBitmapBits[ 2 ];
    PVOID  ReadOnlySharedMemoryBase;
    PVOID  HotpatchInformation;
    PPVOID ReadOnlyStaticServerData;
    PVOID  AnsiCodePageData;
    PVOID  OemCodePageData;
    PVOID  UnicodeCaseTableData;

    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;

    LARGE_INTEGER CriticalSectionTimeout;
    SIZE_T        HeapSegmentReserve;
    SIZE_T        HeapSegmentCommit;
    SIZE_T        HeapDeCommitTotalFreeThreshold;
    SIZE_T        HeapDeCommitFreeBlockThreshold;

    ULONG  NumberOfHeaps;
    ULONG  MaximumNumberOfHeaps;
    PPVOID ProcessHeaps;

    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;

    PRTL_CRITICAL_SECTION LoaderLock;

    ULONG             OSMajorVersion;
    ULONG             OSMinorVersion;
    USHORT            OSBuildNumber;
    USHORT            OSCSDVersion;
    ULONG             OSPlatformId;
    ULONG             ImageSubsystem;
    ULONG             ImageSubsystemMajorVersion;
    ULONG             ImageSubsystemMinorVersion;
    ULONG_PTR         ImageProcessAffinityMask;
    GDI_HANDLE_BUFFER GdiHandleBuffer;
    PVOID             PostProcessInitRoutine;

    PVOID TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[ 32 ];

    ULONG SessionId;

    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID          pShimData;
    PVOID          AppCompatInfo;

    UNICODE_STRING CSDVersion;

    PVOID ActivationContextData;
    PVOID ProcessAssemblyStorageMap;
    PVOID SystemDefaultActivationContextData;
    PVOID SystemAssemblyStorageMap;

    SIZE_T MinimumStackCommit;

    PPVOID     FlsCallback;
    LIST_ENTRY FlsListHead;
    PVOID      FlsBitmap;
    ULONG      FlsBitmapBits[ FLS_MAXIMUM_AVAILABLE / ( sizeof( ULONG ) * 8 ) ];
    ULONG      FlsHighIndex;

    PVOID WerRegistrationData;
    PVOID WerShipAssertPtr;
    PVOID pContextData;
    PVOID pImageHeaderHash;

    union {
        ULONG TracingFlags;

        struct {
            ULONG HeapTracingEnabled    : 1;
            ULONG CritSecTracingEnabled : 1;
            ULONG SpareTracingBits      : 30;
        };
    };
} PEB, *PPEB;

typedef struct _TEB {
    NT_TIB NtTib;

    PVOID     EnvironmentPointer;
    CLIENT_ID ClientId;
    PVOID     ActiveRpcHandle;
    PVOID     ThreadLocalStoragePointer;
    PPEB      ProcessEnvironmentBlock;

    ULONG LastErrorValue;
    ULONG CountOfOwnedCriticalSections;
    PVOID CsrClientThread;
    PVOID Win32ThreadInfo;
    ULONG User32Reserved[ 26 ];
    ULONG UserReserved[ 5 ];
    PVOID WOW32Reserved;
    LCID  CurrentLocale;
    ULONG FpSoftwareStatusRegister;
    PVOID ReservedForDebuggerInstrumentation[ 16 ];
#ifdef _WIN64
    PVOID SystemReserved1[ 25 ];

    PVOID HeapFlsData;

    ULONG_PTR RngState[ 4 ];
#else
    PVOID SystemReserved1[26];
#endif

    CHAR    PlaceholderCompatibilityMode;
    BOOLEAN PlaceholderHydrationAlwaysExplicit;
    CHAR    PlaceholderReserved[ 10 ];

    ULONG                    ProxiedProcessId;
    ACTIVATION_CONTEXT_STACK ActivationStack;

    UCHAR WorkingOnBehalfTicket[ 8 ];

    NTSTATUS ExceptionCode;

    PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
    ULONG_PTR                 InstrumentationCallbackSp;
    ULONG_PTR                 InstrumentationCallbackPreviousPc;
    ULONG_PTR                 InstrumentationCallbackPreviousSp;
#ifdef _WIN64
    ULONG TxFsContext;
#endif

    BOOLEAN InstrumentationCallbackDisabled;
#ifdef _WIN64
    BOOLEAN UnalignedLoadStoreExceptions;
#endif
#ifndef _WIN64
    UCHAR SpareBytes[23];
    ULONG TxFsContext;
#endif
    GDI_TEB_BATCH GdiTebBatch;
    CLIENT_ID     RealClientId;
    HANDLE        GdiCachedProcessHandle;
    ULONG         GdiClientPID;
    ULONG         GdiClientTID;
    PVOID         GdiThreadLocalInfo;
    ULONG_PTR     Win32ClientInfo[ WIN32_CLIENT_INFO_LENGTH ];

    PVOID     glDispatchTable[ 233 ];
    ULONG_PTR glReserved1[ 29 ];
    PVOID     glReserved2;
    PVOID     glSectionInfo;
    PVOID     glSection;
    PVOID     glTable;
    PVOID     glCurrentRC;
    PVOID     glContext;

    NTSTATUS LastStatusValue;

    UNICODE_STRING StaticUnicodeString;
    WCHAR          StaticUnicodeBuffer[ STATIC_UNICODE_BUFFER_LENGTH ];

    PVOID DeallocationStack;

    PVOID      TlsSlots[ TLS_MINIMUM_AVAILABLE ];
    LIST_ENTRY TlsLinks;

    PVOID Vdm;
    PVOID ReservedForNtRpc;
    PVOID DbgSsReserved[ 2 ];

    ULONG HardErrorMode;
#ifdef _WIN64
    PVOID Instrumentation[ 11 ];
#else
    PVOID Instrumentation[9];
#endif
    GUID ActivityId;

    PVOID SubProcessTag;
    PVOID PerflibData;
    PVOID EtwTraceData;
    PVOID WinSockData;
    ULONG GdiBatchCount;

    union {
        PROCESSOR_NUMBER CurrentIdealProcessor;
        ULONG            IdealProcessorValue;

        struct {
            UCHAR ReservedPad0;
            UCHAR ReservedPad1;
            UCHAR ReservedPad2;
            UCHAR IdealProcessor;
        };
    };

    ULONG     GuaranteedStackBytes;
    PVOID     ReservedForPerf;
    PVOID     ReservedForOle; // tagSOleTlsData
    ULONG     WaitingOnLoaderLock;
    PVOID     SavedPriorityState;
    ULONG_PTR ReservedForCodeCoverage;
    PVOID     ThreadPoolData;
    PVOID *   TlsExpansionSlots;
#ifdef _WIN64
    PVOID ChpeV2CpuAreaInfo; // CHPEV2_CPUAREA_INFO // previously DeallocationBStore
    PVOID Unused;            // previously BStoreLimit
#endif
    ULONG             MuiGeneration;
    ULONG             IsImpersonating;
    PVOID             NlsCache;
    PVOID             pShimData;
    ULONG             HeapData;
    HANDLE            CurrentTransactionHandle;
    PTEB_ACTIVE_FRAME ActiveFrame;
    PVOID             FlsData;

    PVOID PreferredLanguages;
    PVOID UserPrefLanguages;
    PVOID MergedPrefLanguages;
    ULONG MuiImpersonation;

    union {
        USHORT CrossTebFlags;
        USHORT SpareCrossTebBits : 16;
    };

    union {
        USHORT SameTebFlags;

        struct {
            USHORT SafeThunkCall        : 1;
            USHORT InDebugPrint         : 1;
            USHORT HasFiberData         : 1;
            USHORT SkipThreadAttach     : 1;
            USHORT WerInShipAssertCode  : 1;
            USHORT RanProcessInit       : 1;
            USHORT ClonedThread         : 1;
            USHORT SuppressDebugMsg     : 1;
            USHORT DisableUserStackWalk : 1;
            USHORT RtlExceptionAttached : 1;
            USHORT InitialThread        : 1;
            USHORT SessionAware         : 1;
            USHORT LoadOwner            : 1;
            USHORT LoaderWorker         : 1;
            USHORT SkipLoaderInit       : 1;
            USHORT SkipFileAPIBrokering : 1;
        };
    };

    PVOID          TxnScopeEnterCallback;
    PVOID          TxnScopeExitCallback;
    PVOID          TxnScopeContext;
    ULONG          LockCount;
    LONG           WowTebOffset;
    PVOID          ResourceRetValue;
    PVOID          ReservedForWdf;
    ULONGLONG      ReservedForCrt;
    GUID           EffectiveContainerId;
    ULONGLONG      LastSleepCounter; // Win11
    ULONG          SpinCallCount;
    ULONGLONG      ExtendedFeatureDisableMask;
    PVOID          SchedulerSharedDataSlot; // 24H2
    PVOID          HeapWalkContext;
    GROUP_AFFINITY PrimaryGroupAffinity;
    ULONG          Rcu[ 2 ];
} TEB, *PTEB;

#endif //DEFS_H
