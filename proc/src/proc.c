#include <Proc.h>
#include <Defs.h>
#include "beacon.c"

#define TOKEN_STORE_ITEM 0xdeadbeef
#include "utils.c"

NTSTATUS ProcList() {
    ULONG                       size   = { 0 };
    NTSTATUS                    status = { 0 };
    PVOID                       Procs  = { 0 };
    PSYSTEM_PROCESS_INFORMATION Proc   = { 0 };
    PPROCESS                    proc   = { 0 };

    // get the returned length to alloc mem
    NTDLL$NtQuerySystemInformation( SystemProcessInformation, NULL, 0, &size );
    Procs = Proc = NTDLL$RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, size );

    // get the processes
    if ( ! NT_SUCCESS( status = NTDLL$NtQuerySystemInformation(
        SystemProcessInformation,
        Procs,
        size,
        &size
    ) ) ) {
        PRINT_NT_ERROR( "NtQuerySystemInformation", status );
        goto END;
    }

    // iterate through all processes
    do {
        // initiate a proc struct
        proc          = NTDLL$RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( PROC ) );
        proc->Name    = Proc->ImageName.Buffer;
        proc->Pid     = ( ULONG ) Proc->UniqueProcessId;
        proc->Ppid    = ( ULONG ) Proc->InheritedFromUniqueProcessId;
        proc->Handles = Proc->HandleCount;

        MSVCRT$printf( "%ls - %lu - %lu - %lu\n", proc->Name, proc->Pid, proc->Ppid, proc->Handles );
    } while ( ( Proc->NextEntryOffset ) &&
              ( Proc = ( PSYSTEM_PROCESS_INFORMATION ) ( C_PTR( Proc ) + Proc->NextEntryOffset ) ) );

END:
    if ( Procs ) NTDLL$RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Procs );
    return status;
}

NTSTATUS ProcListThreads(
    IN ULONG pid
) {
    ULONG                       size   = { 0 };
    NTSTATUS                    status = { 0 };
    PVOID                       Procs  = { 0 };
    PSYSTEM_PROCESS_INFORMATION Proc   = { 0 };

    // get the returned length to alloc mem
    NTDLL$NtQuerySystemInformation( SystemProcessInformation, NULL, 0, &size );
    Procs = Proc = NTDLL$RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, size );

    // get the processes
    if ( ! NT_SUCCESS( status = NTDLL$NtQuerySystemInformation(
        SystemProcessInformation,
        Procs,
        size,
        &size
    ) ) ) {
        PRINT_NT_ERROR( "NtQuerySystemInformation", status );
        goto END;
    }

    // iterate through all processes
    do {
        if ( Proc->UniqueProcessId == C_PTR( pid ) ) {
            MSVCRT$printf( "Threads of %ls (%d):\n", Proc->ImageName.Buffer, pid );

            for ( int i = 0 ; i < Proc->NumberOfThreads ; i++ ) {
                MSVCRT$printf( "TID: %d - StartAddress: 0x%08X - State: %d\n", Proc->Threads[ i ].ClientId.UniqueThread,
                               Proc->Threads[ i ].StartAddress, Proc->Threads[ i ].State );
            }

            break;
        }
    } while ( ( Proc->NextEntryOffset ) &&
              ( Proc = ( PSYSTEM_PROCESS_INFORMATION ) ( C_PTR( Proc ) + Proc->NextEntryOffset ) ) );

END:
    if ( Procs ) NTDLL$RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Procs );
    return status;
}

HANDLE ProcOpen(
    IN ULONG pid,
    IN ULONG AccessMask
) {
    CLIENT_ID         client  = { 0 };
    OBJECT_ATTRIBUTES objAttr = { 0 };
    NTSTATUS          status  = { 0 };
    HANDLE            process = { 0 };

    // initialize obj attributes
    InitializeObjectAttributes( &objAttr, NULL, 0, NULL, NULL );

    // set the pid
    client.UniqueProcess = C_PTR( pid );

    // get a handle on the process
    if ( ! NT_SUCCESS( status = NTDLL$NtOpenProcess(
        &process,
        AccessMask,
        &objAttr,
        &client
    ) ) ) {
        PRINT_NT_ERROR( "NtOpenProcess", status );
    }

    return process;
}

NTSTATUS ProcKill(
    IN ULONG pid
) {
    HANDLE   process = { 0 };
    NTSTATUS status  = { 0 };

    // get a handle on the process
    process = ProcOpen( pid, PROCESS_TERMINATE );
    if ( ! process ) {
        goto END;
    }

    // terminate the process
    if ( ! NT_SUCCESS( status = NTDLL$NtTerminateProcess( process, 0 ) ) ) {
        PRINT_NT_ERROR( "NtTerminateProcess", status );
    }

END:
    if ( process ) NTDLL$NtClose( process );
    return status;
}

BOOL PipeInit(
    OUT PHANDLE Read,
    OUT PHANDLE Write
) {
    SECURITY_ATTRIBUTES SecAttr = {
        .nLength = sizeof( SECURITY_ATTRIBUTES ),
        .bInheritHandle = TRUE
    };

    if ( ! KERNEL32$CreatePipe( Read, Write, &SecAttr, 0 ) ) {
        PRINT_WIN32_ERROR( "CreatePipe" );
        return FALSE;
    }

    if ( ! KERNEL32$SetHandleInformation( *Read, HANDLE_FLAG_INHERIT, 0 ) ) {
        PRINT_WIN32_ERROR( "SetHandleInformation" );
        NTDLL$NtClose( *Read );
        NTDLL$NtClose( *Write );
        return FALSE;
    }

    return TRUE;
}

BOOL PipeRead(
    IN HANDLE   Read,
    OUT PBYTE * Buffer,
    OUT PSIZE_T Size
) {
    BYTE  Bytes[ 1024 ] = { 0 };
    DWORD NbRead        = { 0 };

    while ( TRUE ) {
        if ( ! KERNEL32$ReadFile( Read, Bytes, 1024, &NbRead, NULL ) ) {
            PRINT_WIN32_ERROR( "ReadFile" );
            return FALSE;
        }

        *Size += NbRead;

        // (re)alloc buffer
        if ( *Buffer ) {
            if ( ! ( *Buffer = NTDLL$RtlReAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, *Buffer,
                                                        *Size ) ) ) {
                PRINT_WIN32_ERROR( "LocalReAlloc" );
                return FALSE;
            }
        } else {
            if ( ! ( *Buffer =
                     NTDLL$RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, *Size ) ) ) {
                PRINT_WIN32_ERROR( "LocalAlloc" );
                return FALSE;
            }
        }

        MemCopy( *Buffer + ( *Size - NbRead ), Bytes, NbRead );
        MemSet( Bytes, 0, NbRead );

        if ( NbRead < 1024 ) {
            break;
        }
    }

    return TRUE;
}


NTSTATUS ProcResume(
    IN ULONG pid
) {
    HANDLE   process = { 0 };
    NTSTATUS status  = { 0 };

    // get a handle on the process
    if ( ! ( process = ProcOpen( pid, PROCESS_SUSPEND_RESUME ) ) ) {
        goto END;
    }

    // terminate the process
    if ( ! NT_SUCCESS( status = NTDLL$NtResumeProcess( process ) ) ) {
        PRINT_NT_ERROR( "NtTerminateProcess", status );
    }

END:
    if ( process ) NTDLL$NtClose( process );
    return status;
}

NTSTATUS ProcSuspend(
    IN ULONG pid
) {
    HANDLE   process = { 0 };
    NTSTATUS status  = { 0 };

    // get a handle on the process
    if ( ! ( process = ProcOpen( pid, PROCESS_SUSPEND_RESUME ) ) ) {
        goto END;
    }

    // terminate the process
    if ( ! NT_SUCCESS( status = NTDLL$NtSuspendProcess( process ) ) ) {
        PRINT_NT_ERROR( "NtTerminateProcess", status );
    }

END:
    if ( process ) NTDLL$NtClose( process );
    return status;
}

NTSTATUS ProcListHandles(
    IN ULONG pid
) {
    NTSTATUS                             status      = { 0 };
    HANDLE                               process     = { 0 };
    ULONG                                size        = { 0 };
    PPROCESS_HANDLE_SNAPSHOT_INFORMATION procHandles = { 0 };
    PPROCESS_HANDLE_TABLE_ENTRY_INFO     handle      = { 0 };
    INT                                  cnt         = { 0 };
    POBJECT_NAME_INFORMATION             objInfo     = { 0 };
    ULONG                                objSize     = { 0 };

    if ( ! NT_SUCCESS( process = ProcOpen( pid, PROCESS_QUERY_INFORMATION ) ) ) {
        goto END;
    }

    // set size of 16, because it's return 16 on the first call even though that's not the right size
    // on the second call it returns the right size
    // trying to bypass that
    status = NTDLL$NtQueryInformationProcess( process, ProcessHandleInformation, NULL, 16, &size );
    if ( status != STATUS_INFO_LENGTH_MISMATCH ) {
        PRINT_NT_ERROR( "NtQueryInformationProcess", status );
        goto END;
    }

    procHandles = NTDLL$RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, size );
    if ( ! NT_SUCCESS( status = NTDLL$NtQueryInformationProcess(
        process,
        ProcessHandleInformation,
        procHandles,
        size,
        &size
    ) ) ) {
        PRINT_NT_ERROR( "NtQueryInformationProcess", status );
        goto END;
    }

    MSVCRT$printf( "[+] Captured %lu handles\n", procHandles->NumberOfHandles );

    for ( int i = 0 ; i < procHandles->NumberOfHandles ; i++ ) {
        handle = &procHandles->Handles[ i ];

        status = NTDLL$NtQueryObject( handle->HandleValue, ObjectNameInformation, NULL, 0, &objSize );
        if ( status == STATUS_INVALID_HANDLE ) {
            continue;
        } else if ( status != STATUS_INFO_LENGTH_MISMATCH ) {
            PRINT_NT_ERROR( "NtQueryObject", status );
            goto END;
        }

        objInfo = NTDLL$RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, size );

        if ( ! NT_SUCCESS( status = NTDLL$NtQueryObject(
            handle->HandleValue,
            ObjectNameInformation,
            objInfo,
            objSize,
            &objSize
        ) ) ) {
            PRINT_NT_ERROR( "NtQueryObject", status );
            goto END;
        }

        //MSVCRT$printf( "Access: 0x%08X\n", procHandles->Handles[ i ].GrantedAccess );
        MSVCRT$printf( "Type: %ls\n", objInfo->Name.Buffer );
        NTDLL$RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, objInfo );

        /*
        if ( procHandles->Handles[ i ].GrantedAccess & GENERIC_READ ) {
            cnt++;
        }
        */
    }

END:
    if ( procHandles ) NTDLL$RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, procHandles );
    return status;
}

NTSTATUS ProcCreate(
    IN PUNICODE_STRING imagePath,
    IN PUNICODE_STRING arguments,
    IN OPTIONAL ULONG  parentProcessId,
    IN OPTIONAL BOOL   dontUseCurrentTokenFromVault,
    // IN OPTIONAL USHORT          useTokenFromVault,
    // IN OPTIONAL PUNICODE_STRING username,
    // IN OPTIONAL PUNICODE_STRING password,
    // IN OPTIONAL PUNICODE_STRING domain,
    IN OPTIONAL BOOL blockUnsignedDlls,
    IN OPTIONAL BOOL captureOutput,
    IN OPTIONAL BOOL createSuspended
) {
    HANDLE                       process            = { 0 };
    HANDLE                       thread             = { 0 };
    NTSTATUS                     status             = { 0 };
    PRTL_USER_PROCESS_PARAMETERS params             = { 0 };
    PS_ATTRIBUTE_LIST            attrs              = { 0 };
    PS_CREATE_INFO               createInfo         = { 0 };
    BYTE                         NumberOfAttributes = { 0 };
    HANDLE                       parentProcess      = { 0 };
    ULONG                        processFlags       = { 0 };
    HANDLE                       stdRead            = { 0 };
    HANDLE                       stdWrite           = { 0 };
    LARGE_INTEGER                timeout            = { 0 };
    PBYTE                        output             = { 0 };
    SIZE_T                       outputSize         = { 0 };
    HANDLE                       token              = { 0 };

    DWORD64 blockPolicy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

    // init creation info
    createInfo.Size  = sizeof( PS_CREATE_INFO );
    createInfo.State = PsCreateInitialState;

    // initialize process parameters
    // like the path of the image, the command line arguments...
    if ( ! NT_SUCCESS( status = NTDLL$RtlCreateProcessParametersEx(
        &params,
        imagePath,
        NULL,
        NULL,
        arguments,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        RTL_USER_PROC_PARAMS_NORMALIZED
    ) ) ) {
        PRINT_NT_ERROR( "RtlCreateProcessParametersEx", status );
        goto END;
    }

    // set the image path in the attributes
    attrs.Attributes[ 0 ].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    attrs.Attributes[ 0 ].Size      = imagePath->Length;
    attrs.Attributes[ 0 ].Value     = ( ULONG_PTR ) imagePath->Buffer;

    // perform parent process id spoofing
    // ppid spoofing can be easily detected using kernel callbacks
    // only use if necessary because the parent-child relationship will be flag otherwise
    if ( parentProcessId ) {
        // increase the number of attributes
        NumberOfAttributes++;

        parentProcess = ProcOpen( parentProcessId, PROCESS_CREATE_PROCESS );
        if ( ! parentProcess ) {
            status = STATUS_INTERNAL_ERROR;
            goto END;
        }

        attrs.Attributes[ NumberOfAttributes ].Attribute = PS_ATTRIBUTE_PARENT_PROCESS;
        attrs.Attributes[ NumberOfAttributes ].Size      = sizeof( HANDLE );
        attrs.Attributes[ NumberOfAttributes ].Value     = ( ULONG_PTR ) parentProcess;
    }

    // prevent unsigned dlls from loading into the process
    // if the EDR dll is not signed (which is unlikely nowadays), it wont able inject hooks
    if ( blockUnsignedDlls ) {
        NumberOfAttributes++;
        attrs.Attributes[ NumberOfAttributes ].Attribute = PS_ATTRIBUTE_MITIGATION_OPTIONS;
        attrs.Attributes[ NumberOfAttributes ].Size      = sizeof( DWORD64 );
        attrs.Attributes[ NumberOfAttributes ].Value     = ( ULONG_PTR ) &blockPolicy;
    }

    if ( ! dontUseCurrentTokenFromVault ) {
        // get the current token from the token vault
        // compatible with my bof token vault: https://github.com/NioZow/bof-collection/token-vault

        // check if the token can be assigned a primary token
        // check requirements and so maybe use seclogon
        // make that shit up, might be useless if I use seclogon instead

        // BeaconGetData...
        NumberOfAttributes++;
        attrs.Attributes[ NumberOfAttributes ].Attribute = PS_ATTRIBUTE_TOKEN;
        attrs.Attributes[ NumberOfAttributes ].Size      = sizeof( HANDLE );
        attrs.Attributes[ NumberOfAttributes ].Value     = ( ULONG_PTR ) token;
    }

    // capture the output of the process
    // create a pipe and set the handles for the child process
    // currently does not work, do not use
    // ReadFile waits infinitely, have to fix it. I guess because nothing has been written to the pipe
    // Reverse console flags, to know how can I pass some handles
    if ( captureOutput ) {
        if ( ! PipeInit( &stdRead, &stdWrite ) ) {
            MSVCRT$printf( "Failed to init the pipe!" );
            goto END;
        }

        //params->ConsoleFlags   = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        params->StandardError  = stdWrite;
        params->StandardOutput = stdWrite;
        params->StandardInput  = stdRead;
    }

    // create the process as a suspended process
    // not really opsec friendly as except for malwares this feature is not used a lot
    // might directly mark the process as "suspicious" depending on the EDR
    if ( createSuspended ) {
        processFlags |= PROCESS_CREATE_FLAGS_SUSPENDED;
    }

    // set the length of the attribute list
    attrs.TotalLength = sizeof( SIZE_T ) + sizeof( PS_ATTRIBUTE ) * ( NumberOfAttributes + 1 );

    // create the process
    if ( ! NT_SUCCESS( status = NTDLL$NtCreateUserProcess(
        &process,
        &thread,
        PROCESS_ALL_ACCESS,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        processFlags,
        0,
        params,
        &createInfo,
        &attrs
    ) ) ) {
        PRINT_NT_ERROR( "NtCreateUserProcess", status );
        goto END;
    }

    // read from the created pipe the process output
    if ( captureOutput ) {
        MSVCRT$printf( "Trying to get output\n" );

        timeout.QuadPart = 5000;
        NTDLL$NtWaitForSingleObject( process, FALSE, &timeout );

        if ( PipeRead( stdRead, &output, &outputSize ) ) {
            MSVCRT$printf( "Successfully got output!\n" );
        } else {
            MSVCRT$printf( "Failed to get output!\n" );
        }
    }

END:
    return status;
}

VOID go(
    IN PCHAR args,
    IN INT   argc
) {
    WCHAR targetProcess[ ] = L"\\??\\C:\\Windows\\System32\\cmd.exe";
    WCHAR processParams[ ] = L"/c whoami";

    UNICODE_STRING uTargetProcess = INIT_UNICODE_STRING( targetProcess );
    UNICODE_STRING uProcessParams = INIT_UNICODE_STRING( processParams );

    if ( ! NT_SUCCESS( ProcCreate( &uTargetProcess, &uProcessParams, 0, TRUE, FALSE, FALSE, FALSE ) ) ) {
        return;
    }
}
