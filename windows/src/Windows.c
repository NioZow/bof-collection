#include <Common.h>
#include "Common.c"

VOID WindowsList() {
    PWSTR                       WindowName = { 0 };
    ULONG                       Length     = { 0 };
    ULONG                       ProcId     = { 0 };
    PVOID                       Procs      = { 0 };
    PSYSTEM_PROCESS_INFORMATION ProcInfo   = { 0 };
    ULONG                       Size       = { 0 };
    NTSTATUS                    NtStatus   = { 0 };
    BOOL                        Found      = { 0 };
    HWND                        Window     = USER32$GetTopWindow( NULL );

    //
    // get all process and some intel about them without getting a handle onto those
    //
    NTDLL$NtQuerySystemInformation( SystemProcessInformation, NULL, 0, &Size );

    Procs = MmAlloc( Size );

    if ( ! NT_SUCCESS( NtStatus = NTDLL$NtQuerySystemInformation(
        SystemProcessInformation, Procs, Size, &Size
    ) ) ) {
        PRINT_NT_ERROR( "NtQuerySystemInformation", NtStatus );
        return;
    }

    do {
        //
        // skip if the window is not visible
        //
        if ( ! USER32$IsWindowVisible( Window ) ) {
            continue;
        }

        //
        // get the length of the window name
        //
        Length = ( USER32$GetWindowTextLengthW( Window ) + 1 ) * sizeof( WCHAR );

        //
        // check there is a window name
        //
        if ( Length > 2 ) {
            //
            // get the window process pid
            //
            USER32$GetWindowThreadProcessId( Window, &ProcId );

            //
            // search the process
            //
            ProcInfo = Procs;
            Found    = FALSE;
            do {
                //
                // search for the process with that pid
                //
                if ( ProcInfo->UniqueProcessId == ProcId ) {
                    //
                    // found it
                    //
                    Found = TRUE;
                    break;
                }
            } while ( ( ProcInfo->NextEntryOffset ) &&
                      ( ProcInfo = C_PTR( ProcInfo ) + ProcInfo->NextEntryOffset ) );

            //
            // the process was not found, continue
            //
            if ( ! Found ) {
                continue;
            }

            //
            // get the window name
            //
            WindowName = MmAlloc( Length );
            USER32$GetWindowTextW( Window, WindowName, Length );

            //
            // do not print the default "Program Manager" window
            //
            if ( ! StringCompareW( WindowName, L"Program Manager" ) ) {
                //
                // print that window information
                //
                PRINTF( "=> Found window :\n  => Process : %ls\n  => Window  : %ls\n  => PID     : %ld\n\n",
                        ProcInfo->ImageName.Buffer, WindowName, ProcId );
            }

            //
            // free the memory
            //
            MmFree( WindowName );
        }
    } while ( ( Window = USER32$GetWindow( Window, GW_HWNDNEXT ) ) );

    MmFree( Procs );
}

VOID go(
    IN PCHAR args,
    IN ULONG argc
) {
    WindowsList();
}
