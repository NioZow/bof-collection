#include <Imperium.h>

/*
 * do not insert another function is that file it causes problems
 */

/*!
 * @brief
 *  function to start the program from assembly
 *  do not modify unless you are sure of what you are doing
 *  the entry for your payload should rather be the Main function
 *
 * @param Param
 *  parameters
 */
IMPERIUM_MAIN {
    PINSTANCE Instance = { 0 };
    PPVOID    MmAddr   = { 0 };
    PPEB      Peb      = NtCurrentPeb();

    //
    // check if there are enough heaps to hold our instance
    //
    if ( Peb->NumberOfHeaps >= Peb->MaximumNumberOfHeaps ) {
        return EXIT_FAILURE;
    }

    //
    // get the address of last heap to use to store a pointer to our instance
    //
    MmAddr = &Peb->ProcessHeaps[ Peb->NumberOfHeaps++ ];

    //
    // allocate memory for the instance
    //
    if ( ! ( *MmAddr = Instance = Imperium::mem::alloc( sizeof( INSTANCE ) ) ) ) {
        return EXIT_FAILURE;
    }

    //
    // set a context to find the instance struct in memory
    //
    Instance->Context = 0xc0debabe;

    //
    // get the base address of the current implant in memory and the end.
    // subtract the implant end address with the start address you will
    // get the size of the implant in memory
    //
    Instance->Base.Buffer = StRipStart();
    Instance->Base.Length = U_PTR( StRipEnd() ) - U_PTR( Instance->Base.Buffer );

    //
    // remove RtRipEnd code/instructions as
    // they are not needed anymore
    //
    Imperium::mem::zero( C_PTR( U_PTR( *MmAddr ) + sizeof( PVOID ) ), 0x18 );

    //
    // now execute the implant entrypoint
    //
    Main();
}
