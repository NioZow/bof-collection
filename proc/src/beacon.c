#include <Defs.h>

typedef struct _row {
    void *         data; // pointer to the data
    unsigned short size; // size of the data
    struct _row *  next; // next row
} row, *prow;

typedef enum {
    COLUMN_PVOID,
    COLUMN_PSTR,
    COLUMN_PWSTR,
    COLUMN_NUMBER
} column_type;

typedef struct {
    char * *       columns;
    column_type *  types;
    unsigned short length;
    row *          first;
    unsigned short size;
} table;

void BeaconTableInit(
    table *        tab,
    char **        columns,
    column_type *  types,
    unsigned short length
) {
    tab->columns = columns;
    tab->types   = types;
    tab->length  = length;
}

void BeaconTableAddData(
    table *        tab,
    void *         data,
    unsigned short size
) {
    row *r = { 0 };

    if ( tab->first ) {
        // the table already has an element
        r = tab->first;

        do {
        } while ( r->next && ( r = r->next ) );

        // this is the last element
        r->next       = NTDLL$RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( row ) );
        r->next->data = data;
        r->next->size = size;
    } else {
        // the table does not have any element, create the first one
        tab->first       = NTDLL$RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( row ) );
        tab->first->data = data;
        tab->first->size = size;
    }
    tab->size++;
}

void memcpy_wchar(
    wchar_t *dest,
    wchar_t  ch,
    size_t   size
) {
    for ( size_t i = 0 ; i < size ; i++ ) {
        dest[ i ] = ch;
    }
}

void BeaconTablePrint(
    table *tab
) {
    row *           r          = { 0 };
    unsigned short *columns    = { 0 };
    unsigned short  length     = { 0 };
    unsigned short  index      = { 0 };
    wchar_t *       text       = { 0 };
    wchar_t *       textSpaces = { 0 };

    if ( ! tab->first ) {
        return;
    }

    r       = tab->first;
    columns = NTDLL$RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( short ) * tab->length );

    for ( unsigned short i = 0 ; i < tab->length ; i++ ) {
        columns[ i ] = MSVCRT$strlen( tab->columns[ i ] );
    }

    do {
        for ( unsigned short i = 0 ; i < tab->length ; i++ ) {
            // get the length of maximum length of each colum
            if ( tab->types[ i ] == COLUMN_PWSTR ) {
                // calculate offset properly
                text = *( ( PWSTR * ) r->data );

                if ( text ) {
                    length = MSVCRT$wcslen( *( PWSTR * ) ( r->data ) );

                    if ( length > columns[ i ] ) {
                        columns[ i ] = length;
                    }
                }
            }
        }
    } while ( r->next && ( r = r->next ) );

    r = tab->first;
    do {
        index = 0;

        for ( unsigned short i = 0 ; i < tab->length ; i++ ) {
            // get the length of maximum length of each colum
            if ( tab->types[ i ] == COLUMN_PWSTR ) {
                // calculate offset properly
                text       = *( ( PWSTR * ) ( r->data + index ) );
                textSpaces = NTDLL$RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY,
                                                    columns[ i ] * sizeof( wchar_t ) );

                if ( text ) {
                    length = MSVCRT$wcslen( text );

                    if ( length > columns[ i ] ) {
                        columns[ i ] = length;
                    }
                    MSVCRT$wcscpy( textSpaces, text );
                    memcpy_wchar( textSpaces + length, L' ', columns[ i ] - length );
                } else {
                    memcpy_wchar( textSpaces, L' ', columns[ i ] );
                }

                index += sizeof( wchar_t * );
                MSVCRT$printf( "%ls ", textSpaces );
            } else if ( tab->types[ i ] == COLUMN_NUMBER ) {
                // uncomplete should not use COLUMN_NUMBER cuz i do not know the length of the number
                // should do all for signed/unsigned
                MSVCRT$printf( "%lu ", *( unsigned long * ) ( r->data + index ) );
                index += sizeof( ULONG );
            }
        }

        MSVCRT$printf( "\n" );
    } while ( r->next && ( r = r->next ) );
}

/*!
 * @brief
 *  the string is not null terminated
 *
 * @param parser
 * @param name
 * @param size
 * @return
 */
/*
char *BeaconDataOptionExtract(
    datap *parser,
    char * name,
    int *  size
) {
    char *args   = parser->original;
    char *result = { 0 };
    char *space  = { 0 };
    int   index  = { 0 };

    do {
        space = strchr( args, ' ' );

        if ( ! space ) {
            return 0;
        }

        index = ( int ) ( space - args );

        if ( StrnCmp( name, args, index ) == 0 ) {
            result = strchr( args, ' ' );

            if ( ! result ) {
                return 0;
            }

            *size = ( int ) ( result - args );
            return result + 1;
        }
    } while ( *( args = space + 1 ) );

    return 0;
}

void BeaconDataParse( datap *parser, char *buffer, int size ) {
    if ( parser == NULL ) {
        return;
    }
    parser->original = buffer;
    parser->buffer   = buffer;
    parser->length   = size - 4;
    parser->size     = size - 4;
    parser->buffer += 4;
}
*/
