#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import pefile
import argparse
import hashlib

STARDUST_END : bytes = b'STARDUST-END'
PAGE_SIZE    : int   = 0x1000

##
## calculates the given size to pages
##
def size_to_pages( size: int ) -> int:
    PAGE_MASK       : int = 0xfff
    BASE_PAGE_SHIFT : int = 12

    return ( size >> BASE_PAGE_SHIFT ) + ( ( size & PAGE_MASK ) != 0 )

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()

    # Read the file in chunks to handle large files
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)

    return sha256_hash.hexdigest()

##
## parse specified executable file and
## save .text section shellcode into a file
##
def main() -> None:
    parser = argparse.ArgumentParser( description = 'Extracts shellcode from a PE.' )
    parser.add_argument( '-f', required = True,  help = 'Path to the source executable', type = str )
    parser.add_argument( '-o', required = True,  help = 'Path to store the output raw binary', type = str )
    option = parser.parse_args()

    executable  = pefile.PE( option.f )
    shellcode   = bytearray( executable.sections[ 0 ].get_data() )
    shellcode   = shellcode[ : shellcode.find( STARDUST_END ) ]
    size        = len( shellcode )

    ##
    ## calculate pages
    ##
    pages    = size_to_pages( size )
    padding  = ( ( pages * PAGE_SIZE ) - size )

    ##
    ## fill the padding to have a full page
    ##
    for i in range( padding ):
        shellcode.append( 0 )

    ##
    ## get size of shellcode
    ##
    size = len( shellcode )

    ##
    ## open shellcode file
    ##
    file = open( option.o, 'wb+' )

    ##
    ## write shellcode to file
    ##
    file.write( shellcode )
    file.close()

    ##
    ## get the sha256 hash of the shellcode
    ##
    hash = calculate_sha256( option.o )

    ##
    ## print metadata
    ##
    print( f"[*] payload len : { size - padding } bytes" )
    print( f"[*] size        : { size } bytes" )
    print( f"[*] padding     : { padding } bytes" )
    print( f"[*] page count  : { size / PAGE_SIZE } pages" )
    print( f"[*] sha256sum   : { hash }" )

    return

if __name__ in '__main__':
    main()