/*------------------------ MIT License HEADER ------------------------------------
    Copyright ANSSI and NTU (2015)
    Contributors:
    Ryad BENADJILA [ryad.benadjila@ssi.gouv.fr] and
    Jian GUO [ntu.guo@gmail.com] and
    Victor LOMNE [victor.lomne@ssi.gouv.fr] and
    Thomas PEYRIN [thomas.peyrin@gmail.com]

    This software is a computer program whose purpose is to implement
    lightweight block ciphers with different optimizations for the x86
    platform. Three algorithms have been implemented: PRESENT, LED and 
    Piccolo. Three techniques have been explored: table based 
    implementations, vperm (for vector permutation) and bitslice 
    implementations. For more details, please refer to the SAC 2013
    paper:
    http://eprint.iacr.org/2013/445
    as well as the documentation of the project.
    Here is a big picture of how the code is divided:
      - src/common contains common headers, structures and functions.
      - src/table contains table based implementations, with the code 
        that generates the tables in src/table/gen_tables. The code here 
        is written in pure C so it should compile on any platform (x86  
        and other architectures), as well as any OS flavour (*nix, 
        Windows ...).
      - src/vperm contains vperm based implementations. They are written 
        in inline assembly for x86_64 and will only compile and work on 
        this platform. The code only compiles with gcc, but porting it to
        other assembly flavours should not be too complicated.
      - src/bitslice contains bitslice based implementations. They are 
        written in asm intrinsics. It should compile and run on i386 as 
        well as x86_64 platforms, and it should be portable to other OS 
        flavours since intrinsics are standard among many compilers.
    Note: vperm and bitslice implementations require a x86 CPU with at least 
    SSSE3 extensions.

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.

    Except as contained in this notice, the name(s) of the above copyright holders
    shall not be used in advertising or otherwise to promote the sale, use or other
    dealings in this Software without prior written authorization.


-------------------------- MIT License HEADER ----------------------------------*/
#ifdef VPERM
#include <common/basic_helpers.h>

#ifdef VPERM
#ifdef LED64
void LED64vperm_key_schedule(const u8* masterKey, u8* roundKeys);
__attribute__((noinline)) void LED64vperm_core(const u8* message, const u8* subkeys, u8* ciphertext);
void LED64vperm_cipher(const u64 plaintext_in[VPERM_P], const u16 keys_in[VPERM_P][KEY64], u64 ciphertext_out[VPERM_P]);
#endif
#ifdef LED128
void LED128vperm_key_schedule(const u8* masterKey, u8* roundKeys);
__attribute__((noinline)) void LED128vperm_core(const u8* message,  const u8* subkeys, u8* ciphertext);
void LED128vperm_cipher(const u64 plaintext_in[VPERM_P], const u16 keys_in[VPERM_P][KEY128], u64 ciphertext_out[VPERM_P]);
#endif
#endif

/* Desactivate arguments related warnings */
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif

/* LED format iput masks */
__attribute__((visibility("hidden"),aligned(16))) u8 FormInMask1_LED[] = {0xf0, 0xf0, 0x00, 0x00, 0xf0, 0xf0, 0x00, 0x00, 0xf0, 0xf0, 0x00, 0x00, 0xf0, 0xf0, 0x00, 0x00};
__attribute__((visibility("hidden"),aligned(16))) u8 FormInMask2_LED[] = {0x00, 0xff, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00};
__attribute__((visibility("hidden"),aligned(16))) u8 AndMaskL_LED[]    = {0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f};
__attribute__((visibility("hidden"),aligned(16))) u8 AndMaskH_LED[]    = {0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0};

/* LED four TBoxes */ 
__attribute__((visibility("hidden"),aligned(16))) u8 T1a_LED[] = {0xa5, 0xe7, 0x5b, 0x7a, 0x42, 0x00, 0xfe, 0x21, 0xbc, 0x9d, 0x19, 0xc6, 0x63, 0xdf, 0x84, 0x38};
__attribute__((visibility("hidden"),aligned(16))) u8 T1b_LED[] = {0xbd, 0xa1, 0xcf, 0x59, 0x1c, 0x00, 0x72, 0x96, 0x6e, 0xf8, 0xd3, 0x37, 0x8a, 0xe4, 0x2b, 0x45};
__attribute__((visibility("hidden"),aligned(16))) u8 T2a_LED[] = {0xec, 0xd5, 0x76, 0xfb, 0x39, 0x00, 0x9a, 0x8d, 0xa3, 0x2e, 0x4f, 0x58, 0xb4, 0x17, 0x61, 0xc2};
__attribute__((visibility("hidden"),aligned(16))) u8 T2b_LED[] = {0xb4, 0xa3, 0xc2, 0x58, 0x17, 0x00, 0x76, 0x9a, 0x61, 0xfb, 0xd5, 0x39, 0x8d, 0xec, 0x2e, 0x4f};
__attribute__((visibility("hidden"),aligned(16))) u8 T3a_LED[] = {0x9b, 0x2a, 0xdc, 0x15, 0xb1, 0x00, 0x47, 0xc9, 0xf6, 0x3f, 0x6d, 0xe3, 0x78, 0x8e, 0x52, 0xa4};
__attribute__((visibility("hidden"),aligned(16))) u8 T3b_LED[] = {0x81, 0x64, 0x49, 0x32, 0xe5, 0x00, 0xc8, 0x7b, 0x2d, 0x56, 0xac, 0x1f, 0x9e, 0xb3, 0xfa, 0xd7};
__attribute__((visibility("hidden"),aligned(16))) u8 T4a_LED[] = {0xeb, 0xda, 0x7c, 0xf5, 0x31, 0x00, 0x97, 0x89, 0xa6, 0x2f, 0x4d, 0x53, 0xb8, 0x1e, 0x62, 0xc4};
__attribute__((visibility("hidden"),aligned(16))) u8 T4b_LED[] = {0xd6, 0x1b, 0xf3, 0x9c, 0xcd, 0x00, 0x25, 0x6f, 0xe8, 0x87, 0x3e, 0x74, 0xa2, 0x4a, 0xb9, 0x51};


/* Masks */
__attribute__((visibility("hidden"),aligned(16))) u8 AndMask_LED[] = {0x0f, 0x00, 0x0f, 0x00, 0x0f, 0x00, 0x0f, 0x00, 0x0f, 0x00, 0x0f, 0x00, 0x0f, 0x00, 0x0f, 0x00};
__attribute__((visibility("hidden"),aligned(16))) u8 OrMask_LED[]  = {0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff};

/* Shuffling for ShiftRows */
__attribute__((visibility("hidden"),aligned(16))) u8 ShiftRowsT2a_LED[] = {2, 0xff, 4, 0xff, 6, 0xff, 0, 0xff, 10, 0xff, 12, 0xff, 14, 0xff, 8, 0xff};
__attribute__((visibility("hidden"),aligned(16))) u8 ShiftRowsT2b_LED[] = {0xff, 2, 0xff, 4, 0xff, 6, 0xff, 0, 0xff, 10, 0xff, 12, 0xff, 14, 0xff, 8};
__attribute__((visibility("hidden"),aligned(16))) u8 ShiftRowsT3a_LED[] = {4, 0xff, 6, 0xff, 0, 0xff, 2, 0xff, 12, 0xff, 14, 0xff, 8, 0xff, 10, 0xff};
__attribute__((visibility("hidden"),aligned(16))) u8 ShiftRowsT3b_LED[] = {0xff, 4, 0xff, 6, 0xff, 0, 0xff, 2, 0xff, 12, 0xff, 14, 0xff, 8, 0xff, 10};
__attribute__((visibility("hidden"),aligned(16))) u8 ShiftRowsT4a_LED[] = {6, 0xff, 0, 0xff, 2, 0xff, 4, 0xff, 14, 0xff, 8, 0xff, 10, 0xff, 12, 0xff};
__attribute__((visibility("hidden"),aligned(16))) u8 ShiftRowsT4b_LED[] = {0xff, 6, 0xff, 0, 0xff, 2, 0xff, 4, 0xff, 14, 0xff, 8, 0xff, 10, 0xff, 12};


#ifdef LED64
/* LED64 round constants for the 32 rounds */
__attribute__((visibility("hidden"),aligned(16))) const u8 RC64_LED[16*32] = {0x54, 0x32, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x70, 0x70, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x70, 0x70, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x71, 0x71, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x71, 0x71, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x73, 0x73, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x73, 0x73, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x67, 0x67, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x67, 0x67, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x57, 0x57, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x57, 0x57, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x37, 0x37, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x37, 0x37, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x76, 0x76, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x76, 0x76, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x75, 0x75, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x75, 0x75, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x63, 0x63, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x63, 0x63, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x47, 0x47, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x47, 0x47, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x17, 0x17, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x17, 0x17, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x36, 0x36, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x36, 0x36, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x74, 0x74, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x74, 0x74, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x61, 0x61, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x61, 0x61, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x53, 0x53, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x53, 0x53, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x27, 0x27, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x27, 0x27, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x56, 0x56, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x56, 0x56, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x35, 0x35, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x35, 0x35, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x62, 0x62, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x62, 0x62, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x45, 0x45, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x45, 0x45, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x06, 0x06, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x06, 0x06, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x14, 0x14, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x14, 0x14, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x20, 0x20, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x20, 0x20, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x50, 0x50, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x50, 0x50, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x31, 0x31, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x31, 0x31, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x72, 0x72, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x72, 0x72, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x65, 0x65, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x65, 0x65, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x43, 0x43, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x43, 0x43, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x07, 0x07, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32, 0x07, 0x07, 0x00, 0x00, 0x00, 0x00};
#endif

#ifdef LED128
/* LED128 round constants for the 32 rounds */
__attribute__((visibility("hidden"),aligned(16))) const u8 RC128_LED[16*48] = {0x98, 0x32, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x70, 0x70, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x70, 0x70, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x71, 0x71, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x71, 0x71, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x73, 0x73, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x73, 0x73, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x67, 0x67, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x67, 0x67, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x57, 0x57, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x57, 0x57, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x37, 0x37, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x37, 0x37, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x76, 0x76, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x76, 0x76, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x75, 0x75, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x75, 0x75, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x63, 0x63, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x63, 0x63, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x47, 0x47, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x47, 0x47, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x17, 0x17, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x17, 0x17, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x36, 0x36, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x36, 0x36, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x74, 0x74, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x74, 0x74, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x61, 0x61, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x61, 0x61, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x53, 0x53, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x53, 0x53, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x27, 0x27, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x27, 0x27, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x56, 0x56, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x56, 0x56, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x35, 0x35, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x35, 0x35, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x62, 0x62, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x62, 0x62, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x45, 0x45, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x45, 0x45, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x06, 0x06, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x06, 0x06, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x14, 0x14, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x14, 0x14, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x20, 0x20, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x20, 0x20, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x50, 0x50, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x50, 0x50, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x31, 0x31, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x31, 0x31, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x72, 0x72, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x72, 0x72, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x65, 0x65, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x65, 0x65, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x43, 0x43, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x43, 0x43, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x07, 0x07, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x07, 0x07, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x16, 0x16, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x16, 0x16, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x34, 0x34, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x34, 0x34, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x60, 0x60, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x60, 0x60, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x51, 0x51, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x51, 0x51, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x33, 0x33, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x33, 0x33, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x55, 0x55, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x55, 0x55, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x23, 0x23, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x23, 0x23, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x15, 0x15, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x15, 0x15, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x22, 0x22, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x22, 0x22, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x44, 0x44, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x44, 0x44, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x12, 0x12, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x12, 0x12, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x24, 0x24, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x24, 0x24, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x40, 0x40, 0x00, 0x00, 0x00, 0x00, 0x98, 0x32, 0x40, 0x40, 0x00, 0x00, 0x00, 0x00};
#endif

/* gp register allocation */
#define Plaintext_	rdi
#define Ciphertext_	rdx
#define Keys_	 	rsi
#define RoundCounter_	rcx
#define RCBase_		r10
#ifdef AVX
  /* xmm register allocation */
  #define T1a_LED_	xmm0
  #define T1b_LED_	xmm1
  #define T2a_LED_  	xmm2
  #define T2b_LED_  	xmm3
  #define T3a_LED_ 	xmm4
  #define T3b_LED_	xmm5
  #define T4a_LED_	xmm6
  #define T4b_LED_	xmm7
  #define State_	xmm8
  #define OrMask_LED_	xmm9
  #define AndMask_LED_	xmm10
  #define TmpAccu_	xmm11
  #define Tmp2_		xmm12
  #define Tmp3_		xmm13
  #define Tmp4_		xmm14
  #define Tmp5_		xmm15
#else
  /* xmm register allocation */
  #define T1a_LED_	xmm0
  #define T1b_LED_	xmm1
  #define T2a_LED_  	xmm2
  #define T2b_LED_  	xmm3
  #define T3a_LED_ 	xmm4
  #define T3b_LED_	xmm5
  #define T4a_LED_	xmm6
  #define T4b_LED_	xmm7
  #define State_	xmm8
  #define OrMask_LED_	xmm9
  #define AndMask_LED_	xmm10
  #define TmpAccu_	xmm11
  #define Tmp2_		xmm12
  #define Tmp3_		xmm13
  #define Tmp4_		xmm14
  #define Tmp5_		xmm15
#endif

#ifdef AVX
  #define LEDROUND LEDROUND_AVX
  #define bit_permute_step64 bit_permute_step64_AVX
  #define format_input format_input_AVX
  #define format_output format_output_AVX
#else
  #define LEDROUND LEDROUND_SSSE
  #define bit_permute_step64 bit_permute_step64_SSSE
  #define format_input format_input_SSSE
  #define format_output format_output_SSSE
#endif

/* ---------------------------------------------------------*/
/* ---------------------- SSSE -----------------------------*/
/* ---------------------------------------------------------*/
/* The bit_permute_step primitive */
/* SSSE primitive */
#define bit_permute_step64_SSSE(in, out, mask, shift, tmp1) do {\
	asm("movdqa "tostr(tmp1)", "tostr(in)"");\
	asm("psrlq "tostr(tmp1)", "tostr(shift)"");\
	asm("pxor   "tostr(tmp1)", "tostr(in)"");\
	asm("pand   "tostr(tmp1)", [rip + "tostr(mask)"]");\
	asm("movdqa "tostr(out)",  "tostr(tmp1)"");\
	asm("psllq "tostr(out)",  "tostr(shift)"");\
	asm("pxor   "tostr(tmp1)", "tostr(in)"");\
	asm("pxor   "tostr(out)",  "tostr(tmp1)"");\
} while(0);


#define nibble_exchange_SSSE(in, tmp) do {\
        asm("movdqa "tostr(tmp)",  "tostr(in)"");\
        asm("pand "tostr(in)",  [rip + "tostr(AndMaskL_LED)"]");\
        asm("pand "tostr(tmp)",  [rip + "tostr(AndMaskH_LED)"]");\
        asm("psllq "tostr(in)",  "tostr(4)"");\
        asm("psrlq "tostr(tmp)",  "tostr(4)"");\
        asm("pxor "tostr(in)",  "tostr(tmp)"");\
} while(0) 

#define format_input_SSSE(in) do {\
	nibble_exchange_SSSE(in, Tmp3_);\
	bit_permute_step64_SSSE(in, Tmp2_, FormInMask1_LED, 12, Tmp3_);\
	bit_permute_step64_SSSE(Tmp2_, in, FormInMask2_LED, 24, Tmp3_);\
} while(0);

#define format_output_SSSE(in) do {\
	bit_permute_step64_SSSE(in, Tmp2_, FormInMask1_LED, 12, Tmp3_);\
	bit_permute_step64_SSSE(Tmp2_, in, FormInMask2_LED, 24, Tmp3_);\
	nibble_exchange_SSSE(in, Tmp3_);\
} while(0);

#define LEDROUND_SSSE() do {\
	/* ----------------------------------- */\
	/* AddRoundKey*/\
	asm("pxor "tostr(State_)", ["tostr(RCBase_)"+"tostr(RoundCounter_)"]");\
	asm("add  "tostr(RoundCounter_)", 16");\
	/* ----------------------------------- */\
	/* T1 lookup */\
	/* Get T1a_LED and T1b_LED tables */\
	asm("movdqa  "tostr(TmpAccu_)", "tostr(T1a_LED_)"");\
	asm("movdqa  "tostr(Tmp2_)", "tostr(T1b_LED_)"");\
	/* Save state */\
	asm("movdqa  "tostr(Tmp3_)", "tostr(State_)"");\
	/* Apply masks */\
	asm("pand  "tostr(Tmp3_)", "tostr(AndMask_LED_)"");\
	asm("por   "tostr(Tmp3_)", "tostr(OrMask_LED_)"");\
	/* Get T1a_LED[] for the first nibble */\
	asm("pshufb "tostr(TmpAccu_)", "tostr(Tmp3_)"");\
	/* Get T1b_LED[] for the first nibble */\
	asm("pshufb "tostr(Tmp2_)", "tostr(Tmp3_)"");\
	/* Shift T1b_LED and accumulate in TmpAccu_ */\
	asm("psllw  "tostr(Tmp2_)", 8");\
	asm("pxor   "tostr(TmpAccu_)", "tostr(Tmp2_)"");\
\
	/* ----------------------------------- */\
	/* T2 lookup */\
	/* Get T2a_LED and T2b_LED tables */\
	asm("movdqa  "tostr(Tmp4_)", "tostr(T2a_LED_)"");\
	asm("movdqa  "tostr(Tmp2_)", "tostr(T2b_LED_)"");\
	/* Save state */\
	asm("psrlw   "tostr(State_)", 4");\
	asm("movdqa  "tostr(Tmp3_)", "tostr(State_)"");\
	/* Apply masks */\
	asm("pand  "tostr(Tmp3_)", "tostr(AndMask_LED_)"");\
	asm("por   "tostr(Tmp3_)", "tostr(OrMask_LED_)"");\
	/* Get T1a_LED[] for the first nibble */\
	asm("pshufb "tostr(Tmp4_)", "tostr(Tmp3_)"");\
	/* Get T1b_LED[] for the first nibble */\
	asm("pshufb "tostr(Tmp2_)", "tostr(Tmp3_)"");\
	/* ShiftRows and accumulate in TmpAccu_ */\
	asm("pshufb "tostr(Tmp4_)", [rip + "tostr(ShiftRowsT2a_LED)"]");\
	asm("pxor   "tostr(TmpAccu_)", "tostr(Tmp4_)"");\
	asm("pshufb "tostr(Tmp2_)", [rip + "tostr(ShiftRowsT2b_LED)"]");\
	asm("pxor   "tostr(TmpAccu_)", "tostr(Tmp2_)"");\
	/* ----------------------------------- */\
	/* T3 lookup */\
	/* Get T3a_LED and T3b_LED tables */\
	asm("movdqa  "tostr(Tmp4_)", "tostr(T3a_LED_)"");\
	asm("movdqa  "tostr(Tmp2_)", "tostr(T3b_LED_)"");\
	/* Save state */\
	asm("psrlw   "tostr(State_)", 4");\
	asm("movdqa  "tostr(Tmp3_)", "tostr(State_)"");\
	/* Apply masks */\
	asm("pand  "tostr(Tmp3_)", "tostr(AndMask_LED_)"");\
	asm("por   "tostr(Tmp3_)", "tostr(OrMask_LED_)"");\
	/* Get T1a_LED[] for the first nibble */\
	asm("pshufb "tostr(Tmp4_)", "tostr(Tmp3_)"");\
	/* Get T1b_LED[] for the first nibble */\
	asm("pshufb "tostr(Tmp2_)", "tostr(Tmp3_)"");\
	/* ShiftRows and accumulate in TmpAccu_ */\
	asm("pshufb "tostr(Tmp4_)", [rip + "tostr(ShiftRowsT3a_LED)"]");\
	asm("pxor   "tostr(TmpAccu_)", "tostr(Tmp4_)"");\
	asm("pshufb "tostr(Tmp2_)", [rip + "tostr(ShiftRowsT3b_LED)"]");\
	asm("pxor   "tostr(TmpAccu_)", "tostr(Tmp2_)"");\
	/* ----------------------------------- */\
	/* T4 lookup */\
	/* Get T4a_LED and T4b_LED tables */\
	asm("movdqa  "tostr(Tmp4_)", "tostr(T4a_LED_)"");\
	asm("movdqa  "tostr(Tmp2_)", "tostr(T4b_LED_)"");\
	/* Save state */\
	asm("psrlw   "tostr(State_)", 4");\
	asm("movdqa  "tostr(Tmp3_)", "tostr(State_)"");\
	/* Get accumulator in state */\
	asm("movdqa  "tostr(State_)", "tostr(TmpAccu_)"");\
	/* Apply masks, no need for "and" mask (last nibble) */\
	asm("por   "tostr(Tmp3_)", "tostr(OrMask_LED_)"");\
	/* Get T1a_LED[] for the first nibble */\
	asm("pshufb "tostr(Tmp4_)", "tostr(Tmp3_)"");\
	/* Get T1b_LED[] for the first nibble */\
	asm("pshufb "tostr(Tmp2_)", "tostr(Tmp3_)"");\
	/* ShiftRows and accumulate in TmpAccu_ */\
	asm("pshufb "tostr(Tmp4_)", [rip + "tostr(ShiftRowsT4a_LED)"]");\
	asm("pxor   "tostr(State_)", "tostr(Tmp4_)"");\
	asm("pshufb "tostr(Tmp2_)", [rip + "tostr(ShiftRowsT4b_LED)"]");\
	asm("pxor   "tostr(State_)", "tostr(Tmp2_)"");\
	/* Result is put back in the state */\
} while(0);


/* ---------------------------------------------------------*/
/* ---------------------- AVX ------------------------------*/
/* ---------------------------------------------------------*/
/* The bit_permute_step primitive */
/* AVX primitive */
#define bit_permute_step64_AVX(in, out, mask, shift, tmp1) do {\
	asm("vpsrlq  "tostr(tmp1)", "tostr(in)", "tostr(shift)"");\
	asm("pxor    "tostr(tmp1)", "tostr(in)"");\
	asm("pand    "tostr(tmp1)", [rip + "tostr(mask)"]");\
	asm("vpsllq  "tostr(out)",  "tostr(tmp1)", "tostr(shift)"");\
	asm("pxor    "tostr(tmp1)", "tostr(in)"");\
	asm("pxor    "tostr(out)",  "tostr(tmp1)"");\
} while(0);

#define nibble_exchange_AVX(in, tmp) do {\
        asm("vpand "tostr(tmp)",  "tostr(in)", [rip + "tostr(AndMaskH_LED)"]");\
        asm("pand "tostr(in)",  [rip + "tostr(AndMaskL_LED)"]");\
        asm("psrlq "tostr(tmp)",  "tostr(4)"");\
        asm("psllq "tostr(in)",  "tostr(4)"");\
        asm("pxor "tostr(in)",  "tostr(tmp)"");\
} while(0) 

#define format_input_AVX(in) do {\
	nibble_exchange_AVX(in, Tmp3_);\
	bit_permute_step64_AVX(in, Tmp2_, FormInMask1_LED, 12, Tmp3_);\
	bit_permute_step64_AVX(Tmp2_, in, FormInMask2_LED, 24, Tmp3_);\
} while(0);

#define format_output_AVX(in) do {\
	bit_permute_step64_AVX(in, Tmp2_, FormInMask1_LED, 12, Tmp3_);\
	bit_permute_step64_AVX(Tmp2_, in, FormInMask2_LED, 24, Tmp3_);\
	nibble_exchange_AVX(in, Tmp3_);\
} while(0);

#define LEDROUND_AVX() do {\
	/* ----------------------------------- */\
	/* AddRoundKey*/\
	asm("pxor "tostr(State_)", ["tostr(RCBase_)"+"tostr(RoundCounter_)"]");\
	asm("add  "tostr(RoundCounter_)", 16");\
	/* ----------------------------------- */\
	/* T1 lookup */\
	/* Get T1a_LED and T1b_LED tables */\
	/* Save state */\
	/* Apply masks */\
	asm("vpand  "tostr(Tmp3_)", "tostr(State_)", "tostr(AndMask_LED_)"");\
	asm("por   "tostr(Tmp3_)", "tostr(OrMask_LED_)"");\
	/* Get T1a_LED[] for the first nibble */\
	asm("vpshufb "tostr(TmpAccu_)", "tostr(T1a_LED_)", "tostr(Tmp3_)"");\
	/* Get T1b_LED[] for the first nibble */\
	asm("vpshufb "tostr(Tmp2_)", "tostr(T1b_LED_)", "tostr(Tmp3_)"");\
	/* Shift T1b_LED and accumulate in TmpAccu_ */\
	asm("psllw  "tostr(Tmp2_)", 8");\
	asm("pxor   "tostr(TmpAccu_)", "tostr(Tmp2_)"");\
\
	/* ----------------------------------- */\
	/* T2 lookup */\
	/* Get T2a_LED and T2b_LED tables */\
	/* Save state */\
	asm("psrlw   "tostr(State_)", 4");\
	/* Apply masks */\
	asm("vpand  "tostr(Tmp3_)", "tostr(State_)", "tostr(AndMask_LED_)"");\
	asm("por   "tostr(Tmp3_)", "tostr(OrMask_LED_)"");\
	/* Get T1a_LED[] for the first nibble */\
	asm("vpshufb "tostr(Tmp4_)",  "tostr(T2a_LED_)", "tostr(Tmp3_)"");\
	/* Get T1b_LED[] for the first nibble */\
	asm("vpshufb "tostr(Tmp2_)",  "tostr(T2b_LED_)", "tostr(Tmp3_)"");\
	/* ShiftRows and accumulate in TmpAccu_ */\
	asm("pshufb "tostr(Tmp4_)", [rip + "tostr(ShiftRowsT2a_LED)"]");\
	asm("pxor   "tostr(TmpAccu_)", "tostr(Tmp4_)"");\
	asm("pshufb "tostr(Tmp2_)", [rip + "tostr(ShiftRowsT2b_LED)"]");\
	asm("pxor   "tostr(TmpAccu_)", "tostr(Tmp2_)"");\
	/* ----------------------------------- */\
	/* T3 lookup */\
	/* Get T3a_LED and T3b_LED tables */\
	/* Save state */\
	asm("psrlw   "tostr(State_)", 4");\
	/* Apply masks */\
	asm("vpand  "tostr(Tmp3_)", "tostr(State_)", "tostr(AndMask_LED_)"");\
	asm("por   "tostr(Tmp3_)", "tostr(OrMask_LED_)"");\
	/* Get T1a_LED[] for the first nibble */\
	asm("vpshufb "tostr(Tmp4_)", "tostr(T3a_LED_)", "tostr(Tmp3_)"");\
	/* Get T1b_LED[] for the first nibble */\
	asm("vpshufb "tostr(Tmp2_)", "tostr(T3b_LED_)", "tostr(Tmp3_)"");\
	/* ShiftRows and accumulate in TmpAccu_ */\
	asm("pshufb "tostr(Tmp4_)", [rip + "tostr(ShiftRowsT3a_LED)"]");\
	asm("pxor   "tostr(TmpAccu_)", "tostr(Tmp4_)"");\
	asm("pshufb "tostr(Tmp2_)", [rip + "tostr(ShiftRowsT3b_LED)"]");\
	asm("pxor   "tostr(TmpAccu_)", "tostr(Tmp2_)"");\
	/* ----------------------------------- */\
	/* T4 lookup */\
	/* Get T4a_LED and T4b_LED tables */\
	/* Save state */\
	asm("psrlw   "tostr(State_)", 4");\
	/* Get accumulator in state */\
	/* Apply masks, no need for "and" mask (last nibble) */\
	asm("vpor   "tostr(Tmp3_)", "tostr(State_)", "tostr(OrMask_LED_)"");\
	/* Get T1a_LED[] for the first nibble */\
	asm("vpshufb "tostr(Tmp4_)", "tostr(T4a_LED_)", "tostr(Tmp3_)"");\
	/* Get T1b_LED[] for the first nibble */\
	asm("vpshufb "tostr(Tmp2_)", "tostr(T4b_LED_)", "tostr(Tmp3_)"");\
	/* ShiftRows and accumulate in TmpAccu_ */\
	asm("pshufb "tostr(Tmp4_)", [rip + "tostr(ShiftRowsT4a_LED)"]");\
	asm("pxor   "tostr(TmpAccu_)", "tostr(Tmp4_)"");\
	asm("pshufb "tostr(Tmp2_)", [rip + "tostr(ShiftRowsT4b_LED)"]");\
	asm("vpxor   "tostr(State_)", "tostr(TmpAccu_)", "tostr(Tmp2_)"");\
	/* Result is put back in the state */\
} while(0);

#ifdef LED64
void LED64vperm_key_schedule(const u8* masterKey, u8* roundKeys){
	/* There is NO key schedule for LED */
	memcpy(roundKeys, masterKey, VPERM_P * KEY64 * sizeof(u16));
	return;
}

/* LED main encryption block: it supposes that the scheduled 
   keys are in memory pointed by the second argument */
__attribute__((noinline)) void LED64vperm_core(const u8* message, const u8* subkeys, u8* ciphertext)
{
        /*      Note : message is in rdi, subkeys in rsi and ciphertext in rdx  */
        /*      __cdecl calling convention                                      */
	asm (".intel_syntax noprefix");
	Push_All_Regs();
	/* Key Index */
	asm("xor "tostr(RoundCounter_)", "tostr(RoundCounter_)"");
		
	asm("lea "tostr(RCBase_)", [rip + RC64_LED]");
	/* Load constants (TBoxes) */
	asm("movdqa  "tostr(T1a_LED_)", [rip + T1a_LED]");
	asm("movdqa  "tostr(T1b_LED_)", [rip + T1b_LED]");
	asm("movdqa  "tostr(T2a_LED_)", [rip + T2a_LED]");
	asm("movdqa  "tostr(T2b_LED_)", [rip + T2b_LED]");
	asm("movdqa  "tostr(T3a_LED_)", [rip + T3a_LED]");
	asm("movdqa  "tostr(T3b_LED_)", [rip + T3b_LED]");
	asm("movdqa  "tostr(T4a_LED_)", [rip + T4a_LED]");
	asm("movdqa  "tostr(T4b_LED_)", [rip + T4b_LED]");

	/* Load the the And mask */
	asm("movdqa  "tostr(AndMask_LED_)", [rip + AndMask_LED]");
	asm("movdqa  "tostr(OrMask_LED_)", [rip + OrMask_LED]");
	/* Load the message */
	asm("movdqa  "tostr(State_)", ["tostr(Plaintext_)"]");

	/* Transform the message from line wise to column wise */
	format_input(State_);
	/* Transform the keys from line wise to column wise */
	asm("movdqa "tostr(Tmp4_)", ["tostr(Keys_)"]");
	format_input(Tmp4_);
	asm("movdqa ["tostr(Keys_)"], "tostr(Tmp4_)"");

	asm("pxor "tostr(State_)", ["tostr(Keys_)"]");
	LEDROUND();
	LEDROUND();
	LEDROUND();
	LEDROUND();
	asm("pxor "tostr(State_)", ["tostr(Keys_)"]");
	LEDROUND();
	LEDROUND();
	LEDROUND();
	LEDROUND();

	asm("pxor "tostr(State_)", ["tostr(Keys_)"]");
	LEDROUND();
	LEDROUND();
	LEDROUND();
	LEDROUND();
	asm("pxor "tostr(State_)", ["tostr(Keys_)"]");
	LEDROUND();
	LEDROUND();
	LEDROUND();
	LEDROUND();

	asm("pxor "tostr(State_)", ["tostr(Keys_)"]");
	LEDROUND();
	LEDROUND();
	LEDROUND();
	LEDROUND();
	asm("pxor "tostr(State_)", ["tostr(Keys_)"]");
	LEDROUND();
	LEDROUND();
	LEDROUND();
	LEDROUND();

	asm("pxor "tostr(State_)", ["tostr(Keys_)"]");
	LEDROUND();
	LEDROUND();
	LEDROUND();
	LEDROUND();
	asm("pxor "tostr(State_)", ["tostr(Keys_)"]");
	LEDROUND();
	LEDROUND();
	LEDROUND();
	LEDROUND();
	asm("pxor "tostr(State_)", ["tostr(Keys_)"]");

	/* Transform the message back from column wise to line wise */
	format_output(State_);
	
	/* Move back the result in the input message */
	asm("movdqa ["tostr(Ciphertext_)"], "tostr(State_)"");

	Pop_All_Regs();
	asm (".att_syntax noprefix");

	return;
}

/* LED64 vperm: two plaintexts and two keys as input  */
void LED64vperm_cipher(const u64 plaintext_in[VPERM_P], const u16 keys_in[VPERM_P][KEY64], u64 ciphertext_out[VPERM_P]){
        /* 128-bit aligned buffers for xmm memory load   */
        __attribute__ ((aligned (16))) u8 subkeys[VPERM_P * KEY64 * sizeof(u16)];
        __attribute__ ((aligned (16))) u8 keys[VPERM_P * KEY64 * sizeof(u16)];
        __attribute__ ((aligned (16))) u8 plaintext[VPERM_P * sizeof(u64)];
        __attribute__ ((aligned (16))) u8 ciphertext[VPERM_P * sizeof(u64)];

        /* Copy the input to the aligned buffers */
        memcpy(plaintext, plaintext_in, sizeof(plaintext));
        memcpy(keys, keys_in, sizeof(keys));

	/* The key schedule does merely nothing ... */
#ifdef MEASURE_PERF
        key_schedule_start = 0;
#endif
	LED64vperm_key_schedule(keys, subkeys);	
#ifdef MEASURE_PERF
        key_schedule_end = 0;
#endif

#ifdef MEASURE_PERF
        encrypt_start = rdtsc();
#endif
        /* There is *NO* keyschedule for LED */
        /* Call the core encryption */
        LED64vperm_core(plaintext, subkeys, ciphertext);
#ifdef MEASURE_PERF
        encrypt_end = rdtsc();
#endif

        /* Copy back the result */
        memcpy(ciphertext_out, ciphertext, sizeof(ciphertext));

        return;
}
#endif

#ifdef LED128
void LED128vperm_key_schedule(const u8* masterKey, u8* roundKeys){
	/* There is NO key schedule for LED */
	memcpy(roundKeys, masterKey, VPERM_P * KEY128 * sizeof(u16));
	return;
}

/* LED main encryption block: it supposes that the scheduled 
   keys are in memory pointed by the second argument */
__attribute__((noinline)) void LED128vperm_core(const u8* message,  const u8* subkeys, u8* ciphertext)
{
        /*      Note : message is in rdi, subkeys in rsi and ciphertext in rdx  */
        /*      __cdecl calling convention                                      */
	asm (".intel_syntax noprefix");\
	Push_All_Regs();
	/* Key Index */
	asm("xor "tostr(RoundCounter_)", "tostr(RoundCounter_)"");
	asm("lea "tostr(RCBase_)", [rip + RC128_LED]");
	/* Load constants (TBoxes) */
	asm("movdqa  "tostr(T1a_LED_)", [rip + T1a_LED]");
	asm("movdqa  "tostr(T1b_LED_)", [rip + T1b_LED]");
	asm("movdqa  "tostr(T2a_LED_)", [rip + T2a_LED]");
	asm("movdqa  "tostr(T2b_LED_)", [rip + T2b_LED]");
	asm("movdqa  "tostr(T3a_LED_)", [rip + T3a_LED]");
	asm("movdqa  "tostr(T3b_LED_)", [rip + T3b_LED]");
	asm("movdqa  "tostr(T4a_LED_)", [rip + T4a_LED]");
	asm("movdqa  "tostr(T4b_LED_)", [rip + T4b_LED]");

	/* Load the the And mask */
	asm("movdqa  "tostr(AndMask_LED_)", [rip + AndMask_LED]");
	asm("movdqa  "tostr(OrMask_LED_)", [rip + OrMask_LED]");
	/* Load the message */
	asm("movdqa  "tostr(State_)", ["tostr(Plaintext_)"]");

	/* Transform the message from line wise to column wise */
	format_input(State_);
	/* Transform the keys from line wise to column wise */
	asm("movdqa "tostr(Tmp4_)", ["tostr(Keys_)"]");
	format_input(Tmp4_);
	asm("movdqa ["tostr(Keys_)"], "tostr(Tmp4_)"");
	asm("movdqa "tostr(Tmp4_)", ["tostr(Keys_)"+16]");
	format_input(Tmp4_);
	asm("movdqa ["tostr(Keys_)"+16], "tostr(Tmp4_)"");
	/* Interleave the half keys */
	asm("mov rax, ["tostr(Keys_)"+8]");
	asm("mov rbx, ["tostr(Keys_)"+16]");
	asm("mov ["tostr(Keys_)"+16], rax");
	asm("mov ["tostr(Keys_)"+8], rbx");

	asm("pxor "tostr(State_)", ["tostr(Keys_)"]");
	LEDROUND();
	LEDROUND();
	LEDROUND();
	LEDROUND();
	asm("pxor "tostr(State_)", ["tostr(Keys_)"+16]");
	LEDROUND();
	LEDROUND();
	LEDROUND();
	LEDROUND();

	asm("pxor "tostr(State_)", ["tostr(Keys_)"]");
	LEDROUND();
	LEDROUND();
	LEDROUND();
	LEDROUND();
	asm("pxor "tostr(State_)", ["tostr(Keys_)"+16]");
	LEDROUND();
	LEDROUND();
	LEDROUND();
	LEDROUND();

	asm("pxor "tostr(State_)", ["tostr(Keys_)"]");
	LEDROUND();
	LEDROUND();
	LEDROUND();
	LEDROUND();
	asm("pxor "tostr(State_)", ["tostr(Keys_)"+16]");
	LEDROUND();
	LEDROUND();
	LEDROUND();
	LEDROUND();

	asm("pxor "tostr(State_)", ["tostr(Keys_)"]");
	LEDROUND();
	LEDROUND();
	LEDROUND();
	LEDROUND();
	asm("pxor "tostr(State_)", ["tostr(Keys_)"+16]");
	LEDROUND();
	LEDROUND();
	LEDROUND();
	LEDROUND();

	asm("pxor "tostr(State_)", ["tostr(Keys_)"]");
	LEDROUND();
	LEDROUND();
	LEDROUND();
	LEDROUND();
	asm("pxor "tostr(State_)", ["tostr(Keys_)"+16]");
	LEDROUND();
	LEDROUND();
	LEDROUND();
	LEDROUND();

	asm("pxor "tostr(State_)", ["tostr(Keys_)"]");
	LEDROUND();
	LEDROUND();
	LEDROUND();
	LEDROUND();
	asm("pxor "tostr(State_)", ["tostr(Keys_)"]+16");
	LEDROUND();
	LEDROUND();
	LEDROUND();
	LEDROUND();
	asm("pxor "tostr(State_)", ["tostr(Keys_)"]");

	/* Transform the message back from column wise to line wise */
	format_output(State_);
	
	/* Move back the result in the input message */
	asm("movdqa ["tostr(Ciphertext_)"], "tostr(State_)"");

	Pop_All_Regs();
	asm (".att_syntax noprefix");

	return;
}

/* LED128 vperm: two plaintexts and two keys as input  */
void LED128vperm_cipher(const u64 plaintext_in[VPERM_P], const u16 keys_in[VPERM_P][KEY128], u64 ciphertext_out[VPERM_P]){
        /* 128-bit aligned buffers for xmm memory load   */
        __attribute__ ((aligned (16))) u8 subkeys[VPERM_P * KEY128 * sizeof(u16)];
        __attribute__ ((aligned (16))) u8 keys[VPERM_P * KEY128 * sizeof(u16)];
        __attribute__ ((aligned (16))) u8 plaintext[VPERM_P * sizeof(u64)];
        __attribute__ ((aligned (16))) u8 ciphertext[VPERM_P * sizeof(u64)];

        /* Copy the input to the aligned buffers */
        memcpy(plaintext, plaintext_in, sizeof(plaintext));
        memcpy(keys, keys_in, sizeof(keys));

	/* The key schedule does merely nothing ... */
#ifdef MEASURE_PERF
        key_schedule_start = 0;
#endif
	LED128vperm_key_schedule(keys, subkeys);	
#ifdef MEASURE_PERF
        key_schedule_end = 0;
#endif

#ifdef MEASURE_PERF
        encrypt_start = rdtsc();
#endif
        /* There is *NO* keyschedule for LED */
        /* Call the core encryption          */
        LED128vperm_core(plaintext, subkeys, ciphertext);
#ifdef MEASURE_PERF
        encrypt_end = rdtsc();
#endif

        /* Copy back the result */
        memcpy(ciphertext_out, ciphertext, sizeof(ciphertext));

        return;
}
#endif

/* Reactivate arguments related warnings */
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif
#endif
