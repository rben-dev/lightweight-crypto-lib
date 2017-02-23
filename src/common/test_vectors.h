/*------------------------ MIT License HEADER ------------------------------------
    Copyright ANSSI and NTU (2015)
    Contributors:
    Ryad BENADJILA [ryadbenadjila@gmail.com] and
    Jian GUO [ntu.guo@gmail.com] and
    Victor LOMNE [victor.lomne@gmail.com] and
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
/* Test vectors for all the ciphers */
/**** LED ***/
/* LED64 test vectors */
u64 test_vectorsLED64[] = {0x0ULL, 0xefcdab8967452301ULL};
u16 keys64LED64[sizeof(test_vectorsLED64)/sizeof(u64)][KEY64] = {{0}, {0x2301, 0x6745, 0xab89, 0xefcd}};
u64 test_vectorsLED64results[sizeof(test_vectorsLED64)/sizeof(u64)] = {0x98c7a0031040c239ULL, 0x58fc93381e5503a0ULL};
/* LED128 test vectors */
u64 test_vectorsLED128[] = {0x0ULL, 0xefcdab8967452301ULL};
u16 keys128LED128[sizeof(test_vectorsLED128)/sizeof(u64)][KEY128] = {{0}, {0x2301, 0x6745, 0xab89, 0xefcd, 0x2301, 0x6745, 0xab89, 0xefcd}};
u64 test_vectorsLED128results[sizeof(test_vectorsLED128)/sizeof(u64)] = {0xa1db0c85a0b2ec3dULL, 0xc24f017f5824b8d6ULL};

/*** PRESENT ***/
/* PRESENT80 test vectors */
u64 test_vectorsPRESENT80[] = {0x0ULL, 0x0ULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL};
u16 keys80PRESENT80[sizeof(test_vectorsPRESENT80)/sizeof(u64)][KEY80] = {{0},  {0xffff, 0xffff, 0xffff, 0xffff, 0xffff}, {0}, {0xffff, 0xffff, 0xffff, 0xffff, 0xffff}};
u64 test_vectorsPRESENT80results[sizeof(test_vectorsPRESENT80)/sizeof(u64)] = {0x4584227b38c17955ULL, 0x495094f5c0462ce7ULL, 0x7b41682fc7ff12a1ULL, 0xd2103221d3dc3333ULL};
/* PRESENT128 test vectors */
u64 test_vectorsPRESENT128[] = {0x0ULL};
u16 keys128PRESENT128[sizeof(test_vectorsPRESENT128)/sizeof(u64)][KEY128] = {{0}};
u64 test_vectorsPRESENT128results[sizeof(test_vectorsPRESENT128)/sizeof(u64)] = {0xaf00692e2a70db96ULL};

/*** Piccolo ***/
/* Piccolo80 test vectors */
u64 test_vectorsPiccolo80[] = {0xefcdab8967452301ULL, 0x517fe322009f2f67};
u16 keys80Piccolo80[sizeof(test_vectorsPiccolo80)/sizeof(u64)][KEY80] = {{0x1100, 0x3322, 0x5544, 0x7766, 0x9988}, {0x0fbb, 0x83f6, 0x94d5, 0xa445, 0x9120}};
u64 test_vectorsPiccolo80results[sizeof(test_vectorsPiccolo80)/sizeof(u64)] = {0x5640f83599ff2b8dULL, 0xccbf57920c60a302ULL};
/* Piccolo128 test vectors */
u64 test_vectorsPiccolo128[] = {0xefcdab8967452301ULL, 0x517fe322009f2f67};
u16 keys128Piccolo128[sizeof(test_vectorsPiccolo128)/sizeof(u64)][KEY128] = {{0x1100, 0x3322, 0x5544, 0x7766, 0x9988, 0xbbaa, 0xddcc, 0xffee}, {0x0fbb, 0x83f6, 0x94d5, 0xa445, 0x9120, 0x5926, 0x74f7, 0x7d76}};
u64 test_vectorsPiccolo128results[sizeof(test_vectorsPiccolo128)/sizeof(u64)] = {0xff897b65ea2cc45eULL, 0x6b806ca361beee6cULL};
