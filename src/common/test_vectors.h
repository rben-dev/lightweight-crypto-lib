/*------------------------ CeCILL-B HEADER ------------------------------------
    Copyright ANSSI and NTU (2014)
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


    This software is governed by the CeCILL-B license under French law and
    abiding by the rules of distribution of free software.  You can  use,
    modify and/ or redistribute the software under the terms of the CeCILL-B
    license as circulated by CEA, CNRS and INRIA at the following URL
    "http://www.cecill.info".

    As a counterpart to the access to the source code and  rights to copy,
    modify and redistribute granted by the license, users are provided only
    with a limited warranty  and the software's author,  the holder of the
    economic rights,  and the successive licensors  have only  limited
    liability.

    In this respect, the user's attention is drawn to the risks associated
    with loading,  using,  modifying and/or developing or reproducing the
    software by the user in light of its specific status of free software,
    that may mean  that it is complicated to manipulate,  and  that  also
    therefore means  that it is reserved for developers  and  experienced
    professionals having in-depth computer knowledge. Users are therefore
    encouraged to load and test the software's suitability as regards their
    requirements in conditions enabling the security of their systems and/or
    data to be ensured and,  more generally, to use and operate it in the
    same conditions as regards security.

    The fact that you are presently reading this means that you have had
    knowledge of the CeCILL-B license and that you accept its terms.

    The current source code is part of the common functions and headers 
    source tree.

    Project: Lightweight cryptography library
    File:    src/common/test_vectors.h

-------------------------- CeCILL-B HEADER ----------------------------------*/
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
