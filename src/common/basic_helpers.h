/*------------------------ CeCILL-B HEADER ------------------------------------
    Copyright ANSSI and NTU (2014)
    Contributors:
    Ryad BENADJILA [ryad.benadjila@ssi.gouv.fr] and
    Jian GUO [ntu.guo@gmail.com] and
    Victor LOMNE [victor.lomne@ssi.gouv.fr] and
    Thomas Peyrin [thomas.peyrin@gmail.com]

    This software is a computer program whose purpose is to implement
    lightweight block ciphers with different optimizations for the x86
    platform. Three algorithms have been implemented: PRESENT, LED and 
    Piccolo. Three techniques have been explored: table based 
    implementations, vperm (for vector permutation) and bitslice 
    implementations. For more details, please refer to the SAC 2013
    paper:
    http://eprint.iacr.org/2013/445
    as we as the documentation of the project.

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
    File:    src/common/basic_helpers.h

-------------------------- CeCILL-B HEADER ----------------------------------*/
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>
#include <sched.h>

#define GCC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)

#ifndef MAIN_INCLUDE
/* Includes useful for instrinsics */
#ifdef BITSLICE
/* For SSE2 */
#include <emmintrin.h>
#include <mmintrin.h>

/* For SSE3 and SSSE3 */
#include <pmmintrin.h>
#include <immintrin.h>
#endif
#endif

/* For thread-safety */
/* This is only useful for bitslice based implementations */
#ifdef THREAD_SAFE
#ifdef BITSLICE
#include <pthread.h>
extern pthread_mutex_t bitslice_init_mutex;
#endif
#endif

/* Stringifying macros for inline assembly */
#define tos(a)    #a
#define tostr(a)  tos(a)

/* Types definitions */
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t byte;
typedef uint8_t u8;
#ifndef MAIN_INCLUDE
#ifdef BITSLICE
typedef __m128i word;
#endif
#endif

/* Parallelism definition */
#define TABLE_P         1
#define VPERM_P         2
#define BITSLICE8_P     8
#define BITSLICE16_P    16
#define BITSLICE32_P    32

/* Key size in u16 basic type */
#define KEY64           4
#define KEY80           5
#define KEY128          8

/* Specific number of subkeys for ciphers */
#define LED64_SUBKEYS_SIZE 		(1  * sizeof(u64))
#define LED128_SUBKEYS_SIZE		(2  * sizeof(u64))
#define PRESENT80_SUBKEYS_SIZE          (32 * sizeof(u64))
#define PRESENT128_SUBKEYS_SIZE         (32 * sizeof(u64))
#define Piccolo80_SUBKEYS_SIZE          (27 * sizeof(u64))
#define Piccolo128_SUBKEYS_SIZE         (33 * sizeof(u64))

/* Context saving macros for inline assembly code */
#define Push_All_Regs() do{\
        asm("push rdx");\
        asm("push rcx");\
        asm("push rax");\
        asm("push rbx");\
}while(0);

#define Pop_All_Regs() do{\
        asm("pop rbx");\
        asm("pop rax");\
        asm("pop rcx");\
        asm("pop rdx");\
}while(0);

/******* Performance measurement helpers *********/

/* Number of samples for performance measurement */
#ifndef SAMPLES
#define SAMPLES (0x1ULL << 21)
#endif

#ifndef MAIN_INCLUDE
#ifdef MEASURE_PERF
/* Global variables to keep track of */
/* performance measurements          */
extern u64 key_schedule_start;
extern u64 key_schedule_end;
extern u64 encrypt_start;
extern u64 encrypt_end;
#endif
#endif

#ifdef MEASURE_PERF
inline static u64 rdtsc(){
#if defined(__i386__)
        u64 cycles;
        __asm__ volatile (".byte 0x0f, 0x31" : "=A"(cycles));
        return cycles;
#else
#if defined(__x86_64__)
        u32 hi, lo;
        __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
        return (((u64)lo) | ((u64)(hi) << 32));
#else
#error "Unsupported architecture for counting cycles"
#endif
#endif
}

/* Setting the CPU affinity */
inline static void setCPUaffinity(){
        int cpu_mask = 0x1;
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(cpu_mask, &set);
        if(sched_setaffinity(getpid(), sizeof(set), &set) == -1){
                printf("Impossible to set CPU affinity...\n");
        }
	return;
}
#endif
