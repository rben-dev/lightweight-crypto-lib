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
