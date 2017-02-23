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
#ifdef BITSLICE
#include "PRESENT_utils.h"

#ifdef BITSLICE
#ifdef PRESENT80
void PRESENT80bitslice8_key_schedule(const u8* masterKey, u8* roundKeys);
void PRESENT80bitslice8_core(const u8* message, const u8* subkeys, u8* ciphertext);
void PRESENT80bitslice8_cipher(const u64 plaintext[BITSLICE8_P], const u16 key[BITSLICE8_P][KEY80], u64 ciphertext[BITSLICE8_P]);
void PRESENT80bitslice8_cipher_(const u64 plaintext[BITSLICE8_P], const u16 key[BITSLICE8_P][KEY80], u64 ciphertext[BITSLICE8_P]);
void PRESENT80bitslice16_key_schedule(const u8* masterKey, u8* roundKeys);
void PRESENT80bitslice16_core(const u8* message, const u8* subkeys, u8* ciphertext);
void PRESENT80bitslice16_cipher(const u64 plaintext[BITSLICE16_P], const u16 key[BITSLICE16_P][KEY80], u64 ciphertext[BITSLICE16_P]);
void PRESENT80bitslice16_cipher_(const u64 plaintext[BITSLICE16_P], const u16 key[BITSLICE16_P][KEY80], u64 ciphertext[BITSLICE16_P]);
#endif
#ifdef PRESENT128
void PRESENT128bitslice8_key_schedule(const u8* masterKey, u8* roundKeys);
void PRESENT128bitslice8_core(const u8* message, const u8* subkeys, u8* ciphertext);
void PRESENT128bitslice8_cipher(const u64 plaintext[BITSLICE8_P], const u16 key[BITSLICE8_P][KEY128], u64 ciphertext[BITSLICE8_P]);
void PRESENT128bitslice8_cipher_(const u64 plaintext[BITSLICE8_P], const u16 key[BITSLICE8_P][KEY128], u64 ciphertext[BITSLICE8_P]);
void PRESENT128bitslice16_key_schedule(const u8* masterKey, u8* roundKeys);
void PRESENT128bitslice16_core(const u8* message, const u8* subkeys, u8* ciphertext);
void PRESENT128bitslice16_cipher(const u64 plaintext[BITSLICE16_P], const u16 key[BITSLICE16_P][KEY128], u64 ciphertext[BITSLICE16_P]);
void PRESENT128bitslice16_cipher_(const u64 plaintext[BITSLICE16_P], const u16 key[BITSLICE16_P][KEY128], u64 ciphertext[BITSLICE16_P]);
#endif
#endif

#ifdef PRESENT80
/********************************************************************************/
/********************************************************************************/
void PRESENT80bitslice8_key_schedule(const u8* masterKey, u8* roundKeys){
	PRESENT_KEY_SCHEDULE(BITSLICE8_P, 80);
	return;
}

void PRESENT80bitslice8_core(const u8* message, const u8* subkeys, u8* ciphertext){
	PRESENT_CORE_ENCRYPT(BITSLICE8_P, 80);
	return;
}

void PRESENT80bitslice8_cipher(const u64 plaintext[BITSLICE8_P], const u16 key[BITSLICE8_P][KEY80], u64 ciphertext[BITSLICE8_P])
{
	u8 subkeys[BITSLICE8_P * PRESENT80_SUBKEYS_SIZE];

        /* Initialize the constants: done once and for all */
        PRESENT_init();

#ifdef MEASURE_PERF
        key_schedule_start = rdtsc();
#endif
        PRESENT80bitslice8_key_schedule((u8*)key, (u8*)subkeys);
#ifdef MEASURE_PERF
        key_schedule_end = rdtsc();
#endif

#ifdef MEASURE_PERF
        encrypt_start = rdtsc();
#endif
        PRESENT80bitslice8_core((u8*)plaintext, (u8*)subkeys, (u8*)ciphertext);
#ifdef MEASURE_PERF
        encrypt_end = rdtsc();
#endif
        return;
}

/* Ciphering with mixed key schedule and encryption  */
/* It takes less memory since subkeys are not stored */
void PRESENT80bitslice8_cipher_(const u64 plaintext[BITSLICE8_P], const u16 key[BITSLICE8_P][KEY80], u64 ciphertext[BITSLICE8_P])
{
	PRESENT_init();
#ifdef MEASURE_PERF
        key_schedule_start = 0;
#endif
#ifdef MEASURE_PERF
        key_schedule_start = 0;
#endif

#ifdef MEASURE_PERF
        encrypt_start = rdtsc();
#endif
	PRESENT_CORE_ENCRYPT_AND_KEY_SCHED(BITSLICE8_P, 80);
#ifdef MEASURE_PERF
        encrypt_end = rdtsc();
#endif
	return;
}

/********************************************************************************/
/********************************************************************************/
void PRESENT80bitslice16_key_schedule(const u8* masterKey, u8* roundKeys){
	PRESENT_KEY_SCHEDULE(BITSLICE16_P, 80);
	return;
}

void PRESENT80bitslice16_core(const u8* message, const u8* subkeys, u8* ciphertext){
	PRESENT_CORE_ENCRYPT(BITSLICE16_P, 80);
	return;
}

void PRESENT80bitslice16_cipher(const u64 plaintext[BITSLICE16_P], const u16 key[BITSLICE16_P][KEY80], u64 ciphertext[BITSLICE16_P])
{
	u8 subkeys[BITSLICE16_P * PRESENT80_SUBKEYS_SIZE];

        /* Initialize the constants: done once and for all */
        PRESENT_init();

#ifdef MEASURE_PERF
        key_schedule_start = rdtsc();
#endif
        PRESENT80bitslice16_key_schedule((u8*)key, (u8*)subkeys);
#ifdef MEASURE_PERF
        key_schedule_end = rdtsc();
#endif

#ifdef MEASURE_PERF
        encrypt_start = rdtsc();
#endif
        PRESENT80bitslice16_core((u8*)plaintext, (u8*)subkeys, (u8*)ciphertext);
#ifdef MEASURE_PERF
        encrypt_end = rdtsc();
#endif
        return;
}

/* Ciphering with mixed key schedule and encryption  */
/* It takes less memory since subkeys are not stored */
void PRESENT80bitslice16_cipher_(const u64 plaintext[BITSLICE16_P], const u16 key[BITSLICE16_P][KEY80], u64 ciphertext[BITSLICE16_P])
{
	PRESENT_init();
#ifdef MEASURE_PERF
        key_schedule_start = 0;
#endif
#ifdef MEASURE_PERF
        key_schedule_start = 0;
#endif

#ifdef MEASURE_PERF
        encrypt_start = rdtsc();
#endif
	PRESENT_CORE_ENCRYPT_AND_KEY_SCHED(BITSLICE16_P, 80);
#ifdef MEASURE_PERF
        encrypt_end = rdtsc();
#endif
	return;
}
#endif

#ifdef PRESENT128
/********************************************************************************/
/********************************************************************************/
void PRESENT128bitslice8_key_schedule(const u8* masterKey, u8* roundKeys){
	PRESENT_KEY_SCHEDULE(BITSLICE8_P, 128);
	return;
}

void PRESENT128bitslice8_core(const u8* message, const u8* subkeys, u8* ciphertext){
	PRESENT_CORE_ENCRYPT(BITSLICE8_P, 128);
	return;
}

void PRESENT128bitslice8_cipher(const u64 plaintext[BITSLICE8_P], const u16 key[BITSLICE8_P][KEY128], u64 ciphertext[BITSLICE8_P])
{
	u8 subkeys[BITSLICE8_P * PRESENT128_SUBKEYS_SIZE];

        /* Initialize the constants: done once and for all */
        PRESENT_init();

#ifdef MEASURE_PERF
        key_schedule_start = rdtsc();
#endif
        PRESENT128bitslice8_key_schedule((u8*)key, (u8*)subkeys);
#ifdef MEASURE_PERF
        key_schedule_end = rdtsc();
#endif

#ifdef MEASURE_PERF
        encrypt_start = rdtsc();
#endif
        PRESENT128bitslice8_core((u8*)plaintext, (u8*)subkeys, (u8*)ciphertext);
#ifdef MEASURE_PERF
        encrypt_end = rdtsc();
#endif
        return;
}

/* Ciphering with mixed key schedule and encryption  */
/* It takes less memory since subkeys are not stored */
void PRESENT128bitslice8_cipher_(const u64 plaintext[BITSLICE8_P], const u16 key[BITSLICE8_P][KEY128], u64 ciphertext[BITSLICE8_P])
{
	PRESENT_init();
#ifdef MEASURE_PERF
        key_schedule_start = 0;
#endif
#ifdef MEASURE_PERF
        key_schedule_start = 0;
#endif

#ifdef MEASURE_PERF
        encrypt_start = rdtsc();
#endif
	PRESENT_CORE_ENCRYPT_AND_KEY_SCHED(BITSLICE8_P, 128);
#ifdef MEASURE_PERF
        encrypt_end = rdtsc();
#endif
	return;
}


/********************************************************************************/
/********************************************************************************/
void PRESENT128bitslice16_key_schedule(const u8* masterKey, u8* roundKeys){
	PRESENT_KEY_SCHEDULE(BITSLICE16_P, 128);
	return;
}

void PRESENT128bitslice16_core(const u8* message, const u8* subkeys, u8* ciphertext){
	PRESENT_CORE_ENCRYPT(BITSLICE16_P, 128);
	return;
}

void PRESENT128bitslice16_cipher(const u64 plaintext[BITSLICE16_P], const u16 key[BITSLICE16_P][KEY128], u64 ciphertext[BITSLICE16_P])
{
	u8 subkeys[BITSLICE16_P * PRESENT128_SUBKEYS_SIZE];

        /* Initialize the constants: done once and for all */
        PRESENT_init();

#ifdef MEASURE_PERF
        key_schedule_start = rdtsc();
#endif
        PRESENT128bitslice16_key_schedule((u8*)key, (u8*)subkeys);
#ifdef MEASURE_PERF
        key_schedule_end = rdtsc();
#endif

#ifdef MEASURE_PERF
        encrypt_start = rdtsc();
#endif
        PRESENT128bitslice16_core((u8*)plaintext, (u8*)subkeys, (u8*)ciphertext);
#ifdef MEASURE_PERF
        encrypt_end = rdtsc();
#endif
        return;
}

/* Ciphering with mixed key schedule and encryption  */
/* It takes less memory since subkeys are not stored */
void PRESENT128bitslice16_cipher_(const u64 plaintext[BITSLICE16_P], const u16 key[BITSLICE16_P][KEY128], u64 ciphertext[BITSLICE16_P])
{
	PRESENT_init();
#ifdef MEASURE_PERF
        key_schedule_start = 0;
#endif
#ifdef MEASURE_PERF
        key_schedule_start = 0;
#endif

#ifdef MEASURE_PERF
        encrypt_start = rdtsc();
#endif
	PRESENT_CORE_ENCRYPT_AND_KEY_SCHED(BITSLICE16_P, 128);
#ifdef MEASURE_PERF
        encrypt_end = rdtsc();
#endif
	return;
}
#endif

#endif
