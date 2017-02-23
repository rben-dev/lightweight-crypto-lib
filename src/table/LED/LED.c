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
#ifdef TABLE
#include <common/basic_helpers.h>
#include "LED_tables.h"

#ifdef TABLE
#ifdef LED64
void LED128table_key_schedule(const u8* masterKey128, u8* roundKeys128);
void LED128table_core(const u8* plaintext, const u8* roundKeys128, u8* ciphertext);
void LED128table_cipher(const u64 plaintext_in[TABLE_P], const u16 keys_in[TABLE_P][KEY128], u64 ciphertext_out[TABLE_P]);
#endif
#ifdef LED128
void LED64table_cipher(const u64 plaintext_in[TABLE_P], const u16 keys_in[TABLE_P][KEY64], u64 ciphertext_out[TABLE_P]);
void LED64table_key_schedule(const u8* masterKey64, u8* roundKeys64);
void LED64table_core(const u8* plaintext, const u8* roundKeys64, u8* ciphertext);
#endif
#endif

/****************************************************************************************************/
/* some macros                                                                                      */

#define ROTL16(in, l) ((in) << l) ^ ((in) >> (16-l))
#define ROTR16(in, l) ((in) >> l) ^ ((in) << (16-l))
#define MASK4  0x0f
#define MASK8  0xff
#define MASK16 0xffff

#define LEDROUND(state) do {\
	unsigned long long stateIn;\
	stateIn = state;\
	state  = T0_LED[stateIn & MASK8];\
	state ^= T1_LED[(stateIn >> 8) & MASK8];\
	state ^= T2_LED[(stateIn >> 16) & MASK8];\
	state ^= T3_LED[(stateIn >> 24) & MASK8];\
	state ^= T4_LED[(stateIn >> 32) & MASK8];\
	state ^= T5_LED[(stateIn >> 40) & MASK8];\
	state ^= T6_LED[(stateIn >> 48) & MASK8];\
	state ^= T7_LED[(stateIn >> 56) & MASK8];\
} while(0);



/****************************************************************************************************/
/* LED64 key schedule                                                                               */
#ifdef LED64
void LED64table_key_schedule(const u8* masterKey64, u8* roundKeys64)
{
	((u64*)roundKeys64)[0] = ((u64*)masterKey64)[0];

	return;
}
#endif



/****************************************************************************************************/
/* LED128 key schedule                                                                              */
#ifdef LED128
void LED128table_key_schedule(const u8* masterKey128, u8* roundKeys128)
{
	((u64*)roundKeys128)[0] = ((u64*)masterKey128)[0];
	((u64*)roundKeys128)[1] = ((u64*)masterKey128)[1];

	return;
}
#endif



/****************************************************************************************************/
/* LED64 encryption core                                                                            */
#ifdef LED64
void LED64table_core(const u8* plaintext, const u8* roundKeys64, u8* ciphertext)
{
	u64 * state, * roundKeys;

	/* cast variables */
	*((u64*)ciphertext) = *((u64*)plaintext);
	state     = (u64 *)ciphertext;
	roundKeys = (u64 *)roundKeys64;

	/* addRoundKey */
	state[0] ^= roundKeys[0];

	/* step 1 */
	state[0] ^= Tcon64LED[0];
	LEDROUND(state[0]);
	state[0] ^= Tcon64LED[1];
	LEDROUND(state[0]);
	state[0] ^= Tcon64LED[2];
	LEDROUND(state[0]);
	state[0] ^= Tcon64LED[3];
	LEDROUND(state[0]);

	/* addRoundKey */
	state[0] ^= roundKeys[0];

	/* step 2 */
	state[0] ^= Tcon64LED[4];
	LEDROUND(state[0]);
	state[0] ^= Tcon64LED[5];
	LEDROUND(state[0]);
	state[0] ^= Tcon64LED[6];
	LEDROUND(state[0]);
	state[0] ^= Tcon64LED[7];
	LEDROUND(state[0]);

	/* addRoundKey */
	state[0] ^= roundKeys[0];

	/* step 3 */
	state[0] ^= Tcon64LED[8];
	LEDROUND(state[0]);
	state[0] ^= Tcon64LED[9];
	LEDROUND(state[0]);
	state[0] ^= Tcon64LED[10];
	LEDROUND(state[0]);
	state[0] ^= Tcon64LED[11];
	LEDROUND(state[0]);

	/* addRoundKey */
	state[0] ^= roundKeys[0];

	/* step 4 */
	state[0] ^= Tcon64LED[12];
	LEDROUND(state[0]);
	state[0] ^= Tcon64LED[13];
	LEDROUND(state[0]);
	state[0] ^= Tcon64LED[14];
	LEDROUND(state[0]);
	state[0] ^= Tcon64LED[15];
	LEDROUND(state[0]);

	/* addRoundKey */
	state[0] ^= roundKeys[0];

	/* step 5 */
	state[0] ^= Tcon64LED[16];
	LEDROUND(state[0]);
	state[0] ^= Tcon64LED[17];
	LEDROUND(state[0]);
	state[0] ^= Tcon64LED[18];
	LEDROUND(state[0]);
	state[0] ^= Tcon64LED[19];
	LEDROUND(state[0]);

	/* addRoundKey */
	state[0] ^= roundKeys[0];

	/* step 6 */
	state[0] ^= Tcon64LED[20];
	LEDROUND(state[0]);
	state[0] ^= Tcon64LED[21];
	LEDROUND(state[0]);
	state[0] ^= Tcon64LED[22];
	LEDROUND(state[0]);
	state[0] ^= Tcon64LED[23];
	LEDROUND(state[0]);

	/* addRoundKey */
	state[0] ^= roundKeys[0];

	/* step 7 */
	state[0] ^= Tcon64LED[24];
	LEDROUND(state[0]);
	state[0] ^= Tcon64LED[25];
	LEDROUND(state[0]);
	state[0] ^= Tcon64LED[26];
	LEDROUND(state[0]);
	state[0] ^= Tcon64LED[27];
	LEDROUND(state[0]);

	/* addRoundKey */
	state[0] ^= roundKeys[0];

	/* step 8 */
	state[0] ^= Tcon64LED[28];
	LEDROUND(state[0]);
	state[0] ^= Tcon64LED[29];
	LEDROUND(state[0]);
	state[0] ^= Tcon64LED[30];
	LEDROUND(state[0]);
	state[0] ^= Tcon64LED[31];
	LEDROUND(state[0]);

	/* addRoundKey */
	state[0] ^= roundKeys[0];

	return;
}
#endif



/****************************************************************************************************/
/* LED128 encryption core                                                                           */
#ifdef LED128
void LED128table_core(const u8* plaintext, const u8* roundKeys128, u8* ciphertext)
{
	u64 * state, * roundKeys;

	/* cast variables */
	*((u64*)ciphertext) = *((u64*)plaintext);
	state     = (u64 *)ciphertext;
	roundKeys = (u64 *)roundKeys128;

	/* addRoundKey */
	state[0] ^= roundKeys[0];

	/* step 1 */
	state[0] ^= Tcon128LED[0];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[1];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[2];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[3];
	LEDROUND(state[0]);

	/* addRoundKey */
	state[0] ^= roundKeys[1];

	/* step 2 */
	state[0] ^= Tcon128LED[4];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[5];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[6];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[7];
	LEDROUND(state[0]);

	/* addRoundKey */
	state[0] ^= roundKeys[0];

	/* step 3 */
	state[0] ^= Tcon128LED[8];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[9];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[10];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[11];
	LEDROUND(state[0]);

	/* addRoundKey */
	state[0] ^= roundKeys[1];

	/* step 4 */
	state[0] ^= Tcon128LED[12];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[13];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[14];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[15];
	LEDROUND(state[0]);

	/* addRoundKey */
	state[0] ^= roundKeys[0];

	/* step 5 */
	state[0] ^= Tcon128LED[16];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[17];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[18];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[19];
	LEDROUND(state[0]);

	/* addRoundKey */
	state[0] ^= roundKeys[1];

	/* step 6 */
	state[0] ^= Tcon128LED[20];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[21];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[22];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[23];
	LEDROUND(state[0]);

	/* addRoundKey */
	state[0] ^= roundKeys[0];

	/* step 7 */
	state[0] ^= Tcon128LED[24];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[25];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[26];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[27];
	LEDROUND(state[0]);

	/* addRoundKey */
	state[0] ^= roundKeys[1];

	/* step 8 */
	state[0] ^= Tcon128LED[28];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[29];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[30];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[31];
	LEDROUND(state[0]);

	/* addRoundKey */
	state[0] ^= roundKeys[0];

	/* step 9 */
	state[0] ^= Tcon128LED[32];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[33];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[34];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[35];
	LEDROUND(state[0]);

	/* addRoundKey */
	state[0] ^= roundKeys[1];

	/* step 10 */
	state[0] ^= Tcon128LED[36];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[37];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[38];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[39];
	LEDROUND(state[0]);

	/* addRoundKey */
	state[0] ^= roundKeys[0];

	/* step 11 */
	state[0] ^= Tcon128LED[40];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[41];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[42];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[43];
	LEDROUND(state[0]);

	/* addRoundKey */
	state[0] ^= roundKeys[1];

	/* step 12 */
	state[0] ^= Tcon128LED[44];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[45];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[46];
	LEDROUND(state[0]);
	state[0] ^= Tcon128LED[47];
	LEDROUND(state[0]);

	/* addRoundKey */
	state[0] ^= roundKeys[0];

	return;
}
#endif



/****************************************************************************************************/
/* LED64 key schedule + encryption                                                                  */
#ifdef LED64
void LED64table_cipher(const u64 plaintext_in[TABLE_P], const u16 keys_in[TABLE_P][KEY64], u64 ciphertext_out[TABLE_P])
{
	/* Key schedule: subkeys are of size 1*8 bytes */
	u8 subkeys[TABLE_P * LED64_SUBKEYS_SIZE];

	/* The key schedule does merely nothing */
#ifdef MEASURE_PERF
	key_schedule_start = 0;
#endif

	/* Compute the subkeys */
	LED64table_key_schedule((const u8*)keys_in, subkeys);

#ifdef MEASURE_PERF
	key_schedule_end = 0;
#endif

#ifdef MEASURE_PERF
	encrypt_start = rdtsc();
#endif

	/* Call the core encryption */
	LED64table_core((const u8*)plaintext_in, subkeys, (u8*)ciphertext_out);

#ifdef MEASURE_PERF
	encrypt_end = rdtsc();
#endif

	return;
}
#endif



/****************************************************************************************************/
/* LED128 key schedule + encryption                                                                 */
#ifdef LED128
void LED128table_cipher(const u64 plaintext_in[TABLE_P], const u16 keys_in[TABLE_P][KEY128], u64 ciphertext_out[TABLE_P])
{
	/* Key schedule: subkeys are of size 1*16 bytes */
	u8 subkeys[TABLE_P * LED128_SUBKEYS_SIZE];

	/* The key schedule does merely nothing */
#ifdef MEASURE_PERF
	key_schedule_start = 0;
#endif

	/* Compute the subkeys */
	LED128table_key_schedule((const u8*)keys_in, subkeys);

#ifdef MEASURE_PERF
	key_schedule_end = 0;
#endif

#ifdef MEASURE_PERF
	encrypt_start = rdtsc();
#endif

	/* Call the core encryption */
	LED128table_core((const u8*)plaintext_in, subkeys, (u8*)ciphertext_out);

#ifdef MEASURE_PERF
	encrypt_end = rdtsc();
#endif

	return;
}
#endif

#endif
