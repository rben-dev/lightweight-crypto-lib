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
#ifdef TABLE
#include <common/basic_helpers.h>
#include "Piccolo_tables.h"

#ifdef TABLE
#ifdef Piccolo80
void Piccolo80table_key_schedule(const u8* masterKey80, u8* roundKeys80);
void Piccolo80table_core(const u8* plaintext, const u8* roundKeys80, u8* ciphertext);
void Piccolo80table_cipher(const u64 plaintext_in[TABLE_P], const u16 keys_in[TABLE_P][KEY80], u64 ciphertext_out[TABLE_P]);
#endif
#ifdef Piccolo128
void Piccolo128table_key_schedule(const u8* masterKey128, u8* roundKeys128);
void Piccolo128table_core(const u8* plaintext, const u8* roundKeys128, u8* ciphertext);
void Piccolo128table_cipher(const u64 plaintext_in[TABLE_P], const u16 keys_in[TABLE_P][KEY128], u64 ciphertext_out[TABLE_P]);
#endif
#endif

/****************************************************************************************************/
/* some macros                                                                                      */

#define ROTL64(in, l) ((in) << l) ^ ((in) >> (64-l))
#define ROTR64(in, l) ((in) >> l) ^ ((in) << (64-l))
#define MASK4  0x0f
#define MASK8  0xff
#define MASK16 0xffff

#define PICCOLOKEYSCHEDULE128PERM(key) do {\
	u64 key0, key1, key2, key3, key45, key67;\
	key0  = ((u64 *)key)[0] & 0x000000000000ffff;\
	key1  = ((u64 *)key)[0] & 0x00000000ffff0000;\
	key2  = ((u64 *)key)[0] & 0x0000ffff00000000;\
	key3  = ((u64 *)key)[0] & 0xffff000000000000;\
	key45 = ((u64 *)key)[1] & 0x00000000ffffffff;\
	key67 = ((u64 *)key)[1] & 0xffffffff00000000;\
	key2  = ROTR64(key2, 32);\
	key3  = ROTR64(key3, 32);\
	key45 = ROTL64(key45, 32);\
	((u64 *)key)[0] = key1 ^ key2 ^ key67;\
	((u64 *)key)[1] = key0 ^ key3 ^ key45;\
} while(0);

#define PICCOLOROUNDPERM(state) do {\
	u64 state0, state1;\
	state0 = state & 0x00ff00ff00ff00ff;\
	state1 = state & 0xff00ff00ff00ff00;\
	state0 = ROTR64(state0, 16);\
	state1 = ROTL64(state1, 16);\
	state = state0 ^ state1;\
} while(0);

#define PICCOLOROUND(state, key) do {\
	unsigned int w0, w1;\
	u64 outputFeistel0, outputFeistel1, outputFeistel2, outputFeistel3;\
	w0 = state & MASK8;\
	w1 = (state >> 8) & MASK8;\
	w0 = T0_Piccolo[w0];\
	w1 = T1_Piccolo[w1];\
	w0 = w0 ^ w1;\
	outputFeistel0 = T2_Piccolo[w0 & MASK8];\
	outputFeistel1 = T3_Piccolo[(w0 >> 8) & MASK8];\
	w0 = (state >> 32) & MASK8;\
	w1 = (state >> 40) & MASK8;\
	w0 = T0_Piccolo[w0];\
	w1 = T1_Piccolo[w1];\
	w0 = w0 ^ w1;\
	outputFeistel2 = T4_Piccolo[w0 & MASK8];\
	outputFeistel3 = T5_Piccolo[(w0 >> 8) & MASK8];\
	state ^= outputFeistel0 ^ outputFeistel1 ^ outputFeistel2 ^ outputFeistel3 ^ key;\
} while(0);



/****************************************************************************************************/
/* Piccolo80 key schedule                                                                           */
#ifdef Piccolo80
void Piccolo80table_key_schedule(const u8* masterKey80, u8* roundKeys80)
{
	u64 k2k3, k0k1, k4k4;

	((u64*)roundKeys80)[0]  = 0;
	((u64*)roundKeys80)[26] = 0;
	/* compute wk0 and wk1 such that roundKeys80[0..7] = wk0 | 0x0000 | wk1 | 0x0000 */
	roundKeys80[0]  =  masterKey80[0];
	roundKeys80[1]  =  masterKey80[3];
	roundKeys80[4]  =  masterKey80[2];
	roundKeys80[5]  =  masterKey80[1];

	/* compute wk2 and wk3 such that roundKeys80[208..215] = wk2 | 0x0000 | wk3 | 0x0000 */
	roundKeys80[208] =  masterKey80[8];
	roundKeys80[209] =  masterKey80[7];
	roundKeys80[212] =  masterKey80[6];
	roundKeys80[213] =  masterKey80[9];

	/* compute 0x0000 | k2 | 0x0000 | k3 */
	k2k3 = ((u64)((u16 *)masterKey80)[2] << 16) | ((u64)((u16 *)masterKey80)[3] << 48);

	/* compute 0x0000 | k0 | 0x0000 | k1 */
	k0k1 = ((u64)((u16 *)masterKey80)[0] << 16) | ((u64)((u16 *)masterKey80)[1] << 48);

	/* compute 0x0000 | k4 | 0x0000 | k4 */
	k4k4 = ((u64)((u16 *)masterKey80)[4] << 16) | ((u64)((u16 *)masterKey80)[4] << 48);

	/* compute 0x0000 | rk0  | 0x0000 | rk1 */
	((u64 *)roundKeys80)[1] = Tcon80_Piccolo[0] ^ k2k3;

	/* compute 0x0000 | rk2  | 0x0000 | rk3 */
	((u64 *)roundKeys80)[2] = Tcon80_Piccolo[1] ^ k0k1;

	/* compute 0x0000 | rk4  | 0x0000 | rk5 */
	((u64 *)roundKeys80)[3] = Tcon80_Piccolo[2] ^ k2k3;

	/* compute 0x0000 | rk6  | 0x0000 | rk7 */
	((u64 *)roundKeys80)[4] = Tcon80_Piccolo[3] ^ k4k4;

	/* compute 0x0000 | rk8  | 0x0000 | rk9 */
	((u64 *)roundKeys80)[5] = Tcon80_Piccolo[4] ^ k0k1;

	/* compute 0x0000 | rk10 | 0x0000 | rk11 */
	((u64 *)roundKeys80)[6] = Tcon80_Piccolo[5] ^ k2k3;

	/* compute 0x0000 | rk12 | 0x0000 | rk13 */
	((u64 *)roundKeys80)[7] = Tcon80_Piccolo[6] ^ k0k1;

	/* compute 0x0000 | rk14 | 0x0000 | rk15 */
	((u64 *)roundKeys80)[8] = Tcon80_Piccolo[7] ^ k2k3;

	/* compute 0x0000 | rk16 | 0x0000 | rk17 */
	((u64 *)roundKeys80)[9] = Tcon80_Piccolo[8] ^ k4k4;

	/* compute 0x0000 | rk18 | 0x0000 | rk19 */
	((u64 *)roundKeys80)[10] = Tcon80_Piccolo[9] ^ k0k1;

	/* compute 0x0000 | rk20 | 0x0000 | rk21 */
	((u64 *)roundKeys80)[11] = Tcon80_Piccolo[10] ^ k2k3;

	/* compute 0x0000 | rk22 | 0x0000 | rk23 */
	((u64 *)roundKeys80)[12] = Tcon80_Piccolo[11] ^ k0k1;

	/* compute 0x0000 | rk24 | 0x0000 | rk25 */
	((u64 *)roundKeys80)[13] = Tcon80_Piccolo[12] ^ k2k3;

	/* compute 0x0000 | rk26 | 0x0000 | rk27 */
	((u64 *)roundKeys80)[14] = Tcon80_Piccolo[13] ^ k4k4;

	/* compute 0x0000 | rk28 | 0x0000 | rk29 */
	((u64 *)roundKeys80)[15] = Tcon80_Piccolo[14] ^ k0k1;

	/* compute 0x0000 | rk30 | 0x0000 | rk31 */
	((u64 *)roundKeys80)[16] = Tcon80_Piccolo[15] ^ k2k3;

	/* compute 0x0000 | rk32 | 0x0000 | rk33 */
	((u64 *)roundKeys80)[17] = Tcon80_Piccolo[16] ^ k0k1;

	/* compute 0x0000 | rk34 | 0x0000 | rk35 */
	((u64 *)roundKeys80)[18] = Tcon80_Piccolo[17] ^ k2k3;

	/* compute 0x0000 | rk36 | 0x0000 | rk37 */
	((u64 *)roundKeys80)[19] = Tcon80_Piccolo[18] ^ k4k4;

	/* compute 0x0000 | rk38 | 0x0000 | rk39 */
	((u64 *)roundKeys80)[20] = Tcon80_Piccolo[19] ^ k0k1;

	/* compute 0x0000 | rk40 | 0x0000 | rk41 */
	((u64 *)roundKeys80)[21] = Tcon80_Piccolo[20] ^ k2k3;

	/* compute 0x0000 | rk42 | 0x0000 | rk43 */
	((u64 *)roundKeys80)[22] = Tcon80_Piccolo[21] ^ k0k1;

	/* compute 0x0000 | rk44 | 0x0000 | rk45 */
	((u64 *)roundKeys80)[23] = Tcon80_Piccolo[22] ^ k2k3;

	/* compute 0x0000 | rk46 | 0x0000 | rk47 */
	((u64 *)roundKeys80)[24] = Tcon80_Piccolo[23] ^ k4k4;

	/* compute 0x0000 | rk48 | 0x0000 | rk49 */
	((u64 *)roundKeys80)[25] = Tcon80_Piccolo[24] ^ k0k1;

	return;
}
#endif



/****************************************************************************************************/
/* Piccolo128 key schedule                                                                          */
#ifdef Piccolo128
void Piccolo128table_key_schedule(const u8* masterKey128, u8* roundKeys128)
{
	u64 k0, k1, k2, k3, k4, k5, k6, k7, k4k5, k2k1, k0k3, k6k1, k2k7, k4k1, k6k5, k4k3, k0k7, k2k5;

	((u64*)roundKeys128)[0]  = 0;
	((u64*)roundKeys128)[32] = 0;
	/* compute wk0 and wk1 such that roundKeys128[0..7] = wk0 | 0x0000 | wk1 | 0x0000 */
	roundKeys128[0]  =  masterKey128[0];
	roundKeys128[1]  =  masterKey128[3];
	roundKeys128[4]  =  masterKey128[2];
	roundKeys128[5]  =  masterKey128[1];

	/* compute wk2 and wk3 such that roundKeys128[256..263] = wk2 | 0x0000 | wk3 | 0x0000 */
	roundKeys128[256] =  masterKey128[8];
	roundKeys128[257] =  masterKey128[15];
	roundKeys128[260] =  masterKey128[14];
	roundKeys128[261] =  masterKey128[9];

	/* compute 0x0000 | k0 | 0x0000 | 0x0000 */
	k0 = (u64)((u16 *)masterKey128)[0] << 16;

	/* compute 0x0000 | k2 | 0x0000 | 0x0000 */
	k2 = (u64)((u16 *)masterKey128)[2] << 16;

	/* compute 0x0000 | k4 | 0x0000 | 0x0000 */
	k4 = (u64)((u16 *)masterKey128)[4] << 16;

	/* compute 0x0000 | k6 | 0x0000 | 0x0000 */
	k6 = (u64)((u16 *)masterKey128)[6] << 16;

	/* compute 0x0000 | 0x00 | 0x0000 | k1 */
	k1 = (u64)((u16 *)masterKey128)[1] << 48;

	/* compute 0x0000 | 0x00 | 0x0000 | k3 */
	k3 = (u64)((u16 *)masterKey128)[3] << 48;

	/* compute 0x0000 | 0x00 | 0x0000 | k5 */
	k5 = (u64)((u16 *)masterKey128)[5] << 48;

	/* compute 0x0000 | 0x00 | 0x0000 | k7 */
	k7 = (u64)((u16 *)masterKey128)[7] << 48;

	/* compute 0x0000 | k4  | 0x0000 | k5 */
	k4k5 = k4 ^ k5;

	/* compute 0x0000 | k2  | 0x0000 | k1 */
	k2k1 = k2 ^ k1;

	/* compute 0x0000 | k0  | 0x0000 | k3 */
	k0k3 = k0 ^ k3;

	/* compute 0x0000 | k6  | 0x0000 | k1 */
	k6k1 = k6 ^ k1;

	/* compute 0x0000 | k2  | 0x0000 | k7 */
	k2k7 = k2 ^ k7;

	/* compute 0x0000 | k4  | 0x0000 | k1 */
	k4k1 = k4 ^ k1;

	/* compute 0x0000 | k6  | 0x0000 | k5 */
	k6k5 = k6 ^ k5;

	/* compute 0x0000 | k4  | 0x0000 | k3 */
	k4k3 = k4 ^ k3;

	/* compute 0x0000 | k0  | 0x0000 | k7 */
	k0k7 = k0 ^ k7;

	/* compute 0x0000 | k2  | 0x0000 | k5 */
	k2k5 = k2 ^ k5;

	/* compute 0x0000 | rk0  | 0x0000 | rk1 */
	((u64 *)roundKeys128)[1] = Tcon128_Piccolo[0] ^ k2 ^ k3;

	/* compute 0x0000 | rk2  | 0x0000 | rk3 */
	((u64 *)roundKeys128)[2] = Tcon128_Piccolo[1] ^ k4k5;

	/* compute 0x0000 | rk4  | 0x0000 | rk5 */
	((u64 *)roundKeys128)[3] = Tcon128_Piccolo[2] ^ k6 ^ k7;

	/* take into account Key Schedule permutation */
	/* compute 0x0000 | rk6  | 0x0000 | rk7 */
	((u64 *)roundKeys128)[4] = Tcon128_Piccolo[3] ^ k2k1;

	/* compute 0x0000 | rk8  | 0x0000 | rk9 */
	((u64 *)roundKeys128)[5] = Tcon128_Piccolo[4] ^ k6 ^ k7;

	/* compute 0x0000 | rk10 | 0x0000 | rk11 */
	((u64 *)roundKeys128)[6] = Tcon128_Piccolo[5] ^ k0k3;

	/* compute 0x0000 | rk12 | 0x0000 | rk13 */
	((u64 *)roundKeys128)[7] = Tcon128_Piccolo[6] ^ k4k5;

	/* take into account Key Schedule permutation */
	/* compute 0x0000 | rk14 | 0x0000 | rk15 */
	((u64 *)roundKeys128)[8] = Tcon128_Piccolo[7] ^ k6k1;

	/* compute 0x0000 | rk16 | 0x0000 | rk17 */
	((u64 *)roundKeys128)[9] = Tcon128_Piccolo[8] ^ k4k5;

	/* compute 0x0000 | rk18 | 0x0000 | rk19 */
	((u64 *)roundKeys128)[10] = Tcon128_Piccolo[9] ^ k2k7;

	/* compute 0x0000 | rk20 | 0x0000 | rk21 */
	((u64 *)roundKeys128)[11] = Tcon128_Piccolo[10] ^ k0k3;

	/* take into account Key Schedule permutation */
	/* compute 0x0000 | rk22 | 0x0000 | rk23 */
	((u64 *)roundKeys128)[12] = Tcon128_Piccolo[11] ^ k4k1;

	/* compute 0x0000 | rk24 | 0x0000 | rk25 */
	((u64 *)roundKeys128)[13] = Tcon128_Piccolo[12] ^ k0k3;

	/* compute 0x0000 | rk26 | 0x0000 | rk27 */
	((u64 *)roundKeys128)[14] = Tcon128_Piccolo[13] ^ k6k5;

	/* compute 0x0000 | rk28 | 0x0000 | rk29 */
	((u64 *)roundKeys128)[15] = Tcon128_Piccolo[14] ^ k2k7;

	/* take into account Key Schedule permutation */
	/* compute 0x0000 | rk29 | 0x0000 | rk30 */
	((u64 *)roundKeys128)[16] = Tcon128_Piccolo[15] ^ k0 ^ k1;

	/* compute 0x0000 | rk31 | 0x0000 | rk32 */
	((u64 *)roundKeys128)[17] = Tcon128_Piccolo[16] ^ k2k7;

	/* compute 0x0000 | rk33 | 0x0000 | rk34 */
	((u64 *)roundKeys128)[18] = Tcon128_Piccolo[17] ^ k4k3;

	/* compute 0x0000 | rk35 | 0x0000 | rk36 */
	((u64 *)roundKeys128)[19] = Tcon128_Piccolo[18] ^ k6k5;

	/* take into account Key Schedule permutation */
	/* compute 0x0000 | rk37 | 0x0000 | rk38 */
	((u64 *)roundKeys128)[20] = Tcon128_Piccolo[19] ^ k2k1;

	/* compute 0x0000 | rk39 | 0x0000 | rk40 */
	((u64 *)roundKeys128)[21] = Tcon128_Piccolo[20] ^ k6k5;

	/* compute 0x0000 | rk41 | 0x0000 | rk42 */
	((u64 *)roundKeys128)[22] = Tcon128_Piccolo[21] ^ k0k7;

	/* compute 0x0000 | rk43 | 0x0000 | rk44 */
	((u64 *)roundKeys128)[23] = Tcon128_Piccolo[22] ^ k4k3;

	/* take into account Key Schedule permutation */
	/* compute 0x0000 | rk45 | 0x0000 | rk46 */
	((u64 *)roundKeys128)[24] = Tcon128_Piccolo[23] ^ k6k1;

	/* compute 0x0000 | rk47 | 0x0000 | rk48 */
	((u64 *)roundKeys128)[25] = Tcon128_Piccolo[24] ^ k4k3;

	/* compute 0x0000 | rk49 | 0x0000 | rk50 */
	((u64 *)roundKeys128)[26] = Tcon128_Piccolo[25] ^ k2k5;

	/* compute 0x0000 | rk51 | 0x0000 | rk52 */
	((u64 *)roundKeys128)[27] = Tcon128_Piccolo[26] ^ k0k7;

	/* take into account Key Schedule permutation */
	/* compute 0x0000 | rk53 | 0x0000 | rk54 */
	((u64 *)roundKeys128)[28] = Tcon128_Piccolo[27] ^ k4k1;

	/* compute 0x0000 | rk55 | 0x0000 | rk56 */
	((u64 *)roundKeys128)[29] = Tcon128_Piccolo[28] ^ k0k7;

	/* compute 0x0000 | rk57 | 0x0000 | rk58 */
	((u64 *)roundKeys128)[30] = Tcon128_Piccolo[29] ^ k6 ^ k3;

	/* compute 0x0000 | rk59 | 0x0000 | rk60 */
	((u64 *)roundKeys128)[31] = Tcon128_Piccolo[30] ^ k2k5;

	return;
}
#endif



/****************************************************************************************************/
/* Piccolo80 encryption core                                                                        */
#ifdef Piccolo80
void Piccolo80table_core(const u8* plaintext, const u8* roundKeys80, u8* ciphertext)
{
	u64 * state, * roundKeys;

	/* cast variables */
	*((u64*)ciphertext) = *((u64*)plaintext);
	state     = (u64 *)ciphertext;
	roundKeys = (u64 *)roundKeys80;

	/* initial key whitening */
	state[0] ^= roundKeys[0];

	/* perform one round */
	PICCOLOROUND(state[0], roundKeys[1]);

	/* perform 6 permutation and round transformations */
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[2]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[3]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[4]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[5]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[6]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[7]);

	/* perform 6 permutation and round transformations */
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[8]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[9]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[10]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[11]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[12]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[13]);

	/* perform 6 permutation and round transformations */
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[14]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[15]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[16]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[17]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[18]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[19]);

	/* perform 6 permutation and round transformations */
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[20]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[21]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[22]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[23]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[24]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[25]);

	/* final key whitening */
	state[0] ^= roundKeys[26];

	return;
}
#endif



/****************************************************************************************************/
/* Piccolo128 encryption core                                                                       */
#ifdef Piccolo128
void Piccolo128table_core(const u8* plaintext, const u8* roundKeys128, u8* ciphertext)
{
	u64 * state, * roundKeys;

	/* cast variables */
	*((u64*)ciphertext) = *((u64*)plaintext);
	state     = (u64 *)ciphertext;
	roundKeys = (u64 *)roundKeys128;

	/* initial key whitening */
	state[0] ^= roundKeys[0];

	/* perform one round */
	PICCOLOROUND(state[0], roundKeys[1]);

	/* perform 6 permutation and round transformations */
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[2]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[3]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[4]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[5]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[6]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[7]);

	/* perform 6 permutation and round transformations */
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[8]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[9]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[10]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[11]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[12]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[13]);

	/* perform 6 permutation and round transformations */
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[14]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[15]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[16]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[17]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[18]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[19]);

	/* perform 6 permutation and round transformations */
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[20]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[21]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[22]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[23]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[24]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[25]);

	/* perform 6 permutation and round transformations */
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[26]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[27]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[28]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[29]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[30]);
	PICCOLOROUNDPERM(state[0]);
	PICCOLOROUND(state[0], roundKeys[31]);

	/* final key whitening */
	state[0] ^= roundKeys[32];

	return;
}
#endif



/****************************************************************************************************/
/* Piccolo80 key schedule + encryption                                                              */
#ifdef Piccolo80
void Piccolo80table_cipher(const u64 plaintext_in[TABLE_P], const u16 keys_in[TABLE_P][KEY80], u64 ciphertext_out[TABLE_P])
{
	/* Key schedule: subkeys are of size 2*264 bytes */
	u8 subkeys[TABLE_P * Piccolo80_SUBKEYS_SIZE];

#ifdef MEASURE_PERF
	key_schedule_start = rdtsc();
#endif

	/* Compute the subkeys */
	Piccolo80table_key_schedule((const u8*)keys_in, subkeys);

#ifdef MEASURE_PERF
	key_schedule_end = rdtsc();
#endif

#ifdef MEASURE_PERF
	encrypt_start = rdtsc();
#endif

	/* Call the core encryption */
	Piccolo80table_core((const u8*)plaintext_in, subkeys, (u8*)ciphertext_out);

#ifdef MEASURE_PERF
	encrypt_end = rdtsc();
#endif

	return;
}
#endif



/****************************************************************************************************/
/* Piccolo128 key schedule + encryption                                                             */
#ifdef Piccolo128
void Piccolo128table_cipher(const u64 plaintext_in[TABLE_P], const u16 keys_in[TABLE_P][KEY128], u64 ciphertext_out[TABLE_P])
{
	/* Key schedule: subkeys are of size 2*264 bytes */
	u8 subkeys[TABLE_P * Piccolo128_SUBKEYS_SIZE];

#ifdef MEASURE_PERF
	key_schedule_start = rdtsc();
#endif
	/* Compute the subkeys */
	Piccolo128table_key_schedule((const u8*)keys_in, subkeys);

#ifdef MEASURE_PERF
	key_schedule_end = rdtsc();
#endif

#ifdef MEASURE_PERF
	encrypt_start = rdtsc();
#endif

	/* Call the core encryption */
	Piccolo128table_core((const u8*)plaintext_in, subkeys, (u8*)ciphertext_out);

#ifdef MEASURE_PERF
	encrypt_end = rdtsc();
#endif

	return;
}
#endif

#endif
