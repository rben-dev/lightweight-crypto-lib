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

    The current source code is part of the table based implementations
    source tree.

    Project: Lightweight cryptography library
    File:    src/table/PRESENT/PRESENT.c

-------------------------- CeCILL-B HEADER ----------------------------------*/
#ifdef TABLE
#include <common/basic_helpers.h>
#include "PRESENT_tables.h"

#ifdef TABLE
#ifdef PRESENT80
void PRESENT80table_key_schedule(const u8* masterKey80, u8* roundKeys80);
void PRESENT80table_core(const u8* plaintext, const u8* roundKeys80, u8* ciphertext);
void PRESENT80table_cipher(const u64 plaintext_in[TABLE_P], const u16 keys_in[TABLE_P][KEY80], u64 ciphertext_out[TABLE_P]);
#endif
#ifdef PRESENT128
void PRESENT128table_key_schedule(const u8* masterKey128, u8* roundKeys128);
void PRESENT128table_core(const u8* plaintext, const u8* roundKeys128, u8* ciphertext);
void PRESENT128table_cipher(const u64 plaintext_in[TABLE_P], const u16 keys_in[TABLE_P][KEY128], u64 ciphertext_out[TABLE_P]);
#endif
#endif

/****************************************************************************************************/
/* some macros                                                                                      */

/* Should translate to a 'bswap' instruction in assembly */
#define BSWAP64(in) (u64)((u64)(((u64)(in) & (u64)0x00000000000000ffULL) << 56) |\
		(u64)(((u64)(in) & (u64)0x000000000000ff00ULL) << 40) |\
		(u64)(((u64)(in) & (u64)0x0000000000ff0000ULL) << 24) |\
		(u64)(((u64)(in) & (u64)0x00000000ff000000ULL) <<  8) |\
	        (u64)(((u64)(in) & (u64)0x000000ff00000000ULL) >>  8) |\
		(u64)(((u64)(in) & (u64)0x0000ff0000000000ULL) >> 24) |\
		(u64)(((u64)(in) & (u64)0x00ff000000000000ULL) >> 40) |\
		(u64)(((u64)(in) & (u64)0xff00000000000000ULL) >> 56) )
/* Should translate to a 'rot' instruction in assembly */
#define ROTL64(in, l) ((in) << l) ^ ((in) >> (64-l))
#define ROTR64(in, l) ((in) >> l) ^ ((in) << (64-l))

#define MASK4  0x0f
#define MASK8  0xff
#define MASK16 0xffff

#define PRESENTKS80(keyLow, keyHigh, round) do {\
	u64 temp;\
	keyHigh  ^= TroundCounters80[round];\
	temp      = keyHigh;\
	keyHigh <<= 61;\
	keyHigh  |= (keyLow << 45);\
	keyHigh  |= (temp >> 19);\
	keyLow    = (temp >> 3) & 0xffff;\
	temp      = keyHigh >> 60;\
	keyHigh  &= 0x0fffffffffffffff;\
	temp      = TsboxKS80[temp];\
	keyHigh  |= temp;\
} while(0);

#define PRESENTKS128(keyLow, keyHigh, round) do {\
	u64 temp;\
	keyLow  ^= TroundCounters128[round];\
	temp     = keyHigh;\
	keyHigh  = (temp   & 0x0000000000000007) << 61;\
	keyHigh |= (keyLow & 0xfffffffffffffff8) >> 3;\
	keyLow   = (keyLow & 0x0000000000000007) << 61;\
	keyLow  |= (temp   & 0xfffffffffffffff8) >> 3;\
	temp      = keyHigh >> 56;\
	keyHigh  &= 0x00ffffffffffffff;\
	temp      = TsboxKS128[temp];\
	keyHigh  |= temp;\
} while(0);

#define PRESENTROUND(state) do {\
	u64 stateIn;\
	stateIn = state;\
	state  = T0_PRESENT[stateIn & MASK8];\
	state ^= T1_PRESENT[(stateIn >> 8) & MASK8];\
	state ^= T2_PRESENT[(stateIn >> 16) & MASK8];\
	state ^= T3_PRESENT[(stateIn >> 24) & MASK8];\
	state ^= T4_PRESENT[(stateIn >> 32) & MASK8];\
	state ^= T5_PRESENT[(stateIn >> 40) & MASK8];\
	state ^= T6_PRESENT[(stateIn >> 48) & MASK8];\
	state ^= T7_PRESENT[(stateIn >> 56) & MASK8];\
} while(0);



/****************************************************************************************************/
/* PRESENT80 key schedule                                                                           */
#ifdef PRESENT80
void PRESENT80table_key_schedule(const u8* masterKey80, u8* roundKeys80)
{
	u64 currentKeyLow, currentKeyHigh;

	/* get low and high parts of master key */
	currentKeyHigh = BSWAP64(((u64 *)masterKey80)[0]);
	currentKeyLow  = (BSWAP64(((u16 *)(masterKey80+8))[0])) >> 48;

	/* get round key 0 and compute round key 1 */
	((u64 *)roundKeys80)[0] = currentKeyHigh;
	PRESENTKS80(currentKeyLow, currentKeyHigh, 0);

	/* get round key 1 and compute round key 2 */
	((u64 *)roundKeys80)[1] = currentKeyHigh;
	PRESENTKS80(currentKeyLow, currentKeyHigh, 1);

	/* get round key 2 and compute round key 3 */
	((u64 *)roundKeys80)[2] = currentKeyHigh;
	PRESENTKS80(currentKeyLow, currentKeyHigh, 2);

	/* get round key 3 and compute round key 4 */
	((u64 *)roundKeys80)[3] = currentKeyHigh;
	PRESENTKS80(currentKeyLow, currentKeyHigh, 3);

	/* get round key 4 and compute round key 5 */
	((u64 *)roundKeys80)[4] = currentKeyHigh;
	PRESENTKS80(currentKeyLow, currentKeyHigh, 4);

	/* get round key 5 and compute round key 6 */
	((u64 *)roundKeys80)[5] = currentKeyHigh;
	PRESENTKS80(currentKeyLow, currentKeyHigh, 5);

	/* get round key 6 and compute round key 7 */
	((u64 *)roundKeys80)[6] = currentKeyHigh;
	PRESENTKS80(currentKeyLow, currentKeyHigh, 6);

	/* get round key 7 and compute round key 8 */
	((u64 *)roundKeys80)[7] = currentKeyHigh;
	PRESENTKS80(currentKeyLow, currentKeyHigh, 7);

	/* get round key 8 and compute round key 9 */
	((u64 *)roundKeys80)[8] = currentKeyHigh;
	PRESENTKS80(currentKeyLow, currentKeyHigh, 8);

	/* get round key 9 and compute round key 10 */
	((u64 *)roundKeys80)[9] = currentKeyHigh;
	PRESENTKS80(currentKeyLow, currentKeyHigh, 9);

	/* get round key 10 and compute round key 11 */
	((u64 *)roundKeys80)[10] = currentKeyHigh;
	PRESENTKS80(currentKeyLow, currentKeyHigh, 10);

	/* get round key 11 and compute round key 12 */
	((u64 *)roundKeys80)[11] = currentKeyHigh;
	PRESENTKS80(currentKeyLow, currentKeyHigh, 11);

	/* get round key 12 and compute round key 13 */
	((u64 *)roundKeys80)[12] = currentKeyHigh;
	PRESENTKS80(currentKeyLow, currentKeyHigh, 12);

	/* get round key 13 and compute round key 14 */
	((u64 *)roundKeys80)[13] = currentKeyHigh;
	PRESENTKS80(currentKeyLow, currentKeyHigh, 13);

	/* get round key 14 and compute round key 15 */
	((u64 *)roundKeys80)[14] = currentKeyHigh;
	PRESENTKS80(currentKeyLow, currentKeyHigh, 14);

	/* get round key 15 and compute round key 16 */
	((u64 *)roundKeys80)[15] = currentKeyHigh;
	PRESENTKS80(currentKeyLow, currentKeyHigh, 15);

	/* get round key 16 and compute round key 17 */
	((u64 *)roundKeys80)[16] = currentKeyHigh;
	PRESENTKS80(currentKeyLow, currentKeyHigh, 16);

	/* get round key 17 and compute round key 18 */
	((u64 *)roundKeys80)[17] = currentKeyHigh;
	PRESENTKS80(currentKeyLow, currentKeyHigh, 17);

	/* get round key 18 and compute round key 19 */
	((u64 *)roundKeys80)[18] = currentKeyHigh;
	PRESENTKS80(currentKeyLow, currentKeyHigh, 18);

	/* get round key 19 and compute round key 20 */
	((u64 *)roundKeys80)[19] = currentKeyHigh;
	PRESENTKS80(currentKeyLow, currentKeyHigh, 19);

	/* get round key 20 and compute round key 21 */
	((u64 *)roundKeys80)[20] = currentKeyHigh;
	PRESENTKS80(currentKeyLow, currentKeyHigh, 20);

	/* get round key 21 and compute round key 22 */
	((u64 *)roundKeys80)[21] = currentKeyHigh;
	PRESENTKS80(currentKeyLow, currentKeyHigh, 21);

	/* get round key 22 and compute round key 23 */
	((u64 *)roundKeys80)[22] = currentKeyHigh;
	PRESENTKS80(currentKeyLow, currentKeyHigh, 22);

	/* get round key 23 and compute round key 24 */
	((u64 *)roundKeys80)[23] = currentKeyHigh;
	PRESENTKS80(currentKeyLow, currentKeyHigh, 23);

	/* get round key 24 and compute round key 25 */
	((u64 *)roundKeys80)[24] = currentKeyHigh;
	PRESENTKS80(currentKeyLow, currentKeyHigh, 24);

	/* get round key 25 and compute round key 26 */
	((u64 *)roundKeys80)[25] = currentKeyHigh;
	PRESENTKS80(currentKeyLow, currentKeyHigh, 25);

	/* get round key 26 and compute round key 27 */
	((u64 *)roundKeys80)[26] = currentKeyHigh;
	PRESENTKS80(currentKeyLow, currentKeyHigh, 26);

	/* get round key 27 and compute round key 28 */
	((u64 *)roundKeys80)[27] = currentKeyHigh;
	PRESENTKS80(currentKeyLow, currentKeyHigh, 27);

	/* get round key 28 and compute round key 29 */
	((u64 *)roundKeys80)[28] = currentKeyHigh;
	PRESENTKS80(currentKeyLow, currentKeyHigh, 28);

	/* get round key 29 and compute round key 30 */
	((u64 *)roundKeys80)[29] = currentKeyHigh;
	PRESENTKS80(currentKeyLow, currentKeyHigh, 29);

	/* get round key 30 and compute round key 31 */
	((u64 *)roundKeys80)[30] = currentKeyHigh;
	PRESENTKS80(currentKeyLow, currentKeyHigh, 30);

	/* get round key 31 */
	((u64 *)roundKeys80)[31] = currentKeyHigh;

	return;
}
#endif



/****************************************************************************************************/
/* PRESENT128 key schedule                                                                          */
#ifdef PRESENT128
void PRESENT128table_key_schedule(const u8* masterKey128, u8* roundKeys128)
{
	u64 currentKeyLow, currentKeyHigh;

	/* get low and high parts of master key */
	currentKeyHigh = BSWAP64(((u64 *)masterKey128)[0]);
	currentKeyLow = BSWAP64(((u64 *)masterKey128)[1]);

	/* get round key 0 and compute round key 1 */
	((u64 *)roundKeys128)[0] = currentKeyHigh;
	PRESENTKS128(currentKeyLow, currentKeyHigh, 0);

	/* get round key 1 and compute round key 2 */
	((u64 *)roundKeys128)[1] = currentKeyHigh;
	PRESENTKS128(currentKeyLow, currentKeyHigh, 1);

	/* get round key 2 and compute round key 3 */
	((u64 *)roundKeys128)[2] = currentKeyHigh;
	PRESENTKS128(currentKeyLow, currentKeyHigh, 2);

	/* get round key 3 and compute round key 4 */
	((u64 *)roundKeys128)[3] = currentKeyHigh;
	PRESENTKS128(currentKeyLow, currentKeyHigh, 3);

	/* get round key 4 and compute round key 5 */
	((u64 *)roundKeys128)[4] = currentKeyHigh;
	PRESENTKS128(currentKeyLow, currentKeyHigh, 4);

	/* get round key 5 and compute round key 6 */
	((u64 *)roundKeys128)[5] = currentKeyHigh;
	PRESENTKS128(currentKeyLow, currentKeyHigh, 5);

	/* get round key 6 and compute round key 7 */
	((u64 *)roundKeys128)[6] = currentKeyHigh;
	PRESENTKS128(currentKeyLow, currentKeyHigh, 6);

	/* get round key 7 and compute round key 8 */
	((u64 *)roundKeys128)[7] = currentKeyHigh;
	PRESENTKS128(currentKeyLow, currentKeyHigh, 7);

	/* get round key 8 and compute round key 9 */
	((u64 *)roundKeys128)[8] = currentKeyHigh;
	PRESENTKS128(currentKeyLow, currentKeyHigh, 8);

	/* get round key 9 and compute round key 10 */
	((u64 *)roundKeys128)[9] = currentKeyHigh;
	PRESENTKS128(currentKeyLow, currentKeyHigh, 9);

	/* get round key 10 and compute round key 11 */
	((u64 *)roundKeys128)[10] = currentKeyHigh;
	PRESENTKS128(currentKeyLow, currentKeyHigh, 10);

	/* get round key 11 and compute round key 12 */
	((u64 *)roundKeys128)[11] = currentKeyHigh;
	PRESENTKS128(currentKeyLow, currentKeyHigh, 11);

	/* get round key 12 and compute round key 13 */
	((u64 *)roundKeys128)[12] = currentKeyHigh;
	PRESENTKS128(currentKeyLow, currentKeyHigh, 12);

	/* get round key 13 and compute round key 14 */
	((u64 *)roundKeys128)[13] = currentKeyHigh;
	PRESENTKS128(currentKeyLow, currentKeyHigh, 13);

	/* get round key 14 and compute round key 15 */
	((u64 *)roundKeys128)[14] = currentKeyHigh;
	PRESENTKS128(currentKeyLow, currentKeyHigh, 14);

	/* get round key 15 and compute round key 16 */
	((u64 *)roundKeys128)[15] = currentKeyHigh;
	PRESENTKS128(currentKeyLow, currentKeyHigh, 15);

	/* get round key 16 and compute round key 17 */
	((u64 *)roundKeys128)[16] = currentKeyHigh;
	PRESENTKS128(currentKeyLow, currentKeyHigh, 16);

	/* get round key 17 and compute round key 18 */
	((u64 *)roundKeys128)[17] = currentKeyHigh;
	PRESENTKS128(currentKeyLow, currentKeyHigh, 17);

	/* get round key 18 and compute round key 19 */
	((u64 *)roundKeys128)[18] = currentKeyHigh;
	PRESENTKS128(currentKeyLow, currentKeyHigh, 18);

	/* get round key 19 and compute round key 20 */
	((u64 *)roundKeys128)[19] = currentKeyHigh;
	PRESENTKS128(currentKeyLow, currentKeyHigh, 19);

	/* get round key 20 and compute round key 21 */
	((u64 *)roundKeys128)[20] = currentKeyHigh;
	PRESENTKS128(currentKeyLow, currentKeyHigh, 20);

	/* get round key 21 and compute round key 22 */
	((u64 *)roundKeys128)[21] = currentKeyHigh;
	PRESENTKS128(currentKeyLow, currentKeyHigh, 21);

	/* get round key 22 and compute round key 23 */
	((u64 *)roundKeys128)[22] = currentKeyHigh;
	PRESENTKS128(currentKeyLow, currentKeyHigh, 22);

	/* get round key 23 and compute round key 24 */
	((u64 *)roundKeys128)[23] = currentKeyHigh;
	PRESENTKS128(currentKeyLow, currentKeyHigh, 23);

	/* get round key 24 and compute round key 25 */
	((u64 *)roundKeys128)[24] = currentKeyHigh;
	PRESENTKS128(currentKeyLow, currentKeyHigh, 24);

	/* get round key 25 and compute round key 26 */
	((u64 *)roundKeys128)[25] = currentKeyHigh;
	PRESENTKS128(currentKeyLow, currentKeyHigh, 25);

	/* get round key 26 and compute round key 27 */
	((u64 *)roundKeys128)[26] = currentKeyHigh;
	PRESENTKS128(currentKeyLow, currentKeyHigh, 26);

	/* get round key 27 and compute round key 28 */
	((u64 *)roundKeys128)[27] = currentKeyHigh;
	PRESENTKS128(currentKeyLow, currentKeyHigh, 27);

	/* get round key 28 and compute round key 29 */
	((u64 *)roundKeys128)[28] = currentKeyHigh;
	PRESENTKS128(currentKeyLow, currentKeyHigh, 28);

	/* get round key 29 and compute round key 30 */
	((u64 *)roundKeys128)[29] = currentKeyHigh;
	PRESENTKS128(currentKeyLow, currentKeyHigh, 29);

	/* get round key 30 and compute round key 31 */
	((u64 *)roundKeys128)[30] = currentKeyHigh;
	PRESENTKS128(currentKeyLow, currentKeyHigh, 30);

	/* get round key 31 */
	((u64 *)roundKeys128)[31] = currentKeyHigh;

	return;
}
#endif



/****************************************************************************************************/
/* PRESENT80 encryption core                                                                        */
#ifdef PRESENT80
void PRESENT80table_core(const u8* plaintext, const u8* roundKeys80, u8* ciphertext)
{
	u64 * state, * roundKeys;

	/* cast variables */
	*((u64*)ciphertext) = BSWAP64(*((u64*)plaintext));
	state     = (u64 *)ciphertext;
	roundKeys = (u64 *)roundKeys80;

	/* round 1 */
	state[0] ^= roundKeys[0];
	PRESENTROUND(state[0]);

	/* round 2 */
	state[0] ^= roundKeys[1];
	PRESENTROUND(state[0]);

	/* round 3 */
	state[0] ^= roundKeys[2];
	PRESENTROUND(state[0]);

	/* round 4 */
	state[0] ^= roundKeys[3];
	PRESENTROUND(state[0]);

	/* round 5 */
	state[0] ^= roundKeys[4];
	PRESENTROUND(state[0]);

	/* round 6 */
	state[0] ^= roundKeys[5];
	PRESENTROUND(state[0]);

	/* round 7 */
	state[0] ^= roundKeys[6];
	PRESENTROUND(state[0]);

	/* round 8 */
	state[0] ^= roundKeys[7];
	PRESENTROUND(state[0]);

	/* round 9 */
	state[0] ^= roundKeys[8];
	PRESENTROUND(state[0]);

	/* round 10 */
	state[0] ^= roundKeys[9];
	PRESENTROUND(state[0]);

	/* round 11 */
	state[0] ^= roundKeys[10];
	PRESENTROUND(state[0]);

	/* round 12 */
	state[0] ^= roundKeys[11];
	PRESENTROUND(state[0]);

	/* round 13 */
	state[0] ^= roundKeys[12];
	PRESENTROUND(state[0]);

	/* round 14 */
	state[0] ^= roundKeys[13];
	PRESENTROUND(state[0]);

	/* round 15 */
	state[0] ^= roundKeys[14];
	PRESENTROUND(state[0]);

	/* round 16 */
	state[0] ^= roundKeys[15];
	PRESENTROUND(state[0]);

	/* round 17 */
	state[0] ^= roundKeys[16];
	PRESENTROUND(state[0]);

	/* round 18 */
	state[0] ^= roundKeys[17];
	PRESENTROUND(state[0]);

	/* round 19 */
	state[0] ^= roundKeys[18];
	PRESENTROUND(state[0]);

	/* round 20 */
	state[0] ^= roundKeys[19];
	PRESENTROUND(state[0]);

	/* round 21 */
	state[0] ^= roundKeys[20];
	PRESENTROUND(state[0]);

	/* round 22 */
	state[0] ^= roundKeys[21];
	PRESENTROUND(state[0]);

	/* round 23 */
	state[0] ^= roundKeys[22];
	PRESENTROUND(state[0]);

	/* round 24 */
	state[0] ^= roundKeys[23];
	PRESENTROUND(state[0]);

	/* round 25 */
	state[0] ^= roundKeys[24];
	PRESENTROUND(state[0]);

	/* round 26 */
	state[0] ^= roundKeys[25];
	PRESENTROUND(state[0]);

	/* round 27 */
	state[0] ^= roundKeys[26];
	PRESENTROUND(state[0]);

	/* round 28 */
	state[0] ^= roundKeys[27];
	PRESENTROUND(state[0]);

	/* round 29 */
	state[0] ^= roundKeys[28];
	PRESENTROUND(state[0]);

	/* round 30 */
	state[0] ^= roundKeys[29];
	PRESENTROUND(state[0]);

	/* round 31 */
	state[0] ^= roundKeys[30];
	PRESENTROUND(state[0]);

	/* last addRoundKey */
	state[0] ^= roundKeys[31];

	/* endianness handling */
	state[0] = BSWAP64(state[0]);

	return;
}
#endif



/****************************************************************************************************/
/* PRESENT128 encryption core                                                                       */
#ifdef PRESENT128
void PRESENT128table_core(const u8* plaintext, const u8* roundKeys128, u8* ciphertext)
{
	u64 * state, * roundKeys;

	/* cast variables */
	*((u64*)ciphertext) = BSWAP64(*((u64*)plaintext));
	state     = (u64 *)ciphertext;
	roundKeys = (u64 *)roundKeys128;

	/* round 1 */
	state[0] ^= roundKeys[0];
	PRESENTROUND(state[0]);

	/* round 2 */
	state[0] ^= roundKeys[1];
	PRESENTROUND(state[0]);

	/* round 3 */
	state[0] ^= roundKeys[2];
	PRESENTROUND(state[0]);

	/* round 4 */
	state[0] ^= roundKeys[3];
	PRESENTROUND(state[0]);

	/* round 5 */
	state[0] ^= roundKeys[4];
	PRESENTROUND(state[0]);

	/* round 6 */
	state[0] ^= roundKeys[5];
	PRESENTROUND(state[0]);

	/* round 7 */
	state[0] ^= roundKeys[6];
	PRESENTROUND(state[0]);

	/* round 8 */
	state[0] ^= roundKeys[7];
	PRESENTROUND(state[0]);

	/* round 9 */
	state[0] ^= roundKeys[8];
	PRESENTROUND(state[0]);

	/* round 10 */
	state[0] ^= roundKeys[9];
	PRESENTROUND(state[0]);

	/* round 11 */
	state[0] ^= roundKeys[10];
	PRESENTROUND(state[0]);

	/* round 12 */
	state[0] ^= roundKeys[11];
	PRESENTROUND(state[0]);

	/* round 13 */
	state[0] ^= roundKeys[12];
	PRESENTROUND(state[0]);

	/* round 14 */
	state[0] ^= roundKeys[13];
	PRESENTROUND(state[0]);

	/* round 15 */
	state[0] ^= roundKeys[14];
	PRESENTROUND(state[0]);

	/* round 16 */
	state[0] ^= roundKeys[15];
	PRESENTROUND(state[0]);

	/* round 17 */
	state[0] ^= roundKeys[16];
	PRESENTROUND(state[0]);

	/* round 18 */
	state[0] ^= roundKeys[17];
	PRESENTROUND(state[0]);

	/* round 19 */
	state[0] ^= roundKeys[18];
	PRESENTROUND(state[0]);

	/* round 20 */
	state[0] ^= roundKeys[19];
	PRESENTROUND(state[0]);

	/* round 21 */
	state[0] ^= roundKeys[20];
	PRESENTROUND(state[0]);

	/* round 22 */
	state[0] ^= roundKeys[21];
	PRESENTROUND(state[0]);

	/* round 23 */
	state[0] ^= roundKeys[22];
	PRESENTROUND(state[0]);

	/* round 24 */
	state[0] ^= roundKeys[23];
	PRESENTROUND(state[0]);

	/* round 25 */
	state[0] ^= roundKeys[24];
	PRESENTROUND(state[0]);

	/* round 26 */
	state[0] ^= roundKeys[25];
	PRESENTROUND(state[0]);

	/* round 27 */
	state[0] ^= roundKeys[26];
	PRESENTROUND(state[0]);

	/* round 28 */
	state[0] ^= roundKeys[27];
	PRESENTROUND(state[0]);

	/* round 29 */
	state[0] ^= roundKeys[28];
	PRESENTROUND(state[0]);

	/* round 30 */
	state[0] ^= roundKeys[29];
	PRESENTROUND(state[0]);

	/* round 31 */
	state[0] ^= roundKeys[30];
	PRESENTROUND(state[0]);

	/* last addRoundKey */
	state[0] ^= roundKeys[31];

	/* endianness handling */
	state[0] = BSWAP64(state[0]);

	return;
}
#endif



/****************************************************************************************************/
/* PRESENT80 key schedule + encryption                                                              */
#ifdef PRESENT80
void PRESENT80table_cipher(const u64 plaintext_in[TABLE_P], const u16 keys_in[TABLE_P][KEY80], u64 ciphertext_out[TABLE_P])
{
	/* Key schedule: subkeys are of size 2*264 bytes */
	u8 subkeys[TABLE_P * PRESENT80_SUBKEYS_SIZE];

#ifdef MEASURE_PERF
	key_schedule_start = rdtsc();
#endif

	/* Compute the subkeys */
	PRESENT80table_key_schedule((const u8*)keys_in, subkeys);

#ifdef MEASURE_PERF
	key_schedule_end = rdtsc();
#endif

#ifdef MEASURE_PERF
	encrypt_start = rdtsc();
#endif

	/* Call the core encryption */
	PRESENT80table_core((const u8*)plaintext_in, subkeys, (u8*)ciphertext_out);

#ifdef MEASURE_PERF
	encrypt_end = rdtsc();
#endif

	return;
}
#endif



/****************************************************************************************************/
/* PRESENT128 key schedule + encryption                                                             */
#ifdef PRESENT128
void PRESENT128table_cipher(const u64 plaintext_in[TABLE_P], const u16 keys_in[TABLE_P][KEY128], u64 ciphertext_out[TABLE_P])
{
	/* Key schedule: subkeys are of size 2*264 bytes */
	u8 subkeys[TABLE_P * PRESENT128_SUBKEYS_SIZE];

#ifdef MEASURE_PERF
	key_schedule_start = rdtsc();
#endif

	/* Compute the subkeys */
	PRESENT128table_key_schedule((const u8*)keys_in, subkeys);

#ifdef MEASURE_PERF
	key_schedule_end = rdtsc();
#endif

#ifdef MEASURE_PERF
	encrypt_start = rdtsc();
#endif

	/* Call the core encryption */
	PRESENT128table_core((const u8*)plaintext_in, subkeys, (u8*)ciphertext_out);

#ifdef MEASURE_PERF
	encrypt_end = rdtsc();
#endif

	return;
}
#endif

#endif
