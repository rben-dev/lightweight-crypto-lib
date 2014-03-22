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

    The current source code is part of the bitslice implementations
    source tree.

    Project: Lightweight cryptography library
    File:    src/bitslice/LED/LED.c

-------------------------- CeCILL-B HEADER ----------------------------------*/
#ifdef BITSLICE
#include "LED_utils.h"

#ifdef BITSLICE
#ifdef LED64
void LED64bitslice16_key_schedule(const u8* masterKey, u8* roundKeys);
void LED64bitslice16_core(const u8* message, const u8* subkeys, u8* ciphertext);
void LED64bitslice16_cipher(const u64 plaintext[BITSLICE16_P], const u16 key[BITSLICE16_P][KEY64], u64 ciphertext[BITSLICE16_P]);
void LED64bitslice32_key_schedule(const u8* masterKey, u8* roundKeys);
void LED64bitslice32_core(const u8* message, const u8* subkeys, u8* ciphertext);
void LED64bitslice32_cipher(const u64 plaintext[BITSLICE16_P], const u16 key[BITSLICE16_P][KEY64], u64 ciphertext[BITSLICE16_P]);
#endif
#ifdef LED128
void LED128bitslice16_key_schedule(const u8* masterKey, u8* roundKeys);
void LED128bitslice16_core(const u8* message, const u8* subkeys, u8* ciphertext);
void LED128bitslice16_cipher(const u64 plaintext[BITSLICE16_P], const u16 key[BITSLICE16_P][KEY128], u64 ciphertext[BITSLICE16_P]);
void LED128bitslice32_key_schedule(const u8* masterKey, u8* roundKeys);
void LED128bitslice32_core(const u8* message, const u8* subkeys, u8* ciphertext);
void LED128bitslice32_cipher(const u64 plaintext[BITSLICE32_P], const u16 key[BITSLICE32_P][KEY128], u64 ciphertext[BITSLICE32_P]);
#endif
#endif

/*************************************************************************************/
/*************************************************************************************/
#ifdef LED64
void LED64bitslice16_key_schedule(const u8* masterKey, u8* roundKeys){
	word t0, t1, t2;
	word* k = (word*)roundKeys;
	int i;
	/* loading key */
	for(i = 0; i < (BITSLICE16_P/2); i++){
		k[i] = LOAD(((u16(*)[KEY64])masterKey)[2*i]);
		inverse_nibble_endian(k[i], t0, t1);
	}
	/* packing key */
	packing16(k[0], k[1], k[2], k[3],k[4], k[5], k[6], k[7], t0, t1, t2);

	return;
}

void LED64bitslice16_core(const u8* message, const u8* subkeys, u8* ciphertext){
	word s[BITSLICE16_P/2], t0, t1, t2 ,t3, t4, t5, t6, t7, t8, t9, t10, t11;
	word* k = (word*)subkeys;
	int i, r;

	for(i = 0; i < (BITSLICE16_P/2); i++){
		s[i] = LOAD(((u64*)message)+2*i);
		inverse_nibble_endian(s[i], t0, t1);
	}
	/* packing plaintext */
	packing16(s[0], s[1], s[2], s[3],s[4], s[5], s[6], s[7], t0, t1, t2);

	/* key addition */
	for(i = 0; i < (BITSLICE16_P/2); i++) s[i] = XOR(s[i], k[i]);
	for(r = 0; r < 32; r++){
		for(i = 0; i < (BITSLICE16_P/2); i++) s[i] = XOR(s[i], constants_LED64_BITSLICE16_P[r][i]);
		SboxLayer16(s[0], s[1], s[2], s[3],s[4], s[5], s[6], s[7], t0);
		SR16(s[0], s[1], s[2], s[3],s[4], s[5], s[6], s[7]);
		MIXCOL16(s[0], s[1], s[2], s[3],s[4], s[5], s[6], s[7], t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11);
		if((r&3) == 3){
			for(i = 0; i < (BITSLICE16_P/2); i++) s[i] = XOR(s[i], k[i]);
		}
	}

	/* STORE the results */
	unpacking16(s[0], s[1], s[2], s[3],s[4], s[5], s[6], s[7], t0, t1, t2);
	for(i = 0; i < (BITSLICE16_P/2); i++){
		inverse_nibble_endian(s[i], t0, t1);
		STORE(s[i], ((u64*)ciphertext) + 2*i);
	}

	return;
}

void LED64bitslice16_cipher(const u64 plaintext[BITSLICE16_P], const u16 key[BITSLICE16_P][KEY64], u64 ciphertext[BITSLICE16_P])
{
	word subkeys[BITSLICE16_P/2];

	/* Initialize the constants: done once and for all */
	LED_init();

#ifdef MEASURE_PERF
        key_schedule_start = rdtsc();
#endif
	LED64bitslice16_key_schedule((u8*)key, (u8*)subkeys);
#ifdef MEASURE_PERF
        key_schedule_end = rdtsc();
#endif

#ifdef MEASURE_PERF
        encrypt_start = rdtsc();
#endif
	LED64bitslice16_core((u8*)plaintext, (u8*)subkeys, (u8*)ciphertext);
#ifdef MEASURE_PERF
        encrypt_end = rdtsc();
#endif

	return;
}
#endif

/*************************************************************************************/
/*************************************************************************************/
#ifdef LED128
void LED128bitslice16_key_schedule(const u8* masterKey, u8* roundKeys){
	word t0, t1, t2;
	word* k0 = (word*)roundKeys;
	word* k1 = k0 + (BITSLICE16_P/2);

	int i;
	/* loading key */
	for(i = 0; i < (BITSLICE16_P/2); i++){
		t0 = LOAD(((u16(*)[KEY128])masterKey)[2*i]);
		t1 = LOAD((((u16(*)[KEY128])masterKey)[2*i])+KEY128);
		k0[i] = PUNPCKLQDQ(t0, t1);
		k1[i] = PUNPCKHQDQ(t0, t1);
		inverse_nibble_endian(k0[i], t0, t1);
		inverse_nibble_endian(k1[i], t0, t1);
	}
	/* packing key */
	packing16(k0[0], k0[1], k0[2], k0[3],k0[4], k0[5], k0[6], k0[7], t0, t1, t2);
	packing16(k1[0], k1[1], k1[2], k1[3],k1[4], k1[5], k1[6], k1[7], t0, t1, t2);

	return;
}


void LED128bitslice16_core(const u8* message, const u8* subkeys, u8* ciphertext){
	word s[(BITSLICE16_P/2)], t0, t1, t2 ,t3, t4, t5, t6, t7, t8, t9, t10, t11;
	word* k0 = (word*)subkeys;
	word* k1 = k0 + (BITSLICE16_P/2);

	/* loading plaintext and key */
	int i, r;

	for(i = 0; i < (BITSLICE16_P/2); i++){
		s[i] = LOAD(((u64*)message)+2*i);
		inverse_nibble_endian(s[i], t0, t1);
	}
	/* packing the plaintext and key */
	packing16(s[0], s[1], s[2], s[3],s[4], s[5], s[6], s[7], t0, t1, t2);
	for(i = 0; i < (BITSLICE16_P/2); i++) s[i] = XOR(s[i], k0[i]);
	for(r = 0; r < 48; r++){
		for(i = 0; i < 8; i++) s[i] = XOR(s[i], constants_LED128_BITSLICE16_P[r][i]);
		SboxLayer16(s[0], s[1], s[2], s[3],s[4], s[5], s[6], s[7], t0);
		SR16(s[0], s[1], s[2], s[3],s[4], s[5], s[6], s[7]);
		MIXCOL16(s[0], s[1], s[2], s[3],s[4], s[5], s[6], s[7], t0, t1, t2 ,t3, t4, t5, t6, t7, t8, t9, t10, t11);
		if((r&3) == 3){
			if((r&4) == 0)
				for(i = 0; i < 8; i++) s[i] = XOR(s[i], k0[i]);
			else
				for(i = 0; i < 8; i++) s[i] = XOR(s[i], k1[i]);
		}
	}

	/* STORE the results */
	unpacking16(s[0], s[1], s[2], s[3],s[4], s[5], s[6], s[7], t0, t1, t2);
	for(i = 0; i < (BITSLICE16_P/2); i++){
		inverse_nibble_endian(s[i], t0, t1);
		STORE(s[i], ((u64*)ciphertext) + 2*i);
	}

	return;
}

void LED128bitslice16_cipher(const u64 plaintext[BITSLICE16_P], const u16 key[BITSLICE16_P][KEY128], u64 ciphertext[BITSLICE16_P])
{
	word subkeys[BITSLICE16_P];
	
	LED_init();

#ifdef MEASURE_PERF
        key_schedule_start = rdtsc();
#endif
	LED128bitslice16_key_schedule((u8*)key, (u8*)subkeys);
#ifdef MEASURE_PERF
        key_schedule_end = rdtsc();
#endif

#ifdef MEASURE_PERF
        encrypt_start = rdtsc();
#endif
	LED128bitslice16_core((u8*)plaintext, (u8*)subkeys, (u8*)ciphertext);
#ifdef MEASURE_PERF
        encrypt_end = rdtsc();
#endif

	return;
}
#endif

/*************************************************************************************/
/*************************************************************************************/
#ifdef LED64
void LED64bitslice32_key_schedule(const u8* masterKey, u8* roundKeys){
	word t0, t1, t2;
	word* k = (word*)roundKeys;
	int i;
	/* loading key */
	for(i = 0; i < (BITSLICE32_P/2); i++){
		k[i] = LOAD(((u16(*)[KEY64])masterKey)[2*i]);
		inverse_nibble_endian(k[i], t0, t1);
	}
	/* packing key */
	packing32(k[0], k[1], k[2], k[3],k[4], k[5], k[6], k[7],k[8], k[9], k[10], k[11],k[12], k[13], k[14], k[15], t0, t1, t2);

	return;
}

void LED64bitslice32_core(const u8* message, const u8* subkeys, u8* ciphertext){
	word s[BITSLICE32_P/2], t0, t1, t2 ,t3;
	word* k = (word*)subkeys;
	int i, r;

	for(i = 0; i < (BITSLICE32_P/2); i++){
		s[i] = LOAD(((u64*)message)+2*i);
		inverse_nibble_endian(s[i], t0, t1);
	}

	/* packing the plaintext and key */
	packing32(s[0], s[1], s[2], s[3],s[4], s[5], s[6], s[7],s[8], s[9], s[10], s[11],s[12], s[13], s[14], s[15], t0, t1, t2);

	for(i = 0; i < (BITSLICE32_P/2); i++) s[i] = XOR(s[i], k[i]);
	for(r = 0; r < 32; r++){
		for(i = 0; i < (BITSLICE32_P/2); i++) s[i] = XOR(s[i], constants_LED64_BITSLICE32_P[r][i]);
		SboxLayer32(s[0], s[1], s[2], s[3],s[4], s[5], s[6], s[7],s[8], s[9], s[10], s[11],s[12], s[13], s[14], s[15], t0);
		SR32(s[0], s[1], s[2], s[3],s[4], s[5], s[6], s[7],s[8], s[9], s[10], s[11],s[12], s[13], s[14], s[15]);
		MIXCOL32(s[0], s[1], s[2], s[3],s[4], s[5], s[6], s[7],s[8], s[9], s[10], s[11],s[12], s[13], s[14], s[15], t0, t1, t2, t3);
		if((r&3) == 3){
			for(i = 0; i < 16; i++) s[i] = XOR(s[i], k[i]);
		}
	}
	/* STORE the results */
	unpacking32(s[0], s[1], s[2], s[3],s[4], s[5], s[6], s[7],s[8], s[9], s[10], s[11],s[12], s[13], s[14], s[15], t0, t1, t2);
	for(i = 0; i < (BITSLICE32_P/2); i++){
		inverse_nibble_endian(s[i], t0, t1);
		STORE(s[i], ((u64*)ciphertext) + 2*i);
	}

	return;
}

void LED64bitslice32_cipher(const u64 plaintext[BITSLICE16_P], const u16 key[BITSLICE16_P][KEY64], u64 ciphertext[BITSLICE16_P])
{
	word subkeys[BITSLICE32_P/2];

	/* Initialize the constants: done once and for all */
	LED_init();

#ifdef MEASURE_PERF
        key_schedule_start = rdtsc();
#endif
	LED64bitslice32_key_schedule((u8*)key, (u8*)subkeys);
#ifdef MEASURE_PERF
        key_schedule_end = rdtsc();
#endif

#ifdef MEASURE_PERF
        encrypt_start = rdtsc();
#endif
	LED64bitslice32_core((u8*)plaintext, (u8*)subkeys, (u8*)ciphertext);
#ifdef MEASURE_PERF
        encrypt_end = rdtsc();
#endif

	return;
}
#endif

/*************************************************************************************/
/*************************************************************************************/
#ifdef LED128
void LED128bitslice32_key_schedule(const u8* masterKey, u8* roundKeys){
	word t0, t1, t2;
	word* k0 = (word*)roundKeys;
	word* k1 = k0 + (BITSLICE32_P/2);

	int i;
	/* loading key */
	for(i = 0; i < (BITSLICE32_P/2); i++){
		t0 = LOAD(((u16(*)[KEY128])masterKey)[2*i]);
		t1 = LOAD((((u16(*)[KEY128])masterKey)[2*i])+KEY128);
		k0[i] = PUNPCKLQDQ(t0, t1);
		k1[i] = PUNPCKHQDQ(t0, t1);
		inverse_nibble_endian(k0[i], t0, t1);
		inverse_nibble_endian(k1[i], t0, t1);
	}
	/* packing key */
	packing32(k0[0], k0[1], k0[2], k0[3],k0[4], k0[5], k0[6], k0[7],k0[8], k0[9], k0[10], k0[11],k0[12], k0[13], k0[14], k0[15], t0, t1, t2);
	packing32(k1[0], k1[1], k1[2], k1[3],k1[4], k1[5], k1[6], k1[7],k1[8], k1[9], k1[10], k1[11],k1[12], k1[13], k1[14], k1[15], t0, t1, t2);

	return;
}


void LED128bitslice32_core(const u8* message, const u8* subkeys, u8* ciphertext){
	word s[(BITSLICE32_P/2)], t0, t1, t2 ,t3;
	word* k0 = (word*)subkeys;
	word* k1 = k0 + (BITSLICE32_P/2);

	/* loading plaintext and key */
	int i, r;

	for(i = 0; i < (BITSLICE32_P/2); i++){
		s[i] = LOAD(((u64*)message)+2*i);
		inverse_nibble_endian(s[i], t0, t1);
	}

	/* packing the plaintext and key */
	packing32(s[0], s[1], s[2], s[3],s[4], s[5], s[6], s[7],s[8], s[9], s[10], s[11],s[12], s[13], s[14], s[15], t0, t1, t2);

	for(i = 0; i < (BITSLICE32_P/2); i++) s[i] = XOR(s[i], k0[i]);
	for(r = 0; r < 48; r++){
		for(i = 0; i < (BITSLICE32_P/2); i++) s[i] = XOR(s[i], constants_LED128_BITSLICE32_P[r][i]);
		SboxLayer32(s[0], s[1], s[2], s[3],s[4], s[5], s[6], s[7],s[8], s[9], s[10], s[11],s[12], s[13], s[14], s[15], t0);
		SR32(s[0], s[1], s[2], s[3],s[4], s[5], s[6], s[7],s[8], s[9], s[10], s[11],s[12], s[13], s[14], s[15]);
		MIXCOL32(s[0], s[1], s[2], s[3],s[4], s[5], s[6], s[7],s[8], s[9], s[10], s[11],s[12], s[13], s[14], s[15], t0, t1, t2, t3);
		if((r&3) == 3){
			if((r&4) == 0)
				for(i = 0; i < (BITSLICE32_P/2); i++) s[i] = XOR(s[i], k0[i]);
			else
				for(i = 0; i < (BITSLICE32_P/2); i++) s[i] = XOR(s[i], k1[i]);
		}
	}

	/* STORE the results */
	unpacking32(s[0], s[1], s[2], s[3],s[4], s[5], s[6], s[7],s[8], s[9], s[10], s[11],s[12], s[13], s[14], s[15], t0, t1, t2);
	for(i = 0; i < (BITSLICE32_P/2); i++){
		inverse_nibble_endian(s[i], t0, t1);
		STORE(s[i], ((u64*)ciphertext) + 2*i);
	}

	return;
}

void LED128bitslice32_cipher(const u64 plaintext[BITSLICE32_P], const u16 key[BITSLICE32_P][KEY128], u64 ciphertext[BITSLICE32_P])
{
	word subkeys[BITSLICE32_P];
	
	LED_init();

#ifdef MEASURE_PERF
        key_schedule_start = rdtsc();
#endif
	LED128bitslice32_key_schedule((u8*)key, (u8*)subkeys);
#ifdef MEASURE_PERF
        key_schedule_end = rdtsc();
#endif

#ifdef MEASURE_PERF
        encrypt_start = rdtsc();
#endif
	LED128bitslice32_core((u8*)plaintext, (u8*)subkeys, (u8*)ciphertext);
#ifdef MEASURE_PERF
        encrypt_end = rdtsc();
#endif

	return;
}
#endif

#endif
