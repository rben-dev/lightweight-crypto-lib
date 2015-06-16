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
#ifdef BITSLICE
#include "Piccolo_util.h"

#ifdef BITSLICE
#ifdef Piccolo80
void Piccolo80bitslice16_key_schedule(const u8* masterKey, u8* roundKeys);
void Piccolo80bitslice16_core(const u8* message, const u8* subkeys, u8* ciphertext);
void Piccolo80bitslice16_cipher(const u64 plaintext[BITSLICE16_P], const u16 masterkeys[BITSLICE16_P][KEY80], u64 ciphertext[BITSLICE16_P]);
#endif
#ifdef Piccolo128
void Piccolo128bitslice16_key_schedule(const u8* masterKey, u8* roundKeys);
void Piccolo128bitslice16_core(const u8* message, const u8* subkeys, u8* ciphertext);
void Piccolo128bitslice16_cipher(const u64 plaintext[BITSLICE16_P], const u16 masterkeys[BITSLICE16_P][KEY128], u64 ciphertext[BITSLICE16_P]);
#endif
#endif

#ifdef Piccolo80
void Piccolo80bitslice16_key_schedule(const u8* masterKey, u8* roundKeys){
	/* FIXME: this should not be necessary ...  */
	/* Input keys rearrangement for convenience */
	u16 key[KEY80][BITSLICE16_P];
	Piccolo_rearrange_keys(masterKey, key, BITSLICE16_P, KEY80);
	
	/* load key and pack key */
	Piccolo_pack_keys80((const u16 (*)[BITSLICE16_P])key, Piccolo80_rk23(roundKeys), Piccolo80_rk01(roundKeys), Piccolo80_rk44(roundKeys), Piccolo80_wk01(roundKeys), Piccolo80_wk23(roundKeys));

	return;
}

void Piccolo80bitslice16_core(const u8* message, const u8* subkeys, u8* ciphertext){
	word s[(BITSLICE16_P/2)], t0, t1, t2, t3, t4;
	int i;

	/* load state */
	for(i = 0; i < BITSLICE16_P/2; i++){
		s[i] = LOAD(((u64*)message) + 2*i);
		inverse_bytes_endian64(s[i]);
	}
	/* pack state */
	Piccolo_packing16(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], t0, t1, t2);

	/* the encryption process */
	int r;
	AddKey(s[4], s[5], s[6], s[7], Piccolo80_wk01(subkeys)[0], Piccolo80_wk01(subkeys)[1], Piccolo80_wk01(subkeys)[2], Piccolo80_wk01(subkeys)[3]);
	for(r = 0; r < 25; r++)
	{
		F16(s[4], s[5], s[6], s[7], s[0], s[1], s[2], s[3], t0, t1, t2, t3, t4);
		switch(r%5){
			case 0:
			case 2: AddKey(s[0], s[1], s[2], s[3], Piccolo80_rk23(subkeys)[0], Piccolo80_rk23(subkeys)[1], Piccolo80_rk23(subkeys)[2], Piccolo80_rk23(subkeys)[3]); 
					  break;
			case 1:
			case 4: AddKey(s[0], s[1], s[2], s[3], Piccolo80_rk01(subkeys)[0], Piccolo80_rk01(subkeys)[1], Piccolo80_rk01(subkeys)[2], Piccolo80_rk01(subkeys)[3]);
					  break;
			case 3: AddKey(s[0], s[1], s[2], s[3], Piccolo80_rk44(subkeys)[0], Piccolo80_rk44(subkeys)[1], Piccolo80_rk44(subkeys)[2], Piccolo80_rk44(subkeys)[3]); 
					  break;
		}
		AddKey(s[0], s[1], s[2], s[3], Piccolo80_constants[r][0], Piccolo80_constants[r][1], Piccolo80_constants[r][2], Piccolo80_constants[r][3]);
		if(r < 24){
			Piccolo_RoundPermutation(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]);
		}
	}

	AddKey(s[4], s[5], s[6], s[7], Piccolo80_wk23(subkeys)[0], Piccolo80_wk23(subkeys)[1], Piccolo80_wk23(subkeys)[2], Piccolo80_wk23(subkeys)[3]);

	/* unpack state */
	Piccolo_unpacking16(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], t0, t1, t2);
	/* store the results back to ciphertext */
	for(i = 0; i < (BITSLICE16_P/2); i++){
		inverse_bytes_endian64(s[i]);
		STORE(s[i], ((u64*)ciphertext) + 2*i);
	}

	return;
}

void Piccolo80bitslice16_cipher(const u64 plaintext[BITSLICE16_P], const u16 masterkeys[BITSLICE16_P][KEY80], u64 ciphertext[BITSLICE16_P])
{
	u8 subkeys[BITSLICE16_P * Piccolo80_SUBKEYS_SIZE];

	Piccolo_init();

#ifdef MEASURE_PERF
        key_schedule_start = rdtsc();
#endif
	Piccolo80bitslice16_key_schedule((u8*)masterkeys, (u8*)subkeys);
#ifdef MEASURE_PERF
        key_schedule_end = rdtsc();
#endif

#ifdef MEASURE_PERF
        encrypt_start = rdtsc();
#endif
	Piccolo80bitslice16_core((u8*)plaintext, (u8*)subkeys, (u8*)ciphertext);
#ifdef MEASURE_PERF
        encrypt_end = rdtsc();
#endif

	return;
}
#endif

#ifdef Piccolo128
int Piccolo128_key_constants0[31] = {2, 4, 6, 2, 6, 0, 4, 6, 4, 2, 0, 4, 0, 6, 2, 0, 2, 4, 6, 2, 6, 0, 4, 6, 4, 2, 0, 4, 0, 6, 2};
int Piccolo128_key_constants1[31] = {3, 5, 7, 1, 7, 3, 5, 1, 5, 7, 3, 1, 3, 5, 7, 1, 7, 3, 5, 1, 5, 7, 3, 1, 3, 5, 7, 1, 7, 3, 5};

void Piccolo128bitslice16_key_schedule(const u8* masterKey, u8* roundKeys){
	/* FIXME: this should not be necessary ...  */
	/* Input keys rearrangement for convenience */
	u16 key[KEY128][BITSLICE16_P];
	Piccolo_rearrange_keys(masterKey, key, BITSLICE16_P, KEY128);

	/* load key and pack key */
	Piccolo_pack_keys128((const u16 (*)[BITSLICE16_P])key, Piccolo128_rk(roundKeys, 0), Piccolo128_wk01(roundKeys), Piccolo128_wk23(roundKeys));

	return;
}

void Piccolo128bitslice16_core(const u8* message, const u8* subkeys, u8* ciphertext){
	int i;
	word s[(BITSLICE16_P/2)], t0, t1, t2, t3, t4;

	/* load state */
	for(i = 0; i < (BITSLICE16_P/2); i++){
		s[i] = LOAD(((u64*)message) + 2*i);
		inverse_bytes_endian64(s[i]);
	}
	/* pack state */
	Piccolo_packing16(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], t0, t1, t2);

	/* the encryption process */
	int r;
	AddKey(s[4], s[5], s[6], s[7], Piccolo128_wk01(subkeys)[0], Piccolo128_wk01(subkeys)[1], Piccolo128_wk01(subkeys)[2], Piccolo128_wk01(subkeys)[3]);
	for(r = 0; r < 31; r++)
	{
		F16(s[4], s[5], s[6], s[7], s[0], s[1], s[2], s[3], t0, t1, t2, t3, t4);
		int keyc0 = Piccolo128_key_constants0[r];
		int keyc1 = Piccolo128_key_constants1[r];
		AddKey(s[0], s[1], s[2], s[3], Piccolo128_rk(subkeys,keyc0)[0], Piccolo128_rk(subkeys,keyc0)[1], Piccolo128_rk(subkeys,keyc0)[2], Piccolo128_rk(subkeys,keyc0)[3]);
		AddKey(s[0], s[1], s[2], s[3], Piccolo128_rk(subkeys,keyc1)[0], Piccolo128_rk(subkeys,keyc1)[1], Piccolo128_rk(subkeys,keyc1)[2], Piccolo128_rk(subkeys,keyc1)[3]);
		AddKey(s[0], s[1], s[2], s[3], Piccolo128_constants[r][0], Piccolo128_constants[r][1], Piccolo128_constants[r][2], Piccolo128_constants[r][3]);
		if(r < 30){
			Piccolo_RoundPermutation(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]);
		}
	}

	AddKey(s[4], s[5], s[6], s[7], Piccolo128_wk23(subkeys)[0], Piccolo128_wk23(subkeys)[1], Piccolo128_wk23(subkeys)[2], Piccolo128_wk23(subkeys)[3]);

	/* unpack state */
	Piccolo_unpacking16(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], t0, t1, t2);
	/* store the results back to ciphertext */
	for(i = 0; i < (BITSLICE16_P/2); i++){
		inverse_bytes_endian64(s[i]);
		STORE(s[i], ((u64*)ciphertext) + 2*i);
	}

	return;
}

void Piccolo128bitslice16_cipher(const u64 plaintext[BITSLICE16_P], const u16 masterkeys[BITSLICE16_P][KEY128], u64 ciphertext[BITSLICE16_P])
{
	u8 subkeys[BITSLICE16_P * Piccolo128_SUBKEYS_SIZE];

	Piccolo_init();

#ifdef MEASURE_PERF
        key_schedule_start = rdtsc();
#endif
	Piccolo128bitslice16_key_schedule((u8*)masterkeys, (u8*)subkeys);
#ifdef MEASURE_PERF
        key_schedule_end = rdtsc();
#endif

#ifdef MEASURE_PERF
        encrypt_start = rdtsc();
#endif
        Piccolo128bitslice16_core((u8*)plaintext, (u8*)subkeys, (u8*)ciphertext);
#ifdef MEASURE_PERF
        encrypt_end = rdtsc();
#endif

	return;
}
#endif

#endif
