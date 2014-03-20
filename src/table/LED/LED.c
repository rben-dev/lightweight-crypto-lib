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
