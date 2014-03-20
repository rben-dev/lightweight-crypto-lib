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
