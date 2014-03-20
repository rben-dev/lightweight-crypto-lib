#include "../../common/basic_helpers.h"
#include "../../common/bitslice_common.h"

word round_constants_PRESENT80_8[32][4];
word round_constants_PRESENT80_16[32][4];
word round_constants_PRESENT128_8[32][4];
word round_constants_PRESENT128_16[32][4];

#define generate_constants(P, type) do {\
	int r;\
        u32 ff;\
	if(P == BITSLICE16_P){\
	        ff = 0xffffU;\
	}\
	else{\
	        ff = 0xffU;\
	}\
	\
	if(type == 128){\
	        for(r = 0; r < 32; r++)\
        	{\
                	u32 c[4] = { 0 };\
	                int v = r + 1;\
        	        if((v>>1)&1) c[1] = ff;\
                	if((v>>4)&1) c[2] = ff<<P;\
        	        if(v&1) c[2] ^= ff;\
	                if((v>>3)&1) c[3] = ff<<P;\
        	        if((v>>2)&1) c[0] = ff;\
                	round_constants_PRESENT ## type ## _ ## P[r][0] = SET32(0, 0, 0, c[0]);\
	                round_constants_PRESENT ## type ## _ ## P[r][1] = SET32(0, 0, 0, c[1]);\
        	        round_constants_PRESENT ## type ## _ ## P[r][2] = SET32(0, 0, 0, c[2]);\
	                round_constants_PRESENT ## type ## _ ## P[r][3] = SET32(0, 0, 0, c[3]);\
        	}\
	}\
	else{\
	        for(r = 0; r < 32; r++)\
        	{\
                	u32 c[4] = { 0 };\
	                int v = r + 1;\
        	        if((v>>1)&1) c[0] = ff;\
                	if((v>>4)&1) c[1] = ff<<P;\
	                if(v&1) c[1] ^= ff;\
        	        if((v>>3)&1) c[2] = ff<<P;\
                	if((v>>2)&1) c[3] = ff<<P;\
			if(P == BITSLICE8_P){\
		                round_constants_PRESENT ## type ## _ ## 8[r][0] = SET32(0, 0, c[0], 0);\
		                round_constants_PRESENT ## type ## _ ## 8[r][1] = SET32(0, 0, c[1], 0);\
        	        	round_constants_PRESENT ## type ## _ ## 8[r][2] = SET32(0, 0, c[2], 0);\
                		round_constants_PRESENT ## type ## _ ## 8[r][3] = SET32(0, 0, c[3], 0);\
			}\
			else{\
	        	        round_constants_PRESENT ## type ## _ ## 16[r][0] = SET32(0, c[0], 0, 0);\
	                	round_constants_PRESENT ## type ## _ ## 16[r][1] = SET32(0, c[1], 0, 0);\
	        	        round_constants_PRESENT ## type ## _ ## 16[r][2] = SET32(0, c[2], 0, 0);\
        	        	round_constants_PRESENT ## type ## _ ## 16[r][3] = SET32(0, c[3], 0, 0);\
			}\
        	}\
	}\
} while(0)


unsigned char PRESENT_init_check = 0;
void PRESENT_init(){
#ifdef THREAD_SAFE
        pthread_mutex_lock(&bitslice_init_mutex);
#endif
	if(PRESENT_init_check == 0){
		init();
		generate_constants(8 , 80);
		generate_constants(16, 80);
		generate_constants(8 ,128);
		generate_constants(16,128);
	}
	PRESENT_init_check = 1;
#ifdef THREAD_SAFE
        pthread_mutex_unlock(&bitslice_init_mutex);
#endif
	return;
}

const u64 sBox4[] = {
	0xc000000000000000ULL,
	0x5000000000000000ULL,
	0x6000000000000000ULL,
	0xb000000000000000ULL,
	0x9000000000000000ULL,
	0x0000000000000000ULL,
	0xa000000000000000ULL,
	0xd000000000000000ULL,
	0x3000000000000000ULL,
	0xe000000000000000ULL,
	0xf000000000000000ULL,
	0x8000000000000000ULL,
	0x4000000000000000ULL,
	0x7000000000000000ULL,
	0x1000000000000000ULL,
	0x2000000000000000ULL
};

#define pLayer_eight_fast(r3,r2,r1,r0,t) do {\
	word mask = SET(0x0F, 0x0B, 0x07, 0x03, 0x0E, 0x0A, 0x06, 0x02, 0x0D, 0x09, 0x05, 0x01, 0x0C, 0x08, 0x04, 0x00);\
	r0=PSHUFB(r0,mask);\
	r1=PSHUFB(r1,mask);\
	r2=PSHUFB(r2,mask);\
	r3=PSHUFB(r3,mask);\
	\
	t =PUNPCKHDQ(r2,r3);\
	r2=PUNPCKLDQ(r2,r3);\
	r3=PUNPCKHDQ(r0,r1);\
	r0=PUNPCKLDQ(r0,r1);\
	\
	r1=PUNPCKHQDQ(r0,r2);\
	r0=PUNPCKLQDQ(r0,r2);\
	r2=PUNPCKLQDQ(r3,t );\
	r3=PUNPCKHQDQ(r3,t );\
} while(0);

#define pLayer_sixteen(r0,r1,r2,r3,r4,r5,r6,r7,t0,t1) do{\
	word mask = SET(0x0f, 0x0e, 0x07, 0x06, 0x0d, 0x0c, 0x05, 0x04, 0x0b, 0x0a, 0x03, 0x02, 0x09, 0x08, 0x01, 0x00);\
	r0=PSHUFB(r0,mask);\
	r1=PSHUFB(r1,mask);\
	r2=PSHUFB(r2,mask);\
	r3=PSHUFB(r3,mask);\
	r4=PSHUFB(r4,mask);\
	r5=PSHUFB(r5,mask);\
	r6=PSHUFB(r6,mask);\
	r7=PSHUFB(r7,mask);\
	\
	t0=PUNPCKHDQ(r1,r5);\
	r1=PUNPCKLDQ(r1,r5);\
	r5=PUNPCKHDQ(r0,r4);\
	r0=PUNPCKLDQ(r0,r4);\
	\
	t1=PUNPCKHDQ(r3,r7);\
	r3=PUNPCKLDQ(r3,r7);\
	r7=PUNPCKHDQ(r2,r6);\
	r2=PUNPCKLDQ(r2,r6);\
	\
	r4=PUNPCKHQDQ(r1,r0);\
	r0=PUNPCKLQDQ(r1,r0);\
	r1=PUNPCKLQDQ(t0,r5);\
	r5=PUNPCKHQDQ(t0,r5);\
	\
	r6=PUNPCKHQDQ(r3,r2);\
	r2=PUNPCKLQDQ(r3,r2);\
	r3=PUNPCKLQDQ(t1,r7);\
	r7=PUNPCKHQDQ(t1,r7);\
	\
	t0=r6;\
	r6=r3;\
	r3=r5;\
	r5=t0;\
	\
	t1=r4;\
	r4=r2;\
	r2=r1;\
	r1=t1;\
} while(0);

#define CYCLE_L4(a, b, c, d, t0) do {\
	t0 = a; a = b; b = c; c = d; d = t0;\
} while(0);

#define ROLT128_L60(a, b, t) do {\
	t = a;\
	a = XOR(PSHUFB(a, mask128_key1), PSHUFB(b, mask128_key2));\
	b = XOR(PSHUFB(b, mask128_key1), PSHUFB(t, mask128_key2));\
} while(0);
	

#define ROLT128_L64(a, b) do{\
	word t = a;\
	a = b; b = t;\
} while(0);

#define MASK128_B2(a, b) do{\
	a = XOR(AND(a,mask128_and_b21), AND(b, mask128_and_b22));\
} while(0);

#define Key_sLayer8(k0, k1, k2, k3, t0, t1, t2, t3, t) do{\
	t0 = k0; t1 = k1; t2 = k2; t3 = k3;\
	Sbox(t0, t1, t2, t3, t);\
	\
	k0 = AND(k0, SET(0x0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff));\
	t0 = AND(t0, SET(0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));\
	k0 = XOR(k0, t0);\
	\
	k1 = AND(k1, SET(0x0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff));\
	t1 = AND(t1, SET(0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));\
	k1 = XOR(k1, t1);\
	\
	k2 = AND(k2, SET(0x0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff));\
	t2 = AND(t2, SET(0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));\
	k2 = XOR(k2, t2);\
	\
	k3 = AND(k3, SET(0x0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff));\
	t3 = AND(t3, SET(0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));\
	k3 = XOR(k3, t3);\
} while(0);

#define Key_sLayer16(k0, k1, k2, k3, t0, t1, t2, t3, t) do {\
	t0 = k0; t1 = k1; t2 = k2; t3 = k3;\
	Sbox(t0, t1, t2, t3, t);\
	\
	k0 = AND(k0, SET(0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff));\
	t0 = AND(t0, SET(0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));\
	k0 = XOR(k0, t0);\
	\
	k1 = AND(k1, SET(0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff));\
	t1 = AND(t1, SET(0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));\
	k1 = XOR(k1, t1);\
	\
	k2 = AND(k2, SET(0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff));\
	t2 = AND(t2, SET(0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));\
	k2 = XOR(k2, t2);\
	\
	k3 = AND(k3, SET(0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff));\
	t3 = AND(t3, SET(0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));\
	k3 = XOR(k3, t3);\
} while(0);

#define Key_sLayer16_present128(k0, k1, k2, k3, t0, t1, t2, t3, t) do {\
	t0 = k0; t1 = k1; t2 = k2; t3 = k3;\
	Sbox(t0, t1, t2, t3, t);\
	\
	k0 = AND(k0, SET(0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff));\
	t0 = AND(t0, SET(0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));\
	k0 = XOR(k0, t0);\
	\
	k1 = AND(k1, SET(0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff));\
	t1 = AND(t1, SET(0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));\
	k1 = XOR(k1, t1);\
	\
	k2 = AND(k2, SET(0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff));\
	t2 = AND(t2, SET(0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));\
	k2 = XOR(k2, t2);\
	\
	k3 = AND(k3, SET(0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff));\
	t3 = AND(t3, SET(0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));\
	k3 = XOR(k3, t3);\
} while(0);

#define PRESENT128bitslice8_key_schedule_step(k0, k1, k2, k3, k4, k5, k6, k7, t0, t1, t2, t3, t4, c0, c1, c2, c3) do {\
	k4 = XOR(k4, c0);\
	k5 = XOR(k5, c1);\
	k6 = XOR(k6, c2);\
	k7 = XOR(k7, c3);\
	\
	ROLT128_L60(k1, k5, t0);\
	ROLT128_L60(k2, k6, t0);\
	ROLT128_L60(k3, k7, t0);\
	ROLT128_L64(k0, k4);\
	\
	t0 = k0; t1 = k4;\
	k0 = k1; k4 = k5;\
	k1 = k2; k5 = k6;\
	k2 = k3; k6 = k7;\
	k3 = t0; k7 = t1;\
	\
	t0 = k0; t1 = k1; t2 = k2; t3 = k3;\
	Sbox(t0, t1, t2, t3, t4);\
	\
	MASK128_B2(k0, t0);\
	MASK128_B2(k1, t1);\
	MASK128_B2(k2, t2);\
	MASK128_B2(k3, t3);\
} while(0);

/* rotate 244 (240 or 256) bits to the left, each register of 128 bits */
#define ROT512_L240(a, b, c, d, t0, t1, t2) do {\
	t0 = a;\
	a = XOR(PSHUFB(b, mask512_key1), PSHUFB(c, mask512_key2));\
	t1 = d;\
	d = XOR(PSHUFB(t0, mask512_key1), PSHUFB(b, mask512_key2));\
	t2 = c;\
	c = XOR(PSHUFB(t1, mask512_key1), PSHUFB(t0, mask512_key2));\
	b = XOR(PSHUFB(t2, mask512_key1), PSHUFB(t1, mask512_key2));\
} while(0);

#define ROT512_L256(a, b, c, d, t0) do {\
	t0 = a; a = c; c = t0;\
	t0 = b; b = d; d = t0;\
} while(0);

#define PRESENT128bitslice16_key_schedule_step(k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, c0, c1, c2, c3, t0, t1, t2,t3,t) do {\
	XOR_Key(k12, k13, k14, k15, c0, c1, c2, c3);\
	ROT512_L256(k0, k4, k8, k12, t0);\
	ROT512_L240(k1, k5, k9, k13, t0, t1, t2);\
	ROT512_L240(k2, k6, k10,k14, t0, t1, t2);\
	ROT512_L240(k3, k7, k11,k15, t0, t1, t2);\
	\
	CYCLE_L4(k0,  k1,  k2,  k3, t0);\
	CYCLE_L4(k4,  k5,  k6,  k7, t0);\
	CYCLE_L4(k8,  k9,  k10, k11,t0);\
	CYCLE_L4(k12, k13, k14, k15,t0);\
	\
	Key_sLayer16_present128(k0, k1, k2, k3, t0, t1, t2, t3, t);\
} while(0);

#define PRESENT80bitslice8_key_schedule_step(k0, k1, k2, k3, k4, k5, k6, k7, t0, t1, t2, t3, t, c0, c1, c2, c3) do {\
	k0 = XOR(k0, c0);\
	k1 = XOR(k1, c1);\
	k2 = XOR(k2, c2);\
	k3 = XOR(k3, c3);\
	\
	t1 = SHRB128(k1, 1);\
	k1 = PSHUFB(k1,mask_key1);\
	t2 = PSHUFB(k5,mask_key2);\
	k1 = XOR(k1, t2);\
	k5 = t1;\
	\
	t1 = SHRB128(k2, 1);\
	k2 = PSHUFB(k2,mask_key1);\
	t2 = PSHUFB(k6,mask_key2);\
	k2 = XOR(k2, t2);\
	k6 = t1;\
	\
	t1 = SHRB128(k3, 1);\
	k3 = PSHUFB(k3,mask_key1);\
	t2 = PSHUFB(k7,mask_key2);\
	k3 = XOR(k3, t2);\
	k7 = t1;\
	\
	t1 = k0;\
	k0 = SHRB128(k0, 4);\
	t2 = SHLB128(k4, 12);\
	k0 = XOR(k0, t2);\
	k4 = t1;\
	\
	\
	t0 = k0; t1 = k1; t2 = k2; t3 = k3;\
	Sbox(t1, t2, t3, t0, t);\
	\
	k0 = AND(k0, SET(0x0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff));\
	t0 = AND(t0, SET(0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));\
	k0 = XOR(k0, t0);\
	\
	k1 = AND(k1, SET(0x0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff));\
	t1 = AND(t1, SET(0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));\
	k1 = XOR(k1, t1);\
	\
	k2 = AND(k2, SET(0x0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff));\
	t2 = AND(t2, SET(0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));\
	k2 = XOR(k2, t2);\
	\
	k3 = AND(k3, SET(0x0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff));\
	t3 = AND(t3, SET(0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));\
	k3 = XOR(k3, t3);\
	\
	t0 = k0; t1 = k4;\
	k0 = k1; k4 = k5;\
	k1 = k2; k5 = k6;\
	k2 = k3; k6 = k7;\
	k3 = t0; k7 = t1;\
} while(0);


#define PRESENT80_KS_Step16_L256(k0, k4, k8, t0, t1) do {\
	t0 = k4; t1 = k8;\
	k4 = XOR(SHLB128(k0, 8), SHRB128(t0,8));\
	k8 = AND(t0, SET32(0, 0, 0xffffffff, 0xffffffff));\
	k0 = XOR(SHRB128(k0,8), SHLB128(t1, 8));\
} while(0);

#define PRESENT80_KS_Step16_L240(k0, k4, k8, t0, t1) do {\
	t0 = k4; t1 = k8;\
	k4 = XOR(SHLB128(k0, 6), SHRB128(t0,10));\
	k8 = AND(SHRB128(t0, 2), SET32(0, 0, 0xffffffff, 0xffffffff));\
	k0 = XOR(XOR(SHRB128(k0,10),SHLB128(t1, 6)), SHLB128(t0,14));\
} while(0);

#define PRESENT80bitslice16_key_schedule_step(k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, c0, c1, c2, c3, t0, t1, t2, t3, t) do {\
	XOR_Key(k4, k5, k6, k7, c0, c1, c2, c3);\
	PRESENT80_KS_Step16_L256(k0, k4, k8, t0, t1);\
	PRESENT80_KS_Step16_L240(k1, k5, k9, t0, t1);\
	PRESENT80_KS_Step16_L240(k2, k6, k10, t0, t1);\
	PRESENT80_KS_Step16_L240(k3, k7, k11, t0, t1);\
	\
	CYCLE_L4(k0, k1, k2, k3, t0);\
	CYCLE_L4(k4, k5, k6, k7, t0);\
	CYCLE_L4(k8, k9, k10,k11,t0);\
	\
	Key_sLayer16(k0, k1, k2, k3, t0, t1, t2, t3, t);\
} while(0);

#define PRESENT_packing16_nibble_permute(a, t0, t1, t2) do {\
        /* Isolate even low nibbles */\
        t0 = AND(a, mask_l);\
        /* Isolate odd high nibbles*/\
        t1 = AND(a, mask_u);\
        /* Low nibbles are rotated right by 9 nibbles */\
        t2 = SHLQ64(t0, 9*4);\
        a  = SHRQ64(t0, 64-9*4);\
        a  = XOR(a, t2);\
        /* High nibbles are rotated left 7 nibbles */\
        t2 = SHLQ64(t1, 7*4);\
        t0 = SHRQ64(t1, 64-7*4);\
        t0 = XOR(t0, t2);\
        /* Merge the results */\
        a  = XOR(a, t0);\
} while(0);

#define PRESENT_packing16(a0, a1, a2, a3, a4, a5, a6, a7, t0, t1, t2) do {\
        /* Perform the nibble permutation */\
        PRESENT_packing16_nibble_permute(a0, t0, t1, t2);\
        PRESENT_packing16_nibble_permute(a1, t0, t1, t2);\
        PRESENT_packing16_nibble_permute(a2, t0, t1, t2);\
        PRESENT_packing16_nibble_permute(a3, t0, t1, t2);\
        PRESENT_packing16_nibble_permute(a4, t0, t1, t2);\
        PRESENT_packing16_nibble_permute(a5, t0, t1, t2);\
        PRESENT_packing16_nibble_permute(a6, t0, t1, t2);\
        PRESENT_packing16_nibble_permute(a7, t0, t1, t2);\
        /* Pack the input */\
        packing16(a0, a1, a2, a3, a4, a5, a6, a7, t0, t1, t2);\
} while(0);

/**** Keys and state load/store macros *****/
#define PACK_KEYS8(TYPE) do {\
	packing8(k[0], k[1], k[2], k[3], t[0], t[1], t[2], t[3], t[4], t[5]);\
	packing8(k[4], k[5], k[6], k[7], t[0], t[1], t[2], t[3], t[4], t[5]);\
} while(0);

#define PACK_KEYS16(TYPE) do {\
	if(TYPE == 80){\
	        PRESENT_packing16(k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7], t[0], t[1], t[2]);\
        	PRESENT_packing16(k[8], k[9], k[10], k[11], k[12], k[13], k[14], k[15], t[0], t[1], t[2]);\
	}\
	else{\
	        packing16(k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7], t[0], t[1], t[2]);\
        	packing16(k[8], k[9], k[10], k[11], k[12], k[13], k[14], k[15], t[0], t[1], t[2]);\
	}\
} while(0);

#define LOADKEYS(P, TYPE, key) do {\
	int i;\
	/* load the keys */\
	for(i=0; i < P; i++){\
		t[i] = LOAD(((u16(*)[KEY ## TYPE])key)[i]);\
		/* Inverse endianness */\
		if(TYPE == 80){\
			inverse_bytes_endian80(t[i]);\
		}\
		else{\
			inverse_bytes_endian(t[i]);\
			if(P == BITSLICE16_P){\
				word t0, t1;\
		                inverse_nibble_endian(t[i], t0, t1);\
			}\
		}\
	}\
	for(i=0; i < P; i++){\
		if(i < (P/2)){\
			k[i] = PUNPCKLQDQ(t[2*i+1], t[2*i]);\
		}\
		else{\
			k[i] = PUNPCKHQDQ(t[2*i-P+1], t[2*i-P]);\
		}\
	}\
	/* Pack the keys */\
	PACK_KEYS ## P(TYPE);\
} while(0);

#define STORESUBKEYS(P, TYPE, subkeys) do {\
	int i;\
	for(i=0; i < (P/2); i++){\
		((word*)subkeys)[i] = k[i];\
	}\
} while(0);

#define LOADSTATES8() do {\
	packing8(s[0], s[1], s[2], s[3], t[0], t[1], t[2], t[3], t[4], t[5]);\
} while(0);

#define LOADSTATES16() do {\
	PRESENT_packing16(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], t[0], t[1], t[2]);\
} while(0);

#define LOADSTATES(P, plaintext) do {\
	int i;\
	for(i=0; i < (P/2); i++){\
		s[i] = LOAD(((u64*)plaintext) + 2*i);\
		inverse_bytes_endian(s[i]);\
	}\
	/* Pack the states */\
	LOADSTATES ## P();\
} while(0);

#define STORESTATES_8(P, ciphertext) do {\
	int i;\
	/* Unpack the states */\
	unpacking8(t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7], t[8], s[0], s[1], s[2], s[3]);\
	for(i=0; i < (P/2); i++){\
		inverse_bytes_endian(t[i]);\
		STORE(t[i], ((u64*)ciphertext) + 2*i);\
	}\
} while(0);


#define STORESTATES_16(P, ciphertext) do {\
	int i;\
	/* Unpack the states */\
        unpacking16(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], t[0], t[1], t[2]);\
	for(i=0; i < (P/2); i++){\
		inverse_bytes_endian(s[i]);\
		STORE(s[i], ((u64*)ciphertext) + 2*i);\
	}\
} while(0);

#define STORESTATES(P, ciphertext) do {\
	STORESTATES_ ## P(P, ciphertext);\
} while(0);

/**** Key schedule and core encryption macros ****/
#define KEY_SCHEDULE_STEP_8_80() do{\
	word t0, t1, t2, t3, t4;\
	/* Compute the new subkeys */\
        PRESENT80bitslice8_key_schedule_step(k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7], t0, t1, t2, t3, t4, round_constants_PRESENT80_8[r][0], round_constants_PRESENT80_8[r][1], round_constants_PRESENT80_8[r][2], round_constants_PRESENT80_8[r][3]);\
} while(0);

#define KEY_SCHEDULE_STEP_16_80() do {\
	word t0, t1, t2, t3, t4;\
        /* Compute the new subkeys */\
        PRESENT80bitslice16_key_schedule_step(k[4], k[5], k[6], k[7], k[0], k[1], k[2], k[3], k[8], k[9], k[10], k[11], round_constants_PRESENT80_16[r][0], round_constants_PRESENT80_16[r][1], round_constants_PRESENT80_16[r][2], round_constants_PRESENT80_16[r][3], t0, t1, t2, t3, t4);\
} while(0);

#define KEY_SCHEDULE_STEP_8_128() do {\
	word t0, t1, t2, t3, t4;\
	/* Compute the new subkeys */\
	PRESENT128bitslice8_key_schedule_step(k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7], t0, t1, t2, t3, t4, round_constants_PRESENT128_8[r][0], round_constants_PRESENT128_8[r][1], round_constants_PRESENT128_8[r][2], round_constants_PRESENT128_8[r][3]);\
} while(0);

#define KEY_SCHEDULE_STEP_16_128() do {\
	word t0, t1, t2, t3, t4;\
	/* Compute the new subkeys */\
	PRESENT128bitslice16_key_schedule_step(k[4], k[5], k[6], k[7], k[0], k[1], k[2], k[3], k[12], k[13], k[14], k[15], k[8], k[9], k[10], k[11], round_constants_PRESENT128_16[r][0], round_constants_PRESENT128_16[r][1], round_constants_PRESENT128_16[r][2], round_constants_PRESENT128_16[r][3], t0, t1, t2, t3, t4);\
} while(0);


#define KEY_SCHEDULE_STEP(P, TYPE) do {\
	KEY_SCHEDULE_STEP_ ## P ## _ ## TYPE();\
} while(0);

#define PRESENT_KEY_SCHEDULE(P, TYPE) do {\
	word k[P];\
        word t[P + 1];\
	int r;\
	\
	/* Load the keys */\
	LOADKEYS(P, TYPE, masterKey);\
	\
	/* Key schedule */\
	for (r=0; r<=31; r++)\
	{\
		/* Store the keys */\
		STORESUBKEYS(P, TYPE, roundKeys + (P/2) * r);\
		/* Perform the key schedule step */\
		KEY_SCHEDULE_STEP(P, TYPE);\
	}\
} while(0);

#define PRESENT_CORE_ENCRYPT_BITSLICE8_P(P, TYPE) do {\
	int r;\
	word t0;\
	/* round functions */\
	for (r=0; r<31; r++)\
	{\
		XOR_Key(s[0], s[1], s[2], s[3], k[0], k[1], k[2], k[3]);\
		Sbox(s[0], s[1], s[2], s[3], t0);\
		pLayer_eight_fast(s[0], s[1], s[2], s[3], t0);\
		k += (P/2);\
	}\
	XOR_Key(s[0], s[1], s[2], s[3], k[0], k[1], k[2], k[3]);\
} while(0);

#define PRESENT_CORE_ENCRYPT_BITSLICE16_P(P, TYPE) do {\
	int r;\
	word t0, t1, t4;\
	/* round functions */\
	for (r=0; r<31; r++)\
	{\
		XOR_Key(s[0], s[1], s[2], s[3], k[0], k[1], k[2], k[3]);\
        	XOR_Key(s[4], s[5], s[6], s[7], k[4], k[5], k[6], k[7]);\
		Sbox(s[0], s[1], s[2], s[3], t0);\
		Sbox(s[4], s[5], s[6], s[7], t0);\
		pLayer_sixteen(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], t0, t1);\
                t4 = s[7]; s[7] = s[0]; s[0] = t4;\
	        t4 = s[6]; s[6] = s[1]; s[1] = t4;\
        	t4 = s[5]; s[5] = s[2]; s[2] = t4;\
                t4 = s[4]; s[4] = s[3]; s[3] = t4;\
		k += (P/2);\
	}\
	XOR_Key(s[0], s[1], s[2], s[3], k[0], k[1], k[2], k[3]);\
	XOR_Key(s[4], s[5], s[6], s[7], k[4], k[5], k[6], k[7]);\
} while(0);

#define PRESENT_CORE_ENCRYPT(P, TYPE) do {\
        word s[P/2];\
	word t[P + 1];\
	word* k = (word*)subkeys;\
	\
	/* load the states */\
	LOADSTATES(P, message);\
	\
	PRESENT_CORE_ENCRYPT ## _ ## P(P, TYPE);\
	/*saving all the values to back to ciphertexts */\
	STORESTATES(P, ciphertext);\
} while(0);


#define PRESENT_CORE_ENCRYPT_AND_KEY_SCHED_BITSLICE8_P(P, TYPE) do {\
	int r;\
	word t0;\
	/* round functions */\
	for (r=0; r<31; r++)\
	{\
		XOR_Key(s[0], s[1], s[2], s[3], k[0], k[1], k[2], k[3]);\
		KEY_SCHEDULE_STEP(P, TYPE);\
		Sbox(s[0], s[1], s[2], s[3], t0);\
		pLayer_eight_fast(s[0], s[1], s[2], s[3], t0);\
	}\
	XOR_Key(s[0], s[1], s[2], s[3], k[0], k[1], k[2], k[3]);\
} while(0);

#define PRESENT_CORE_ENCRYPT_AND_KEY_SCHED_BITSLICE16_P(P, TYPE) do {\
	int r;\
	word t0, t1, t4;\
	/* round functions */\
	for (r=0; r<31; r++)\
	{\
		XOR_Key(s[0], s[1], s[2], s[3], k[0], k[1], k[2], k[3]);\
        	XOR_Key(s[4], s[5], s[6], s[7], k[4], k[5], k[6], k[7]);\
		KEY_SCHEDULE_STEP(P, TYPE);\
		Sbox(s[0], s[1], s[2], s[3], t0);\
		Sbox(s[4], s[5], s[6], s[7], t0);\
		pLayer_sixteen(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], t0, t1);\
                t4 = s[7]; s[7] = s[0]; s[0] = t4;\
	        t4 = s[6]; s[6] = s[1]; s[1] = t4;\
        	t4 = s[5]; s[5] = s[2]; s[2] = t4;\
                t4 = s[4]; s[4] = s[3]; s[3] = t4;\
	}\
	XOR_Key(s[0], s[1], s[2], s[3], k[0], k[1], k[2], k[3]);\
	XOR_Key(s[4], s[5], s[6], s[7], k[4], k[5], k[6], k[7]);\
} while(0);

#define PRESENT_CORE_ENCRYPT_AND_KEY_SCHED(P, TYPE) do {\
	word k[P];\
	word s[P/2];\
	word t[P + 1];\
	\
	/* Load the keys */\
	LOADKEYS(P, TYPE, key);\
	\
	/* load the states */\
	LOADSTATES(P, plaintext);\
	\
	PRESENT_CORE_ENCRYPT_AND_KEY_SCHED ## _ ## P(P, TYPE);\
	\
	/*saving all the values to back to ciphertexts */\
	STORESTATES(P, ciphertext);\
} while(0);
