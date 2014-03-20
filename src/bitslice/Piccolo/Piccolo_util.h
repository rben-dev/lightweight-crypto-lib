#include "../../common/basic_helpers.h"
#include "../../common/bitslice_common.h"

/* FIXME: this should not be used ...                 */
/* Rearranging the input key for bitslice convenience */
#define Piccolo_rearrange_keys(a, b, parallelism, key_type) do {\
        int i, j;\
        for(i=0; i < parallelism; i++){\
                for(j=0; j < key_type; j++){\
                        ((u16 (*)[parallelism])b)[j][i] = (((u16 (*)[key_type])a)[i][j] << 8) ^ (((u16 (*)[key_type])a)[i][j] >> 8);\
                }\
        }\
} while(0);

word mask_rp0, mask_rp1;
word mask_wk0, mask_wk1;
word mask_rotl16, mask_rotl32, mask_rotl48;
word mask_shf0, mask_shf16, mask_shf32;

#undef uSWAP8
#define uSWAP8(x, y, t0); do {\
	t0 = x; x = y; y = t0;\
	t0 = x;\
	x = XOR(PSHUFB(x , mask_unpack8_l0), PSHUFB(y, mask_unpack8_h0));\
	y = XOR(PSHUFB(t0, mask_unpack8_l1), PSHUFB(y, mask_unpack8_h1));\
} while(0);

#define Piccolo_packing16(a0, a1, a2, a3, a4, a5, a6, a7, t0, t1, t2) do {\
	packing16(a0, a1, a2, a3, a4, a5, a6, a7, t0, t1, t2);\
	SWAP64(a0, a4, t0);\
	SWAP64(a1, a5, t0);\
	SWAP64(a2, a6, t0);\
	SWAP64(a3, a7, t0);\
} while(0);

#define Piccolo_unpacking16(a0, a1, a2, a3, a4, a5, a6, a7, t0, t1, t2) do {\
	uSWAP64(a0, a4, t0); \
	uSWAP64(a1, a5, t0); \
	uSWAP64(a2, a6, t0); \
	uSWAP64(a3, a7, t0); \
	unpacking16(a0, a1, a2, a3, a4, a5, a6, a7, t0, t1, t2);\
} while(0);

#define ROTL16(x)	PSHUFB((x), mask_rotl16)
#define ROTL32(x)	PSHUFB((x), mask_rotl32)
#define ROTL48(x)	PSHUFB((x), mask_rotl48)
#define TIMES3(x)	XOR((x), ROTL16(x))
#define TIMES33(x) 	XOR(ROTL16(x), ROTL32(TIMES3(x)))

#define SHF0(x)		PSHUFB(x, mask_shf0)
#define SHF16(x)	PSHUFB(x, mask_shf16)
#define SHF32(x)	PSHUFB(x, mask_shf32)

#define SHF3(x)		XOR(SHF0(x), SHF16(x))
#define SHF33(x)	XOR(SHF16(x), SHF32(SHF3(x)))

word Piccolo80_constants[25][(BITSLICE16_P/2)/2];
word Piccolo128_constants[31][(BITSLICE16_P/2)/2];
u32 Piccolo80_RC[25];
u32 Piccolo128_RC[31];
#define Piccolo_generate_constants(P, TYPE) do {\
        int i, j;\
	int R;\
        u16 t[2][P];\
	if(TYPE == 80){\
		R = 25;\
	}\
	else{\
		R = 31;\
	}\
        for(i = 0; i < R; i++){\
                Piccolo ## TYPE ## _RC[i] = (i+1) & 0x1fU;\
                Piccolo ## TYPE ## _RC[i] <<= 10;\
                Piccolo ## TYPE ## _RC[i] ^= (i+1) & 0x1fU;\
                Piccolo ## TYPE ## _RC[i] ^= Piccolo ## TYPE ## _RC[i] << 17;\
		if(TYPE == 128){\
	                Piccolo ## TYPE ## _RC[i] ^= 0x6547a98bU;\
		}\
		else{\
	                Piccolo ## TYPE ## _RC[i] ^= 0x0f1e2d3cU;\
		}\
                for(j = 0; j < P; j++){\
                        t[0][j] = (u16)(Piccolo ## TYPE ## _RC[i] >> 16);\
                        t[1][j] = (u16)(Piccolo ## TYPE ## _RC[i] & 0xffff);\
                }\
                pack_one(Piccolo ## TYPE ## _ ## constants[i], t[0], t[1]);\
        }\
} while(0);


/*
#define pack_one(w, a, b) do {\
        word t0, t1, t2, t3, t4, t5, t6;\
        u64 x[BITSLICE16_P];\
        int i;\
        for(i = 0; i < BITSLICE16_P; i++){\
                x[i] = (((u64)a[i]) << 48) ^ (((u64)b[i]) << 16);\
        }\
        t0 = LOAD(x+0);\
        t1 = LOAD(x+2);\
        t2 = LOAD(x+4);\
        t3 = LOAD(x+6);\
	\
        w[0] = LOAD(x+8);\
        w[1] = LOAD(x+10);\
        w[2] = LOAD(x+12);\
        w[3] = LOAD(x+14);\
        Piccolo_packing16(t0, t1, t2, t3, w[0], w[1], w[2], w[3], t4, t5, t6);\
} while(0);
*/
void pack_one(word* w, const u16 a[BITSLICE16_P], const u16 b[BITSLICE16_P])
{
        word t0, t1, t2, t3, t4, t5, t6;
        u64 x[BITSLICE16_P];
        int i;
        for(i = 0; i < BITSLICE16_P; i++){
                x[i] = (((u64)a[i]) << 48) ^ (((u64)b[i]) << 16);
        }
        t0 = LOAD(x+0);
        t1 = LOAD(x+2);
        t2 = LOAD(x+4);
        t3 = LOAD(x+6);

        w[0] = LOAD(x+8);
        w[1] = LOAD(x+10);
        w[2] = LOAD(x+12);
        w[3] = LOAD(x+14);
        Piccolo_packing16(t0, t1, t2, t3, w[0], w[1], w[2], w[3], t4, t5, t6);
}

/*
	CHES 12 paper:
Input: 	r3 (MSB), r2, r1, r0, tmp
Output: 	r0 (MSB), r1, r2, r3
1.  tmp = r1; r1 |= r2; r3 = ~r3;
2.  r0 ^= r2; r1 ^= r3; r3 |= r2;
3.  r0 ^= r3; r3 = r1; 
4.  r3 |= r0;
5.  r3 ^= tmp; tmp |= r0;
6.  r2 ^= tmp; r3 = ~r3;
 */
#define piccoloSbox(r3, r2, r1, r0, t) do {\
	t = r1;	r1 = OR(r1, r2); r3 = XOR(r3, mask_one);\
	r0 = XOR(r0, r2); r1 = XOR(r1, r3); r3 = OR(r3, r2);\
	r0 = XOR(r0, r3);\
	r3 = OR(r1, r0);\
	r3 = XOR(r3, t); t = OR(t, r0);\
	r2 = XOR(r2, t); r3 = XOR(r3, mask_one);\
} while(0);

#define SboxLayer16(a0, a1, a2, a3, a4, a5, a6, a7) do {\
	piccoloSbox(a0, a1, a2, a3);\
	piccoloSbox(a4, a5, a6, a7);\
} while(0);

#define MIXCOL16(r0, r1, r2, r3, t) do {\
	t = r0;\
	r0 = XOR(TIMES3(r1), TIMES33(r0));\
	r1 = XOR(TIMES3(r2), TIMES33(r1));\
	r2 = XOR(XOR(TIMES3(t), TIMES3(r3)), TIMES33(r2));\
	r3 = XOR(TIMES3(t), TIMES33(r3));\
} while(0);
	
#define F16(a0, a1, a2, a3, a4, a5, a6, a7, t0, t1, t2, t3, t4) do {\
	t0 = a0; t1 = a1; t2 = a2;t3 = a3;\
	piccoloSbox(t0, t1, t2, t3, t4);\
	MIXCOL16(t3, t2, t1, t0, t4);\
	piccoloSbox(t3, t2, t1, t0, t4);\
	AddKey(a4, a5, a6, a7, t0, t1, t2, t3);\
} while(0);

#define PERMUTE16(r0, r1, r2, r3) do {\
	r0 = XOR(SHF3(r1), SHF33(r0));\
	r1 = XOR(SHF3(r2), SHF33(r1));\
	r2 = XOR(XOR(SHF3(r0), SHF3(r3)), SHF33(r2));\
	r3 = XOR(SHF3(r0), SHF33(r3));\
} while(0);

/* Piccolo round permutation */
#define Piccolo_RoundPermutation(a0, a1, a2, a3, a4, a5, a6, a7) do {\
	a0 = PSHUFB(a0, mask_rp0);\
	a1 = PSHUFB(a1, mask_rp0);\
	a2 = PSHUFB(a2, mask_rp0);\
	a3 = PSHUFB(a3, mask_rp0);\
	\
	a4 = PSHUFB(a4, mask_rp1);\
	a5 = PSHUFB(a5, mask_rp1);\
	a6 = PSHUFB(a6, mask_rp1);\
	a7 = PSHUFB(a7, mask_rp1);\
	word t;\
	t = a0; a0 = a4; a4 = t;\
	t = a1; a1 = a5; a5 = t;\
	t = a2; a2 = a6; a6 = t;\
	t = a3; a3 = a7; a7 = t;\
} while(0);

void pack_two(word* w0, word* w1, const u16 a[BITSLICE16_P], const u16 b[BITSLICE16_P], const u16 c[BITSLICE16_P], const u16 d[BITSLICE16_P])
{
	u64 x[BITSLICE16_P];
	word t4, t5, t6;
	int i;
	for(i = 0; i < BITSLICE16_P; i++){
		x[i] = (((u64)a[i]) << 48) ^ (((u64)b[i]) << 16) ^ (((u64)c[i]) << 32) ^ ((u64)d[i]);
	}
	w0[0] = LOAD(x+0);
	w0[1] = LOAD(x+2);
	w0[2] = LOAD(x+4);
	w0[3] = LOAD(x+6);

	w1[0] = LOAD(x+8);
	w1[1] = LOAD(x+10);
	w1[2] = LOAD(x+12);
	w1[3] = LOAD(x+14);

	Piccolo_packing16(w0[0], w0[1], w0[2], w0[3], w1[0], w1[1], w1[2], w1[3], t4, t5, t6);
}

void pack_four(word* w0, word* w1, word* w2, word* w3, const u16 a[BITSLICE16_P], const u16 b[BITSLICE16_P], const u16 c[BITSLICE16_P], const u16 d[BITSLICE16_P], int h)
{
	u64 x[BITSLICE16_P];
	word t4, t5, t6;
	int i;
	for(i = 0; i < BITSLICE16_P; i++)
	{
		x[i] = (((u64)a[i]) << 48) ^ (((u64)b[i]) << 16) ^ (((u64)c[i]) << 32) ^ ((u64)d[i]);
	}
	w0[0] = LOAD(x+0);
	w0[1] = LOAD(x+2);
	w0[2] = LOAD(x+4);
	w0[3] = LOAD(x+6);

	w1[0] = LOAD(x+8);
	w1[1] = LOAD(x+10);
	w1[2] = LOAD(x+12);
	w1[3] = LOAD(x+14);

	Piccolo_packing16(w0[0], w0[1], w0[2], w0[3], w1[0], w1[1], w1[2], w1[3], t4, t5, t6);

	if(h){
		w2[0] = PSHUFB(w0[0], mask_unpack64_l0);
		w2[1] = PSHUFB(w0[1], mask_unpack64_l0);
		w2[2] = PSHUFB(w0[2], mask_unpack64_l0);
		w2[3] = PSHUFB(w0[3], mask_unpack64_l0);

		w3[0] = PSHUFB(w0[0], mask_unpack64_l1);
		w3[1] = PSHUFB(w0[1], mask_unpack64_l1);
		w3[2] = PSHUFB(w0[2], mask_unpack64_l1);
		w3[3] = PSHUFB(w0[3], mask_unpack64_l1);

		w0[0] = PSHUFB(w1[0], mask_unpack64_l0);
		w0[1] = PSHUFB(w1[1], mask_unpack64_l0);
		w0[2] = PSHUFB(w1[2], mask_unpack64_l0);
		w0[3] = PSHUFB(w1[3], mask_unpack64_l0);

		w1[0] = PSHUFB(w1[0], mask_unpack64_l1);
		w1[1] = PSHUFB(w1[1], mask_unpack64_l1);
		w1[2] = PSHUFB(w1[2], mask_unpack64_l1);
		w1[3] = PSHUFB(w1[3], mask_unpack64_l1);
	}
	else{
		w2[0] = PSHUFB(w0[0], mask_unpack64_h0);
		w2[1] = PSHUFB(w0[1], mask_unpack64_h0);
		w2[2] = PSHUFB(w0[2], mask_unpack64_h0);
		w2[3] = PSHUFB(w0[3], mask_unpack64_h0);

		w3[0] = PSHUFB(w0[0], mask_unpack64_h1);
		w3[1] = PSHUFB(w0[1], mask_unpack64_h1);
		w3[2] = PSHUFB(w0[2], mask_unpack64_h1);
		w3[3] = PSHUFB(w0[3], mask_unpack64_h1);

		w0[0] = PSHUFB(w1[0], mask_unpack64_h0);
		w0[1] = PSHUFB(w1[1], mask_unpack64_h0);
		w0[2] = PSHUFB(w1[2], mask_unpack64_h0);
		w0[3] = PSHUFB(w1[3], mask_unpack64_h0);

		w1[0] = PSHUFB(w1[0], mask_unpack64_h1);
		w1[1] = PSHUFB(w1[1], mask_unpack64_h1);
		w1[2] = PSHUFB(w1[2], mask_unpack64_h1);
		w1[3] = PSHUFB(w1[3], mask_unpack64_h1);
	}
}


/* 
rk23: 0,2 mod 5, k[2], k[3]
rk01: round 1,4 mod 5, k[0], [1]
rk44: 3 mod 5, k[4], k[4]
wk0, k0L | k1R
wk1, K1L | K0R

wk2, k4L | k3R
wk3, K3L | k4R */

#define Piccolo80_rk23(k) (((word*)k) + ((BITSLICE16_P/2)/2)*0) 
#define Piccolo80_rk01(k) (((word*)k) + ((BITSLICE16_P/2)/2)*1) 
#define Piccolo80_rk44(k) (((word*)k) + ((BITSLICE16_P/2)/2)*2)
#define Piccolo80_wk01(k) (((word*)k) + ((BITSLICE16_P/2)/2)*3)
#define Piccolo80_wk23(k) (((word*)k) + ((BITSLICE16_P/2)/2)*4)

void Piccolo_pack_keys80(const u16 keys[KEY80][BITSLICE16_P], word* rk23, word* rk01, word* rk44, word* wk01, word* wk23)
{
	int i;
	pack_two(rk23, rk01, keys[0], keys[1], keys[2], keys[3]);
	pack_one(rk44, keys[4], keys[4]);
	for(i = 0; i < ((BITSLICE16_P/2)/2); i++){
		wk01[i] = PSHUFB(rk01[i], mask_wk0);
		wk01[i] = XOR(wk01[i], PSHUFB(rk01[i], mask_wk1));
		wk23[i] = PSHUFB(rk44[i], mask_wk0);
		wk23[i] = XOR(wk23[i], PSHUFB(rk23[i], mask_wk1));
	}
}

/* word rk0[(BITSLICE16_P/2)/2], rk1[(BITSLICE16_P/2)/2], rk2[(BITSLICE16_P/2)/2], rk3[(BITSLICE16_P/2)/2], rk4[(BITSLICE16_P/2)/2], rk5[(BITSLICE16_P/2)/2], rk6[(BITSLICE16_P/2)/2], rk7[(BITSLICE16_P/2)/2]; */
#define Piccolo128_rk(k,i)  (((word*)k) + ((i*BITSLICE16_P/2)/2))
#define Piccolo128_wk01(k)  (((word*)k) + (KEY128)  *((BITSLICE16_P/2)/2))
#define Piccolo128_wk23(k)  (((word*)k) + (KEY128+1)*((BITSLICE16_P/2)/2))

void Piccolo_pack_keys128(const u16 keys[KEY128][BITSLICE16_P], word* rk, word* wk01, word* wk23)
{
	int i;

	pack_four(Piccolo128_rk(rk,0),  Piccolo128_rk(rk,2),  Piccolo128_rk(rk,4), Piccolo128_rk(rk,6), keys[0], keys[2], keys[4], keys[6], 1);
	pack_four(Piccolo128_rk(rk,1),  Piccolo128_rk(rk,3),  Piccolo128_rk(rk,5), Piccolo128_rk(rk,7), keys[1], keys[3], keys[5], keys[7], 0);

	for(i = 0; i < ((BITSLICE16_P/2)/2); i++){
		wk01[i] = PSHUFB(Piccolo128_rk(rk,0)[i], mask_wk0);
		wk01[i] = XOR(wk01[i], PSHUFB(Piccolo128_rk(rk,1)[i], mask_wk1));
		wk23[i] = PSHUFB(Piccolo128_rk(rk, 4)[i], mask_wk0);
		wk23[i] = XOR(wk23[i], PSHUFB(Piccolo128_rk(rk,7)[i], mask_wk1));
	}
}

/* Initialize masks and constants */
unsigned char Piccolo_init_check = 0;
void Piccolo_init()
{
#ifdef THREAD_SAFE
        pthread_mutex_lock(&bitslice_init_mutex);
#endif
	if(Piccolo_init_check == 0){
		init();
		mask_one    = CONSTANT(0xff);
		mask_rotl16 = SET(9, 8, 15, 14, 13, 12, 11, 10, 1, 0, 7, 6, 5, 4, 3, 2);
		mask_rotl32 = SET(11, 10, 9, 8, 15, 14, 13, 12, 3, 2, 1, 0, 7, 6, 5, 4);
		mask_rotl48 = SET(13, 12, 11, 10, 9, 8, 15, 14, 5, 4, 3, 2, 1, 0, 7, 6);
		mask_shf0   = SET(7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8);
		mask_shf16  = SET(9, 8, 7, 6, 13, 12, 3, 2, 1, 0, 15, 14, 5, 4, 11, 10);
		mask_shf32  = SET(3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12);
		mask_rp0    = SET(15, 14, 13, 12, 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8);
		mask_rp1    = SET(7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12, 3, 2, 1, 0);
		mask_wk0    = SET(0x80, 0x80, 0x80, 0x80, 3, 2, 1, 0, 7, 6, 5, 4, 0x80, 0x80, 0x80, 0x80);
		mask_wk1    = SET(15, 14, 13, 12, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 11, 10, 9, 8);
		mask_l16    = SET(0x80, 0x80, 13, 12, 0x80, 0x80, 9, 8, 0x80, 0x80, 5, 4, 0x80, 0x80, 1, 0);
		mask_r16    = SET(15, 14, 0x80, 0x80, 11, 10, 0x80, 0x80, 7, 6, 0x80, 0x80, 3, 2, 0x80, 0x80);
		Piccolo_generate_constants(BITSLICE16_P, 80);
		Piccolo_generate_constants(BITSLICE16_P, 128);
	}
	Piccolo_init_check = 1;
#ifdef THREAD_SAFE
        pthread_mutex_unlock(&bitslice_init_mutex);
#endif	
	return;
}
