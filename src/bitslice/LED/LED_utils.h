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
#include "../../common/basic_helpers.h"
#include "../../common/bitslice_common.h"

#define ru64()   ((((u64) rand()) << 32)  | ((u64)rand()))


#undef SWAP8
#define SWAP8(l, h, t0)\
	t0 = l;\
	l = PUNPCKLBW(l , h);\
	h = PUNPCKHBW(t0, h);

#undef uSWAP8
#define uSWAP8(x, y, t0);\
	t0 = x;\
	x = XOR(PSHUFB(x , mask_unpack8_l0), PSHUFB(y, mask_unpack8_h0));\
	y = XOR(PSHUFB(t0, mask_unpack8_l1), PSHUFB(y, mask_unpack8_h1));

word constants_LED64_BITSLICE16_P[32][BITSLICE16_P/2];
word constants_LED64_BITSLICE32_P[32][BITSLICE32_P/2];
word constants_LED128_BITSLICE16_P[48][BITSLICE16_P/2];
word constants_LED128_BITSLICE32_P[48][BITSLICE32_P/2];

const u8 LED_RC[48] = {
	0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F,
	0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B,
	0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E,
	0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A,
	0x34, 0x29, 0x12, 0x24, 0x08, 0x11, 0x22, 0x04
};
#define generate_constants(P, LED) do {\
	/* precompute the constants */\
	u64 c[32];\
	word t0, t1, t2;\
	int r;\
	int R;\
	if(LED == 64){\
		R = 32;\
	}\
	else{\
		R = 48;\
	}\
	for(r = 0; r < R; r++)\
	{\
		u64 t = 0;\
		t |= (u64) (LED>>4)&0xF;\
		t |= ((u64) 1^((LED>>4) & 0xFF)) << 16;\
		t |= ((u64) 2^(LED&0xF)) << 32;\
		t |= ((u64) 3^(LED&0xF)) << 48;\
\
		t |= ((u64) (LED_RC[r] >> 3) & 7) << 4;\
		t |= ((u64) (LED_RC[r] >> 3) & 7) << (4+32);\
		t |= ((u64) (LED_RC[r] >> 0) & 7) << (4+16);\
		t |= ((u64) (LED_RC[r] >> 0) & 7) << (4+16+32);\
		int i;\
		for(i = 0; i < P; i++){\
			c[i] = t;\
		}\
		for(i = 0; i < P/2; i++){\
			constants_LED ## LED ## _ ## BITSLICE ## P ## _P[r][i] = LOAD(c+2*i);\
		}\
		if(P == BITSLICE32_P){\
			packing32(\
				constants_LED ## LED ## _ ## BITSLICE ## 32 ## _P[r][0],constants_LED ## LED ## _ ## BITSLICE ## 32 ## _P[r][1],constants_LED ## LED ## _ ## BITSLICE ## 32 ## _P[r][2],constants_LED ## LED ## _ ## BITSLICE ## 32 ## _P[r][3],\
				constants_LED ## LED ## _ ## BITSLICE ## 32 ## _P[r][4],constants_LED ## LED ## _ ## BITSLICE ## 32 ## _P[r][5],constants_LED ## LED ## _ ## BITSLICE ## 32 ## _P[r][6],constants_LED ## LED ## _ ## BITSLICE ## 32 ## _P[r][7],\
				constants_LED ## LED ## _ ## BITSLICE ## 32 ## _P[r][8],constants_LED ## LED ## _ ## BITSLICE ## 32 ## _P[r][9],constants_LED ## LED ## _ ## BITSLICE ## 32 ## _P[r][10],constants_LED ## LED ## _ ## BITSLICE ## 32 ## _P[r][11],\
				constants_LED ## LED ## _ ## BITSLICE ## 32 ## _P[r][12],constants_LED ## LED ## _ ## BITSLICE ## 32 ## _P[r][13],constants_LED ## LED ## _ ## BITSLICE ## 32 ## _P[r][14],constants_LED ## LED ## _ ## BITSLICE ## 32 ## _P[r][15],\
				t0, t1, t2);\
		}\
		else{\
			packing16(\
				constants_LED ## LED ## _ ## BITSLICE ## 16 ## _P[r][0],constants_LED ## LED ## _ ## BITSLICE ## 16 ## _P[r][1],constants_LED ## LED ## _ ## BITSLICE ## 16 ## _P[r][2],constants_LED ## LED ## _ ## BITSLICE ## 16 ## _P[r][3],\
				constants_LED ## LED ## _ ## BITSLICE ## 16 ## _P[r][4],constants_LED ## LED ## _ ## BITSLICE ## 16 ## _P[r][5],constants_LED ## LED ## _ ## BITSLICE ## 16 ## _P[r][6],constants_LED ## LED ## _ ## BITSLICE ## 16 ## _P[r][7],\
				t0, t1, t2);\
		}\
	}\
} while(0);

u8 LED_init_check = 0;
void LED_init(){
#ifdef THREAD_SAFE
	pthread_mutex_lock(&bitslice_init_mutex);
#endif
	if(LED_init_check == 0){
		init();
		generate_constants(16, 64);
		generate_constants(32, 64);
		generate_constants(16, 128);
		generate_constants(32, 128);
	}
	LED_init_check = 1;
#ifdef THREAD_SAFE
	pthread_mutex_unlock(&bitslice_init_mutex);
#endif
	return;	
}

/*  16 copies of the data,
ai: i-th bit of x0,0 (16 copies), followed by i-th bit of x0,1, x0,2, x0,3, then i-th bit of x1,0, x1,1, x1,2, x1,3 for i = 0, 1, 2, 3 (a3 for MSB)
bi: i-th bit of x2,0 (16 copies), followed by i-th bit of x2,1, x2,2, x2,3, then i-th bit of x3,0, x3,1, x3,2, x3,3 for i = 0, 1, 2, 3 (b3 for MSB)
 */

/* Sbox Layer 16 */
#define SboxLayer16(a0, a1, a2, a3, a4, a5, a6, a7, t0) do {\
	Sbox(a0, a1, a2, a3, t0);\
	Sbox(a4, a5, a6, a7, t0);\
} while(0);

/* Sbox Layer 32 */
#define SboxLayer32(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, t0) do{\
	Sbox( a0,  a1,  a2,  a3, t0);\
	Sbox( a4,  a5,  a6,  a7, t0);\
	Sbox( a8,  a9, a10, a11, t0);\
	Sbox(a12, a13, a14, a15, t0);\
} while(0);

#define MCS32(a3, a2, a1, a0, b3, b2, b1, b0, c3, c2, c1, c0, d3, d2, d1, d0, e3, e2, e1, e0) do {\
	e3 = XOR(XOR(a1,b3), XOR(c2,d2));\
	e2 = XOR(XOR(XOR(a3,a0), XOR(b2,c1)), d1);\
	e1 = XOR(XOR(XOR(a3,a2), XOR(b1,c0)), XOR(XOR(c3, d0), d3));\
	e0 = XOR(XOR(a2,b0), XOR(c3,d3));\
} while(0);

#define MIXCOL32(a3, a2, a1, a0,  c3, c2, c1, c0,b3, b2, b1, b0, d3, d2, d1, d0, e3, e2, e1, e0) do {\
	MCS32(a3, a2, a1, a0, b3, b2, b1, b0, c3, c2, c1, c0, d3, d2, d1, d0, e3, e2, e1, e0);\
	MCS32(b3, b2, b1, b0, c3, c2, c1, c0, d3, d2, d1, d0, e3, e2, e1, e0, a3, a2, a1, a0);\
	MCS32(c3, c2, c1, c0, d3, d2, d1, d0, e3, e2, e1, e0, a3, a2, a1, a0, b3, b2, b1, b0);\
	MCS32(d3, d2, d1, d0, e3, e2, e1, e0, a3, a2, a1, a0, b3, b2, b1, b0, c3, c2, c1, c0);\
	d3 = c3; d2 = c2; d1=c1; d0=c0;\
	c3 = b3; c2 = b2; c1=b1; c0=b0;\
	b3 = a3; b2 = a2; b1=a1; b0=a0;\
	a3 = e3; a2 = e2; a1=e1; a0=e0;\
} while(0);


#define MIXCOL16(a3, a2, a1, a0, c3, c2, c1, c0, b3, b2, b1, b0, d3, d2, d1, d0, e3, e2, e1, e0) do {\
	b3 = SHRB128(a3,8);\
	b2 = SHRB128(a2,8);\
	b1 = SHRB128(a1,8);\
	b0 = SHRB128(a0,8);\
	d3 = SHRB128(c3,8);\
	d2 = SHRB128(c2,8);\
	d1 = SHRB128(c1,8);\
	d0 = SHRB128(c0,8);\
\
	MCS32(a3, a2, a1, a0, b3, b2, b1, b0, c3, c2, c1, c0, d3, d2, d1, d0, e3, e2, e1, e0);\
	MCS32(b3, b2, b1, b0, c3, c2, c1, c0, d3, d2, d1, d0, e3, e2, e1, e0, a3, a2, a1, a0);\
	MCS32(c3, c2, c1, c0, d3, d2, d1, d0, e3, e2, e1, e0, a3, a2, a1, a0, b3, b2, b1, b0);\
	MCS32(d3, d2, d1, d0, e3, e2, e1, e0, a3, a2, a1, a0, b3, b2, b1, b0, c3, c2, c1, c0);\
\
	a3 = XOR(AND(e3, mask_l64), SHLB128(a3,8));\
	a2 = XOR(AND(e2, mask_l64), SHLB128(a2,8));\
	a1 = XOR(AND(e1, mask_l64), SHLB128(a1,8));\
	a0 = XOR(AND(e0, mask_l64), SHLB128(a0,8));\
	c3 = XOR(AND(b3, mask_l64), SHLB128(c3,8));\
	c2 = XOR(AND(b2, mask_l64), SHLB128(c2,8));\
	c1 = XOR(AND(b1, mask_l64), SHLB128(c1,8));\
	c0 = XOR(AND(b0, mask_l64), SHLB128(c0,8));\
} while(0);


/* shift row operation, data structure follows above p16 */
#define SR16(a0, a1, a2, a3, a4, a5, a6, a7) do {\
	a0 = PSHUFB(a0, mask16_sr01);\
	a1 = PSHUFB(a1, mask16_sr01);\
	a2 = PSHUFB(a2, mask16_sr01);\
	a3 = PSHUFB(a3, mask16_sr01);\
	a4 = PSHUFB(a4, mask16_sr23);\
	a5 = PSHUFB(a5, mask16_sr23);\
	a6 = PSHUFB(a6, mask16_sr23);\
	a7 = PSHUFB(a7, mask16_sr23);\
} while(0);

/* shift row operation, data structure follows above p32 */
#define SR32(a3, a2, a1, a0, c3, c2, c1, c0, b3, b2, b1, b0, d3, d2, d1, d0) do {\
	b3 = PSHUF32(b3, _MM_SHUFFLE(2, 1, 0, 3));\
	b2 = PSHUF32(b2, _MM_SHUFFLE(2, 1, 0, 3));\
	b1 = PSHUF32(b1, _MM_SHUFFLE(2, 1, 0, 3));\
	b0 = PSHUF32(b0, _MM_SHUFFLE(2, 1, 0, 3));\
\
	c3 = PSHUF32(c3, _MM_SHUFFLE(1, 0, 3, 2));\
	c2 = PSHUF32(c2, _MM_SHUFFLE(1, 0, 3, 2));\
	c1 = PSHUF32(c1, _MM_SHUFFLE(1, 0, 3, 2));\
	c0 = PSHUF32(c0, _MM_SHUFFLE(1, 0, 3, 2));\
\
	d3 = PSHUF32(d3, _MM_SHUFFLE(0, 3, 2, 1));\
	d2 = PSHUF32(d2, _MM_SHUFFLE(0, 3, 2, 1));\
	d1 = PSHUF32(d1, _MM_SHUFFLE(0, 3, 2, 1));\
	d0 = PSHUF32(d0, _MM_SHUFFLE(0, 3, 2, 1));\
} while(0);


