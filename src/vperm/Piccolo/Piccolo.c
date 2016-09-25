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
#ifdef VPERM
#include <common/basic_helpers.h>

#ifdef VPERM
#ifdef Piccolo80
__attribute__((noinline)) void Piccolo80vperm_key_schedule(const u8* masterKey, u8* roundKeys);
__attribute__((noinline)) void Piccolo80vperm_core(const u8* message, const u8* subkeys, u8* ciphertext);
void Piccolo80vperm_cipher(const u64 plaintext_in[VPERM_P], const u16 keys_in[VPERM_P][KEY80], u64 ciphertext_out[VPERM_P]);
#endif
#ifdef Piccolo128
__attribute__((noinline)) void Piccolo128vperm_key_schedule(const u8* masterKey, u8* roundKeys);
__attribute__((noinline)) void Piccolo128vperm_core(const u8* message, const u8* subkeys, u8* ciphertext);
void Piccolo128vperm_cipher(const u64 plaintext_in[VPERM_P], const u16 keys_in[VPERM_P][KEY128], u64 ciphertext_out[VPERM_P]);
#endif
#endif

/* Desactivate arguments related warnings */
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif

/* Input transform shuffle */
__attribute__((visibility("hidden"),aligned(16))) u8 PiccoloInShuffleOdd[] = {0, 0xff, 1, 0xff, 2, 0xff, 3, 0xff, 4, 0xff, 5, 0xff, 6, 0xff, 7, 0xff};
__attribute__((visibility("hidden"),aligned(16))) u8 PiccoloInShuffleEven[]  = {0xff, 0, 0xff, 1, 0xff, 2, 0xff, 3, 0xff, 4, 0xff, 5, 0xff, 6, 0xff, 7};
/* Output transform shuffle */
__attribute__((visibility("hidden"),aligned(16))) u8 PiccoloOutShuffleOdd[] = {0, 2, 4, 6, 8, 10, 12, 14, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
__attribute__((visibility("hidden"),aligned(16))) u8 PiccoloOutShuffleEven[]  = {1, 3, 5, 7, 9, 11, 13, 15, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

/* Piccolo SBox (high and low nibbles) */ 
__attribute__((visibility("hidden"),aligned(16))) u8 PiccoloSBoxL[] = {0x0e, 0x04, 0x0b, 0x02, 0x03, 0x08, 0x00, 0x09, 0x01, 0x0a, 0x07, 0x0f, 0x06, 0x0c, 0x05, 0x0d};
__attribute__((visibility("hidden"),aligned(16))) u8 PiccoloSBoxH[] = {0xe0, 0x40, 0xb0, 0x20, 0x30, 0x80, 0x00, 0x90, 0x10, 0xa0, 0x70, 0xf0, 0x60, 0xc0, 0x50, 0xd0};


/* Piccolo 2 multiplication (high and low nibbles) */
__attribute__((visibility("hidden"),aligned(16))) u8 TwoMulPiccoloSBoxL[] = {0x0f, 0x08, 0x05, 0x04, 0x06, 0x03, 0x00, 0x01, 0x02, 0x07, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09};

/* Piccolo 3 multiplication (high and low nibbles) */ 
__attribute__((visibility("hidden"),aligned(16))) u8 ThreeMulPiccoloSBoxL[] = {0x01, 0x0c, 0x0e, 0x06, 0x05, 0x0b, 0x00, 0x08, 0x03, 0x0d, 0x09, 0x02, 0x0a, 0x07, 0x0f, 0x04};

/* Piccolo's MixCoumns shuffles */
__attribute__((visibility("hidden"),aligned(16))) u8 PiccoloThreeShuf[]  = {1, 2, 3, 0, 0xff, 0xff, 0xff, 0xff, 9, 10, 11, 8, 0xff, 0xff, 0xff, 0xff};
__attribute__((visibility("hidden"),aligned(16))) u8 PiccoloOneShufa[] = {2, 3, 0, 1, 0xff, 0xff, 0xff, 0xff, 10, 11, 8, 9, 0xff, 0xff, 0xff, 0xff};
__attribute__((visibility("hidden"),aligned(16))) u8 PiccoloOneShufb[] = {3, 0, 1, 2, 0xff, 0xff, 0xff, 0xff, 11, 8, 9, 10, 0xff, 0xff, 0xff, 0xff};


/* Mask for selecting high and low nibbles */
__attribute__((visibility("hidden"),aligned(16))) u8 PiccoloAndMaskL[] = {0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f};
__attribute__((visibility("hidden"),aligned(16))) u8 PiccoloAndMaskH[] = {0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0};

/* Mask for removing X0 and X2 */
__attribute__((visibility("hidden"),aligned(16))) u8 PiccoloAndMaskX13[] = {0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff};


/* Piccolo's Round Permutation */
__attribute__((visibility("hidden"),aligned(16))) u8 PiccoloRP[] = {4, 5, 14, 15, 8, 9, 2, 3, 12, 13, 6, 7, 0, 1, 10, 11};


#ifdef Piccolo80
/* Key schedule constants */
__attribute__((visibility("hidden"),aligned(16))) u8 PiccoloTcon80[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x77, 0x11, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x22, 0x99, 0x33, 0xdd, 0x00, 0x00, 0x00, 0x00, 0x11, 0xff, 0x11, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x22, 0x55, 0x33, 0xee, 0x00, 0x00, 0x00, 0x00, 0x11, 0x77, 0x11, 0x88, 0x00, 0x00, 0x00, 0x00, 0x22, 0x11, 0x33, 0xff, 0x00, 0x00, 0x00, 0x00, 0x22, 0xff, 0x11, 0x66, 0x00, 0x00, 0x00, 0x00, 0x33, 0xdd, 0x33, 0x88, 0x00, 0x00, 0x00, 0x00, 0x22, 0x77, 0x11, 0x44, 0x00, 0x00, 0x00, 0x00, 0x33, 0x99, 0x33, 0x99, 0x00, 0x00, 0x00, 0x00, 0x33, 0xff, 0x11, 0x22, 0x00, 0x00, 0x00, 0x00, 0x33, 0x55, 0x33, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x33, 0x77, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x11, 0x33, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x44, 0xff, 0x00, 0xee, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdd, 0x33, 0x44, 0x00, 0x00, 0x00, 0x00, 0x44, 0x77, 0x00, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x99, 0x33, 0x55, 0x00, 0x00, 0x00, 0x00, 0x55, 0xff, 0x00, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x33, 0x66, 0x00, 0x00, 0x00, 0x00, 0x55, 0x77, 0x00, 0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x33, 0x77, 0x00, 0x00, 0x00, 0x00, 0x66, 0xff, 0x00, 0x66, 0x00, 0x00, 0x00, 0x00, 0x11, 0xdd, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x77, 0x00, 0x44, 0x00, 0x00, 0x00, 0x00, 0x11, 0x99, 0x33, 0x11, 0x00, 0x00, 0x00, 0x00, 0x77, 0xff, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x11, 0x55, 0x33, 0x22, 0x00, 0x00, 0x00, 0x00, 0x77, 0x77, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11, 0x33, 0x33, 0x00, 0x00, 0x00, 0x00, 0x88, 0xff, 0x33, 0xee, 0x00, 0x00, 0x00, 0x00, 0x66, 0xdd, 0x22, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x88, 0x77, 0x33, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x66, 0x99, 0x22, 0xdd, 0x00, 0x00, 0x00, 0x00, 0x99, 0xff, 0x33, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x66, 0x55, 0x22, 0xee, 0x00, 0x00, 0x00, 0x00, 0x99, 0x77, 0x33, 0x88, 0x00, 0x00, 0x00, 0x00, 0x66, 0x11, 0x22, 0xff, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xff, 0x33, 0x66, 0x00, 0x00, 0x00, 0x00, 0x77, 0xdd, 0x22, 0x88, 0x00, 0x00, 0x00, 0x00, 0xaa, 0x77, 0x33, 0x44, 0x00, 0x00, 0x00, 0x00, 0x77, 0x99, 0x22, 0x99, 0x00, 0x00, 0x00, 0x00, 0xbb, 0xff, 0x33, 0x22, 0x00, 0x00, 0x00, 0x00, 0x77, 0x55, 0x22, 0xaa, 0x00, 0x00, 0x00, 0x00, 0xbb, 0x77, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x77, 0x11, 0x22, 0xbb, 0x00, 0x00, 0x00, 0x00, 0xcc, 0xff, 0x22, 0xee, 0x00, 0x00, 0x00, 0x00, 0x44, 0xdd, 0x22, 0x44, 0x00, 0x00, 0x00, 0x00, 0xcc, 0x77, 0x22, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x44, 0x99, 0x22, 0x55};
#endif

#ifdef Piccolo128
/* Key schedule constants */
__attribute__((visibility("hidden"),aligned(16))) u8 PiccoloTcon128[] = {0x00, 0x00, 0x00, 0x00, 0x66, 0xdd, 0x44, 0x55, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xdd, 0x88, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x77, 0x55, 0x44, 0x33, 0x00, 0x00, 0x00, 0x00, 0xaa, 0x11, 0x88, 0x99, 0x00, 0x00, 0x00, 0x00, 0x77, 0xdd, 0x44, 0x11, 0x00, 0x00, 0x00, 0x00, 0xaa, 0x55, 0x88, 0x88, 0x00, 0x00, 0x00, 0x00, 0x44, 0x55, 0x44, 0xff, 0x00, 0x00, 0x00, 0x00, 0xbb, 0x99, 0x88, 0xff, 0x00, 0x00, 0x00, 0x00, 0x44, 0xdd, 0x44, 0xdd, 0x00, 0x00, 0x00, 0x00, 0xbb, 0xdd, 0x88, 0xee, 0x00, 0x00, 0x00, 0x00, 0x55, 0x55, 0x44, 0xbb, 0x00, 0x00, 0x00, 0x00, 0xbb, 0x11, 0x88, 0xdd, 0x00, 0x00, 0x00, 0x00, 0x55, 0xdd, 0x44, 0x99, 0x00, 0x00, 0x00, 0x00, 0xbb, 0x55, 0x88, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x22, 0x55, 0x55, 0x77, 0x00, 0x00, 0x00, 0x00, 0x88, 0x99, 0x88, 0x33, 0x00, 0x00, 0x00, 0x00, 0x22, 0xdd, 0x55, 0x55, 0x00, 0x00, 0x00, 0x00, 0x88, 0xdd, 0x88, 0x22, 0x00, 0x00, 0x00, 0x00, 0x33, 0x55, 0x55, 0x33, 0x00, 0x00, 0x00, 0x00, 0x88, 0x11, 0x88, 0x11, 0x00, 0x00, 0x00, 0x00, 0x33, 0xdd, 0x55, 0x11, 0x00, 0x00, 0x00, 0x00, 0x88, 0x55, 0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x55, 0xff, 0x00, 0x00, 0x00, 0x00, 0x99, 0x99, 0x88, 0x77, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdd, 0x55, 0xdd, 0x00, 0x00, 0x00, 0x00, 0x99, 0xdd, 0x88, 0x66, 0x00, 0x00, 0x00, 0x00, 0x11, 0x55, 0x55, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x99, 0x11, 0x88, 0x55, 0x00, 0x00, 0x00, 0x00, 0x11, 0xdd, 0x55, 0x99, 0x00, 0x00, 0x00, 0x00, 0x99, 0x55, 0x88, 0x44, 0x00, 0x00, 0x00, 0x00, 0xee, 0x55, 0x66, 0x77, 0x00, 0x00, 0x00, 0x00, 0xee, 0x99, 0x99, 0xbb, 0x00, 0x00, 0x00, 0x00, 0xee, 0xdd, 0x66, 0x55, 0x00, 0x00, 0x00, 0x00, 0xee, 0xdd, 0x99, 0xaa, 0x00, 0x00, 0x00, 0x00, 0xff, 0x55, 0x66, 0x33, 0x00, 0x00, 0x00, 0x00, 0xee, 0x11, 0x99, 0x99, 0x00, 0x00, 0x00, 0x00, 0xff, 0xdd, 0x66, 0x11, 0x00, 0x00, 0x00, 0x00, 0xee, 0x55, 0x99, 0x88, 0x00, 0x00, 0x00, 0x00, 0xcc, 0x55, 0x66, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0x99, 0x99, 0xff, 0x00, 0x00, 0x00, 0x00, 0xcc, 0xdd, 0x66, 0xdd, 0x00, 0x00, 0x00, 0x00, 0xff, 0xdd, 0x99, 0xee, 0x00, 0x00, 0x00, 0x00, 0xdd, 0x55, 0x66, 0xbb, 0x00, 0x00, 0x00, 0x00, 0xff, 0x11, 0x99, 0xdd, 0x00, 0x00, 0x00, 0x00, 0xdd, 0xdd, 0x66, 0x99, 0x00, 0x00, 0x00, 0x00, 0xff, 0x55, 0x99, 0xcc, 0x00, 0x00, 0x00, 0x00, 0xaa, 0x55, 0x77, 0x77, 0x00, 0x00, 0x00, 0x00, 0xcc, 0x99, 0x99, 0x33, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xdd, 0x77, 0x55, 0x00, 0x00, 0x00, 0x00, 0xcc, 0xdd, 0x99, 0x22, 0x00, 0x00, 0x00, 0x00, 0xbb, 0x55, 0x77, 0x33, 0x00, 0x00, 0x00, 0x00, 0xcc, 0x11, 0x99, 0x11, 0x00, 0x00, 0x00, 0x00, 0xbb, 0xdd, 0x77, 0x11, 0x00, 0x00, 0x00, 0x00, 0xcc, 0x55, 0x99, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x55, 0x77, 0xff, 0x00, 0x00, 0x00, 0x00, 0xdd, 0x99, 0x99, 0x77, 0x00, 0x00, 0x00, 0x00, 0x88, 0xdd, 0x77, 0xdd, 0x00, 0x00, 0x00, 0x00, 0xdd, 0xdd, 0x99, 0x66, 0x00, 0x00, 0x00, 0x00, 0x99, 0x55, 0x77, 0xbb, 0x00, 0x00, 0x00, 0x00, 0xdd, 0x11, 0x99, 0x55, 0x00, 0x00, 0x00, 0x00, 0x99, 0xdd, 0x77, 0x99, 0x00, 0x00, 0x00, 0x00, 0xdd, 0x55, 0x99, 0x44};
#endif

/* gp register allocation */
#define Plaintext_			rdi
#define Ciphertext_			rdx
#define Keys_	 			rsi
#define RoundCounter_			rcx
#define PiccoloTcon80_	 		rax
#define PiccoloTcon128_	 		rbx
#ifdef AVX
  /* xmm register allocation */
  #define PiccoloSBoxL_ 		xmm0
  #define PiccoloSBoxH_ 		xmm1
  #define TwoMulPiccoloSBoxL_ 		xmm2
  #define ThreeMulPiccoloSBoxL_  	xmm3
  #define PiccoloThreeShuf_  		xmm4
  #define PiccoloOneShufa_		xmm5
  #define PiccoloOneShufb_		xmm6
  #define PiccoloAndMaskL_		xmm7
  #define PiccoloRP_			xmm8
  #define State_			xmm9
  #define Tmp1_				xmm10
  #define Tmp2_				xmm11
  #define Tmp3_				xmm12
  #define Tmp4_				xmm13
  #define Tmp5_				xmm14
  #define Tmp6_				xmm15
#else
  /* xmm register allocation */
  #define PiccoloSBoxL_ 		xmm0
  #define PiccoloSBoxH_ 		xmm1
  #define TwoMulPiccoloSBoxL_ 		xmm2
  #define ThreeMulPiccoloSBoxL_  	xmm3
  #define PiccoloThreeShuf_  		xmm4
  #define PiccoloOneShufa_		xmm5
  #define PiccoloOneShufb_		xmm6
  #define PiccoloAndMaskL_		xmm7
  #define PiccoloRP_			xmm8
  #define State_			xmm9
  #define Tmp1_				xmm10
  #define Tmp2_				xmm11
  #define Tmp3_				xmm12
  #define Tmp4_				xmm13
  #define Tmp5_				xmm14
  #define Tmp6_				xmm15
#endif

#ifdef AVX
  #define PiccoloROUND PiccoloROUND_AVX
  #define PiccoloLASTROUND PiccoloLASTROUND_AVX
  #define format_input format_input_AVX
  #define format_output format_output_AVX
#else
  #define PiccoloROUND PiccoloROUND_SSSE
  #define PiccoloLASTROUND PiccoloLASTROUND_SSSE
  #define format_input format_input_SSSE
  #define format_output format_output_SSSE
#endif



/***************** ROUNDS *************************/

/* ---------------------------------------------------------*/
/* ---------------------- SSSE -----------------------------*/
/* ---------------------------------------------------------*/
/* The format message primitive */
/* Interleaves nibbles of 16 bytes pointed register */
#define format_input_SSSE(in1, in2, xmmout, tmp1, tmp2, tmp3) do {\
	/* Move the two quadwords in temp registers */\
	asm("movq    "tostr(tmp1)", ["tostr(in1)"]");\
	asm("movq    "tostr(tmp2)", ["tostr(in2)"]");\
	asm("movq    "tostr(xmmout)", "tostr(tmp1)"");\
	asm("movq    "tostr(tmp3)", "tostr(tmp2)"");\
	/* Keep the low parts */\
	asm("pand    "tostr(tmp1)", [rip + "tostr(PiccoloAndMaskL)"]");\
	asm("pand    "tostr(tmp2)", [rip + "tostr(PiccoloAndMaskL)"]");\
	/* Keep the high parts */\
	asm("pand    "tostr(xmmout)", [rip + "tostr(PiccoloAndMaskH)"]");\
	asm("pand    "tostr(tmp3)", [rip + "tostr(PiccoloAndMaskH)"]");\
	/* Shift the elements. Word1 high is put low, Word2 low is put high */\
	asm("psrlq   "tostr(xmmout)", 4");\
	asm("psllq   "tostr(tmp2)", 4");\
	/* Shuffle */\
	asm("pshufb  "tostr(tmp1)", [rip + "tostr(PiccoloInShuffleEven)"]");\
	asm("pshufb  "tostr(tmp2)", [rip + "tostr(PiccoloInShuffleEven)"]");\
	asm("pshufb  "tostr(xmmout)", [rip + "tostr(PiccoloInShuffleOdd)"]");\
	asm("pshufb  "tostr(tmp3)", [rip + "tostr(PiccoloInShuffleOdd)"]");\
	/* Merge */\
	asm("pxor   "tostr(xmmout)", "tostr(tmp1)"");\
	asm("pxor   "tostr(xmmout)", "tostr(tmp2)"");\
	asm("pxor   "tostr(xmmout)", "tostr(tmp3)"");\
} while(0);

/* Interleaves nibbles from a xmm register to memory */
#define format_output_SSSE(out, xmmin, tmp1, tmp2, tmp3) do {\
	/* Copy the input */\
	asm("movdqa  "tostr(tmp1)", "tostr(xmmin)"");\
	asm("movdqa  "tostr(tmp2)", "tostr(xmmin)"");\
	/* Shuffle */\
	asm("pshufb  "tostr(tmp1)", [rip + "tostr(PiccoloOutShuffleEven)"]");\
	asm("pshufb  "tostr(tmp2)", [rip + "tostr(PiccoloOutShuffleOdd)"]");\
	asm("movdqa  "tostr(tmp3)", "tostr(tmp1)"");\
	asm("movdqa  "tostr(xmmin)", "tostr(tmp2)"");\
	/* Shift and mask for Word1 */\
	asm("pand    "tostr(tmp1)", [rip + "tostr(PiccoloAndMaskL)"]");\
	asm("pand    "tostr(tmp2)", [rip + "tostr(PiccoloAndMaskL)"]");\
	asm("psllq   "tostr(tmp2)", 4");\
	asm("pxor   "tostr(tmp1)", "tostr(tmp2)"");\
	/* Shift and mask for Word2 */\
	asm("pand    "tostr(tmp3)", [rip + "tostr(PiccoloAndMaskH)"]");\
	asm("pand    "tostr(xmmin)", [rip + "tostr(PiccoloAndMaskH)"]");\
	asm("psrlq   "tostr(tmp3)", 4");\
	asm("pxor    "tostr(tmp3)", "tostr(xmmin)"");\
	/* Save Word1 to memory */\
	asm("movq    ["tostr(out)"], "tostr(tmp1)"");\
	/* Merge the two Words */\
	asm("movq    ["tostr(out)"+8], "tostr(tmp3)"");\
} while(0);

#define PiccoloLASTROUND_SSSE() do {\
	/* ------------ */\
	/* LOW NIBBLES  */\
	/* ------------ */\
	/* Get the state */\
	asm("movdqa  "tostr(Tmp1_)", "tostr(State_)"");\
	/* Select the low nibbles */\
	asm("pand    "tostr(Tmp1_)", "tostr(PiccoloAndMaskL_)"");\
	/* Do the SBox+Multiplications */\
	asm("movdqa  "tostr(Tmp2_)", "tostr(PiccoloSBoxL_)"");\
	asm("movdqa  "tostr(Tmp4_)", "tostr(TwoMulPiccoloSBoxL_)"");\
	asm("movdqa  "tostr(Tmp5_)", "tostr(ThreeMulPiccoloSBoxL_)"");\
\
	asm("pshufb  "tostr(Tmp2_)", "tostr(Tmp1_)"");\
	asm("pshufb  "tostr(Tmp4_)", "tostr(Tmp1_)"");\
	asm("pshufb  "tostr(Tmp5_)", "tostr(Tmp1_)"");\
	asm("movdqa  "tostr(Tmp3_)", "tostr(Tmp2_)"");\
\
	/* Shuffle for MixColumns */\
	asm("pshufb  "tostr(Tmp2_)", "tostr(PiccoloOneShufa_)"");\
	asm("pshufb  "tostr(Tmp3_)", "tostr(PiccoloOneShufb_)"");\
	asm("pshufb  "tostr(Tmp5_)", "tostr(PiccoloThreeShuf_)"");\
\
	/* Merge */\
	asm("pxor    "tostr(Tmp2_)", "tostr(Tmp3_)"");\
	asm("pxor    "tostr(Tmp2_)", "tostr(Tmp4_)"");\
	asm("pxor    "tostr(Tmp2_)", "tostr(Tmp5_)"");\
\
	/* Second SBox lookup and result in Tmp6_ */\
	asm("movdqa  "tostr(Tmp6_)", "tostr(PiccoloSBoxL_)"");\
	asm("pshufb  "tostr(Tmp6_)", "tostr(Tmp2_)"");\
\
	/* ------------ */\
	/* HIGH NIBBLES */\
	/* ------------ */\
	/* Get the state */\
	asm("movdqa  "tostr(Tmp1_)", "tostr(State_)"");\
	/* Select the high nibbles and shift them right */\
	asm("psrlq   "tostr(Tmp1_)", 4");\
	asm("pand    "tostr(Tmp1_)", "tostr(PiccoloAndMaskL_)"");\
	/* Do the SBox+Multiplications */\
	asm("movdqa  "tostr(Tmp2_)", "tostr(PiccoloSBoxL_)"");\
	asm("movdqa  "tostr(Tmp4_)", "tostr(TwoMulPiccoloSBoxL_)"");\
	asm("movdqa  "tostr(Tmp5_)", "tostr(ThreeMulPiccoloSBoxL_)"");\
\
	asm("pshufb  "tostr(Tmp2_)", "tostr(Tmp1_)"");\
	asm("pshufb  "tostr(Tmp4_)", "tostr(Tmp1_)"");\
	asm("pshufb  "tostr(Tmp5_)", "tostr(Tmp1_)"");\
	asm("movdqa  "tostr(Tmp3_)", "tostr(Tmp2_)"");\
\
	/* Shuffle for MixColumns */\
	asm("pshufb  "tostr(Tmp2_)", "tostr(PiccoloOneShufa_)"");\
	asm("pshufb  "tostr(Tmp3_)", "tostr(PiccoloOneShufb_)"");\
	asm("pshufb  "tostr(Tmp5_)", "tostr(PiccoloThreeShuf_)"");\
\
	/* Merge */\
	asm("pxor    "tostr(Tmp2_)", "tostr(Tmp3_)"");\
	asm("pxor    "tostr(Tmp2_)", "tostr(Tmp4_)"");\
	asm("pxor    "tostr(Tmp2_)", "tostr(Tmp5_)"");\
\
	/* Second SBox lookup and result in Tmp6_ */\
	asm("movdqa  "tostr(Tmp3_)", "tostr(PiccoloSBoxH_)"");\
	asm("pshufb  "tostr(Tmp3_)", "tostr(Tmp2_)"");\
\
	/* Merge with low nibbles result, and shift left for Feistel */\
	asm("pxor    "tostr(Tmp6_)", "tostr(Tmp3_)"");\
	asm("pslldq  "tostr(Tmp6_)", 4");\
	asm("pand    "tostr(Tmp6_)", [rip + PiccoloAndMaskX13]");\
	/* AddRoundKey */\
	asm("pxor    "tostr(Tmp6_)", ["tostr(Keys_)"+"tostr(RoundCounter_)"]");\
	asm("add     "tostr(RoundCounter_)", 16");\
\
	/* Merge with the state for Feistel (propagate X0 and X2) */\
	asm("pxor    "tostr(State_)", "tostr(Tmp6_)"");\
} while(0);

#define PiccoloROUND_SSSE() do {\
	PiccoloLASTROUND_SSSE();\
	/* Apply Round Permutation */\
	asm("pshufb    "tostr(State_)", "tostr(PiccoloRP_)"");\
} while(0);



/* ---------------------------------------------------------*/
/* ---------------------- AVX ------------------------------*/
/* ---------------------------------------------------------*/
/* The format message primitive */
/* Interleaves nibbles of 16 bytes pointed register */
#define format_input_AVX(in1, in2, xmmout, tmp1, tmp2, tmp3) do {\
	/* Mov the two quadwords in temp registers */\
	asm("movq    "tostr(tmp1)", ["tostr(in1)"]");\
	asm("movq    "tostr(tmp2)", ["tostr(in2)"]");\
	/* Keep the high parts */\
	asm("vpand    "tostr(xmmout)", "tostr(tmp1)", [rip + "tostr(PiccoloAndMaskH)"]");\
	asm("vpand    "tostr(tmp3)", "tostr(tmp2)", [rip + "tostr(PiccoloAndMaskH)"]");\
	/* Keep the low parts */\
	asm("vpand    "tostr(tmp1)", "tostr(tmp1)", [rip + "tostr(PiccoloAndMaskL)"]");\
	asm("vpand    "tostr(tmp2)", "tostr(tmp2)", [rip + "tostr(PiccoloAndMaskL)"]");\
	/* Shift the elements. Word1 high is put low, Word2 low is put high */\
	asm("psrlq   "tostr(xmmout)", 4");\
	asm("psllq   "tostr(tmp2)", 4");\
	/* Shuffle */\
	asm("pshufb  "tostr(tmp1)", [rip + "tostr(PiccoloInShuffleEven)"]");\
	asm("pshufb  "tostr(tmp2)", [rip + "tostr(PiccoloInShuffleEven)"]");\
	asm("pshufb  "tostr(xmmout)", [rip + "tostr(PiccoloInShuffleOdd)"]");\
	asm("pshufb  "tostr(tmp3)", [rip + "tostr(PiccoloInShuffleOdd)"]");\
	/* Merge */\
	asm("pxor   "tostr(xmmout)", "tostr(tmp1)"");\
	asm("pxor   "tostr(xmmout)", "tostr(tmp2)"");\
	asm("pxor   "tostr(xmmout)", "tostr(tmp3)"");\
} while(0);

/* Interleaves nibbles from a xmm register to memory */
#define format_output_AVX(out, xmmin, tmp1, tmp2, tmp3) do {\
	/* Shuffle */\
	asm("vpshufb "tostr(tmp1)", "tostr(xmmin)", [rip + "tostr(PiccoloOutShuffleEven)"]");\
	asm("vpshufb "tostr(tmp2)", "tostr(xmmin)", [rip + "tostr(PiccoloOutShuffleOdd)"]");\
	asm("movdqa  "tostr(tmp3)", "tostr(tmp1)"");\
	asm("movdqa  "tostr(xmmin)", "tostr(tmp2)"");\
	/* Shift and mask for Word1 */\
	asm("pand    "tostr(tmp1)", [rip + "tostr(PiccoloAndMaskL)"]");\
	asm("pand    "tostr(tmp2)", [rip + "tostr(PiccoloAndMaskL)"]");\
	asm("psllq   "tostr(tmp2)", 4");\
	asm("pxor   "tostr(tmp1)", "tostr(tmp2)"");\
	/* Shift and mask for Word2 */\
	asm("pand    "tostr(tmp3)", [rip + "tostr(PiccoloAndMaskH)"]");\
	asm("pand    "tostr(xmmin)", [rip + "tostr(PiccoloAndMaskH)"]");\
	asm("psrlq   "tostr(tmp3)", 4");\
	asm("pxor    "tostr(tmp3)", "tostr(xmmin)"");\
	/* Save Word1 to memory */\
	asm("movq    ["tostr(out)"], "tostr(tmp1)"");\
	/* Merge the two Words */\
	asm("movq    ["tostr(out)"+8], "tostr(tmp3)"");\
} while(0);

#define PiccoloLASTROUND_AVX() do {\
	/* ------------ */\
	/* LOW NIBBLES  */\
	/* ------------ */\
	/* Get the state */\
	/* Select the low nibbles */\
	asm("vpand    "tostr(Tmp1_)", "tostr(State_)", "tostr(PiccoloAndMaskL_)"");\
	/* Do the SBox+Multiplications */\
\
	asm("vpshufb "tostr(Tmp2_)", "tostr(PiccoloSBoxL_)", "tostr(Tmp1_)"");\
	asm("vpshufb "tostr(Tmp4_)", "tostr(TwoMulPiccoloSBoxL_)", "tostr(Tmp1_)"");\
	asm("vpshufb "tostr(Tmp5_)", "tostr(ThreeMulPiccoloSBoxL_)", "tostr(Tmp1_)"");\
	asm("movdqa  "tostr(Tmp3_)", "tostr(Tmp2_)"");\
\
	/* Shuffle for MixColumns */\
	asm("pshufb  "tostr(Tmp2_)", "tostr(PiccoloOneShufa_)"");\
	asm("pshufb  "tostr(Tmp3_)", "tostr(PiccoloOneShufb_)"");\
	asm("pshufb  "tostr(Tmp5_)", "tostr(PiccoloThreeShuf_)"");\
\
	/* Merge */\
	asm("pxor    "tostr(Tmp2_)", "tostr(Tmp3_)"");\
	asm("pxor    "tostr(Tmp2_)", "tostr(Tmp4_)"");\
	asm("pxor    "tostr(Tmp2_)", "tostr(Tmp5_)"");\
\
	/* Second SBox lookup and result in Tmp6_ */\
	asm("movdqa  "tostr(Tmp6_)", "tostr(PiccoloSBoxL_)"");\
	asm("pshufb  "tostr(Tmp6_)", "tostr(Tmp2_)"");\
\
	/* ------------ */\
	/* HIGH NIBBLES */\
	/* ------------ */\
	/* Get the state */\
	/* Select the high nibbles and shift them right */\
	asm("vpsrlq  "tostr(Tmp1_)", "tostr(State_)", 4");\
	asm("pand    "tostr(Tmp1_)", "tostr(PiccoloAndMaskL_)"");\
	/* Do the SBox+Multiplications */\
\
	asm("vpshufb "tostr(Tmp2_)", "tostr(PiccoloSBoxL_)", "tostr(Tmp1_)"");\
	asm("vpshufb "tostr(Tmp4_)", "tostr(TwoMulPiccoloSBoxL_)", "tostr(Tmp1_)"");\
	asm("vpshufb "tostr(Tmp5_)", "tostr(ThreeMulPiccoloSBoxL_)", "tostr(Tmp1_)"");\
	asm("movdqa  "tostr(Tmp3_)", "tostr(Tmp2_)"");\
\
	/* Shuffle for MixColumns */\
	asm("pshufb  "tostr(Tmp2_)", "tostr(PiccoloOneShufa_)"");\
	asm("pshufb  "tostr(Tmp3_)", "tostr(PiccoloOneShufb_)"");\
	asm("pshufb  "tostr(Tmp5_)", "tostr(PiccoloThreeShuf_)"");\
\
	/* Merge */\
	asm("pxor    "tostr(Tmp2_)", "tostr(Tmp3_)"");\
	asm("pxor    "tostr(Tmp2_)", "tostr(Tmp4_)"");\
	asm("pxor    "tostr(Tmp2_)", "tostr(Tmp5_)"");\
\
	/* Second SBox lookup and result in Tmp6_ */\
	asm("movdqa  "tostr(Tmp3_)", "tostr(PiccoloSBoxH_)"");\
	asm("pshufb  "tostr(Tmp3_)", "tostr(Tmp2_)"");\
\
	/* Merge with low nibbles result, and shift left for Feistel */\
	asm("pxor    "tostr(Tmp6_)", "tostr(Tmp3_)"");\
	asm("pslldq  "tostr(Tmp6_)", 4");\
	asm("pand    "tostr(Tmp6_)", [rip + PiccoloAndMaskX13]");\
	/* AddRoundKey */\
	asm("pxor    "tostr(Tmp6_)", ["tostr(Keys_)"+"tostr(RoundCounter_)"]");\
	asm("add     "tostr(RoundCounter_)", 16");\
\
	/* Merge with the state for Feistel (propagate X0 and X2) */\
	asm("pxor    "tostr(State_)", "tostr(Tmp6_)"");\
} while(0);

#define PiccoloROUND_AVX() do {\
	PiccoloLASTROUND_AVX();\
	/* Apply Round Permutation */\
	asm("pshufb    "tostr(State_)", "tostr(PiccoloRP_)"");\
} while(0);


/***************** KEY SCHEDULE STUFF *************************/
#ifdef Piccolo80
/* Key schedule macros */
__attribute__((visibility("hidden"),aligned(16))) u8 PiccoloKSShufwa[] = {0, 1, 6, 7, 0xff, 0xff, 0xff, 0xff, 4, 5, 2, 3, 0xff, 0xff, 0xff, 0xff};
__attribute__((visibility("hidden"),aligned(16))) u8 PiccoloKSShufwb[] = {4, 5, 2, 3, 0xff, 0xff, 0xff, 0xff, 0, 1, 6, 7, 0xff, 0xff, 0xff, 0xff};
__attribute__((visibility("hidden"),aligned(16))) u8 PiccoloKSShufa[] = {0xff, 0xff, 0xff, 0xff, 0, 1, 2, 3, 0xff, 0xff, 0xff, 0xff, 4, 5, 6, 7};
__attribute__((visibility("hidden"),aligned(16))) u8 PiccoloKSShufb[] = {0xff, 0xff, 0xff, 0xff, 4, 5, 6, 7, 0xff, 0xff, 0xff, 0xff, 4, 5, 6, 7};


#define KEYSCHED_SSSE80() do {\
	/* 0 = (k2, k3) */\
	asm("movdqa xmm5, xmm0");\
	asm("pxor   xmm5, ["tostr(PiccoloTcon80_)"+rcx-16]");\
	asm("movdqa [rsi+rcx], xmm5");\
	asm("add rcx, 16");\
	/* 1 = (k0, k1) */\
	asm("movdqa xmm5, xmm1");\
	asm("pxor   xmm5, ["tostr(PiccoloTcon80_)"+rcx-16]");\
	asm("movdqa [rsi+rcx], xmm5");\
	asm("add rcx, 16");\
	/* 2 = (k2, k3) */\
	asm("movdqa xmm5, xmm0");\
	asm("pxor   xmm5, ["tostr(PiccoloTcon80_)"+rcx-16]");\
	asm("movdqa [rsi+rcx], xmm5");\
	asm("add rcx, 16");\
	/* 3 = (k4, k4) */\
	asm("movdqa xmm5, xmm2");\
	asm("pxor   xmm5, ["tostr(PiccoloTcon80_)"+rcx-16]");\
	asm("movdqa [rsi+rcx], xmm5");\
	asm("add rcx, 16");\
	/* 4 = (k0, k1) */\
	asm("movdqa xmm5, xmm1");\
	asm("pxor   xmm5, ["tostr(PiccoloTcon80_)"+rcx-16]");\
	asm("movdqa [rsi+rcx], xmm5");\
	asm("add rcx, 16");\
\
} while(0);
#define KEYSCHED_AVX80() do {\
	/* 0 = (k2, k3) */\
	asm("vpxor   xmm5, xmm0, ["tostr(PiccoloTcon80_)"+rcx-16]");\
	asm("movdqa [rsi+rcx], xmm5");\
	asm("add rcx, 16");\
	/* 1 = (k0, k1) */\
	asm("vpxor  xmm5, xmm1, ["tostr(PiccoloTcon80_)"+rcx-16]");\
	asm("movdqa [rsi+rcx], xmm5");\
	asm("add rcx, 16");\
	/* 2 = (k2, k3) */\
	asm("vpxor   xmm5, xmm0, ["tostr(PiccoloTcon80_)"+rcx-16]");\
	asm("movdqa [rsi+rcx], xmm5");\
	asm("add rcx, 16");\
	/* 3 = (k4, k4) */\
	asm("vpxor  xmm5, xmm2, ["tostr(PiccoloTcon80_)"+rcx-16]");\
	asm("movdqa [rsi+rcx], xmm5");\
	asm("add rcx, 16");\
	/* 4 = (k0, k1) */\
	asm("vpxor   xmm5, xmm1, ["tostr(PiccoloTcon80_)"+rcx-16]");\
	asm("movdqa [rsi+rcx], xmm5");\
	asm("add rcx, 16");\
\
} while(0);
#ifdef AVX
  #define KEYSCHED80 KEYSCHED_AVX80
#else
  #define KEYSCHED80 KEYSCHED_SSSE80
#endif

__attribute__((noinline)) void Piccolo80vperm_key_schedule(const u8* masterKey, u8* roundKeys)
{
        /*      Note : master key in rdi and round keys in rsi  */
        /*      __cdecl calling convention                      */
	asm (".intel_syntax noprefix");
	Push_All_Regs();
	
	asm("lea "tostr(PiccoloTcon80_)", [rip + PiccoloTcon80]");

	/* Isolate interleaved k2 and k3 */
	format_input(rdi+4, rdi+14, xmm0, xmm13, xmm14, xmm15);
	/* Shuffle the result */
	asm("pshufb xmm0, [rip + PiccoloKSShufa]");

	/* Isolate interleaved k0 and k1 */
	format_input(rdi, rdi+10, xmm1, xmm13, xmm14, xmm15);
	asm("movdqa xmm3, xmm1");
	/* Shuffle the result */
	asm("pshufb xmm1, [rip + PiccoloKSShufa]");
	/* Get the pre-whitening keys */
	asm("pshufb xmm3, [rip + PiccoloKSShufwa]");

	/* Isolate interleaved k4 */
	format_input(rdi+6, rdi+16, xmm2, xmm13, xmm14, xmm15);
	asm("movdqa xmm4, xmm2");
	/* Shuffle the result */
	asm("pshufb xmm2, [rip + PiccoloKSShufb]");
	/* Get the post-whitening keys */
	asm("pshufb xmm4, [rip + PiccoloKSShufwb]");

	/* Go for the transformed key schedule */
	asm("xor rcx, rcx");
	/* Store the pre-whitening keys */
	asm("movdqa [rsi+rcx], xmm3");
	asm("add rcx, 16");
	KEYSCHED80();
	KEYSCHED80();
	KEYSCHED80();
	KEYSCHED80();
	KEYSCHED80();
	/* Store the post-whitening keys */
	asm("movdqa [rsi+rcx], xmm4");


	Pop_All_Regs();
	asm (".att_syntax noprefix");

	return;
}
#endif

#ifdef Piccolo128
/* Key schedule macros */	
__attribute__((visibility("hidden"),aligned(16))) u8 PiccoloKSShufw0[] = {0, 1, 6, 7, 0xff, 0xff, 0xff, 0xff, 4, 5, 2, 3, 0xff, 0xff, 0xff, 0xff};
__attribute__((visibility("hidden"),aligned(16))) u8 PiccoloKSShufw1[] = {0, 1, 14, 15, 0xff, 0xff, 0xff, 0xff, 12, 13, 2, 3, 0xff, 0xff, 0xff, 0xff};

__attribute__((visibility("hidden"),aligned(16))) u8 PiccoloKSShuf0[] = {0xff, 0xff, 0xff, 0xff, 0, 1, 2, 3, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
__attribute__((visibility("hidden"),aligned(16))) u8 PiccoloKSShuf2[] = {0xff, 0xff, 0xff, 0xff, 8, 9, 10, 11, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
__attribute__((visibility("hidden"),aligned(16))) u8 PiccoloKSShuf1[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 4, 5, 6, 7};
__attribute__((visibility("hidden"),aligned(16))) u8 PiccoloKSShuf3[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 12, 13, 14, 15};

__attribute__((noinline)) void Piccolo128vperm_key_schedule(const u8* masterKey, u8* roundKeys)
{
	/*	Note : master key in rdi and round keys in rsi 	*/
	/*	__cdecl calling convention			*/	
	asm (".intel_syntax noprefix");
	Push_All_Regs();
	
	asm("lea "tostr(PiccoloTcon128_)", [rip + PiccoloTcon128]");
	/* Interleave keys */
	format_input(rdi, rdi+16, xmm11, xmm13, xmm14, xmm15);
	format_input(rdi+8, rdi+24, xmm12, xmm13, xmm14, xmm15);
#ifdef AVX
	/* Pre-Whitening Key */
	asm("vpshufb xmm0, xmm11, [rip + PiccoloKSShufw0]");
	asm("movdqa [rsi], xmm0");
	/* Post-Whitening Key */
	asm("vpshufb xmm1, xmm12, [rip + PiccoloKSShufw1]");
	asm("movdqa [rsi+512], xmm1");
	/* Even keys */
	/* --------- */
	/* Isolate interleaved k0 */
	asm("vpshufb xmm0, xmm11, [rip + PiccoloKSShuf0]");
	/* Isolate interleaved k2 */
	asm("vpshufb xmm2, xmm11, [rip + PiccoloKSShuf2]");
	/* Isolate interleaved k4 */
	asm("vpshufb xmm4, xmm12, [rip + PiccoloKSShuf0]");
	/* Isolate interleaved k6 */
	asm("vpshufb xmm6, xmm12, [rip + PiccoloKSShuf2]");
	/* Odd keys */
	/* -------- */
	/* Isolate interleaved k1 */
	asm("vpshufb xmm1, xmm11, [rip + PiccoloKSShuf1]");
	/* Isolate interleaved k3 */
	asm("vpshufb xmm3, xmm11, [rip + PiccoloKSShuf3]");
	/* Isolate interleaved k5 */
	asm("vpshufb xmm5, xmm12, [rip + PiccoloKSShuf1]");
	/* Isolate interleaved k7 */
	asm("vpshufb xmm7, xmm12, [rip + PiccoloKSShuf3]");

	/* Compute the pairs */
	/* 2 - 3 */
	asm("vpxor   xmm13, xmm2, xmm3");
	asm("pxor   xmm13, ["tostr(PiccoloTcon128_)"]");	
	asm("movdqa [rsi+16], xmm13");
	/* 4 - 5 */
	asm("vpxor   xmm13, xmm4, xmm5");
	asm("mov    rcx, 2*2");
	asm("vpxor   xmm8, xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm8");
	asm("mov    rcx, 2*7");
	asm("vpxor   xmm9, xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm9");
	asm("mov    rcx, 2*9");
	asm("vpxor   xmm10, xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm10");
	/* 6 - 7 */
	asm("vpxor  xmm13, xmm6, xmm7");
	asm("mov    rcx, 2*3");
	asm("vpxor  xmm8, xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm8");
	asm("mov    rcx, 2*5");
	asm("vpxor   xmm9, xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm9");
	/* 2 - 1 */
	asm("vpxor  xmm13, xmm2, xmm1");
	asm("mov    rcx, 2*4");
	asm("vpxor  xmm8, xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm8");
	asm("mov    rcx, 2*20");
	asm("vpxor  xmm9, xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm9");
	/* 0 - 3 */
	asm("vpxor  xmm13, xmm0, xmm3");
	asm("mov    rcx, 2*6");
	asm("vpxor  xmm8, xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm8");
	asm("mov    rcx, 2*11");
	asm("vpxor  xmm9, xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm9");
	asm("mov    rcx, 2*13");
	asm("vpxor  xmm10, xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm10");
	/* 6 - 1 */
	asm("vpxor  xmm13, xmm6, xmm1");
	asm("mov    rcx, 2*8");
	asm("vpxor   xmm8, xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm8");
	asm("mov    rcx, 2*24");
	asm("vpxor   xmm9, xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm9");
	/* 2 - 7 */
	asm("vpxor  xmm13, xmm2, xmm7");
	asm("mov    rcx, 2*10");
	asm("vpxor  xmm8, xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm8");
	asm("mov    rcx, 2*15");
	asm("vpxor  xmm9, xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm9");
	asm("mov    rcx, 2*17");
	asm("vpxor  xmm10, xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm10");
	/* 4 - 1 */
	asm("vpxor  xmm13, xmm4, xmm1");
	asm("mov    rcx, 2*12");
	asm("vpxor  xmm8, xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm8");
	asm("mov    rcx, 2*28");
	asm("vpxor  xmm9, xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm9");
	/* 6 - 5 */
	asm("vpxor  xmm13, xmm6, xmm5");
	asm("mov    rcx, 2*14");
	asm("vpxor  xmm8, xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm8");
	asm("mov    rcx, 2*19");
	asm("vpxor  xmm9, xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm9");
	asm("mov    rcx, 2*21");
	asm("vpxor  xmm10, xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm10");
	/* 0 - 1 */
	asm("vpxor  xmm13, xmm0, xmm1");
	asm("mov    rcx, 2*16");
	asm("pxor   xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm13");
	/* 4 - 3 */
	asm("vpxor  xmm13, xmm4, xmm3");
	asm("mov    rcx, 2*18");
	asm("vpxor  xmm8, xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm8");
	asm("mov    rcx, 2*23");
	asm("vpxor  xmm9, xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm9");
	asm("mov    rcx, 2*25");
	asm("vpxor  xmm10, xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm10");	
	/* 0 - 7 */
	asm("vpxor  xmm13, xmm0, xmm7");
	asm("mov    rcx, 2*22");
	asm("vpxor  xmm8, xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm8");
	asm("mov    rcx, 2*27");
	asm("vpxor  xmm9, xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm9");
	asm("mov    rcx, 2*29");
	asm("vpxor  xmm10, xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm10");
	/* 2 - 5 */
	asm("vpxor  xmm13, xmm2, xmm5");
	asm("mov    rcx, 2*26");
	asm("vpxor  xmm8, xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm8");
	asm("mov    rcx, 2*31");
	asm("vpxor   xmm9, xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm9");
	/* 6 - 3 */
	asm("vpxor  xmm13, xmm6, xmm3");
	asm("mov    rcx, 2*30");
	asm("pxor   xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm13");
#else
	/* Pre-Whitening Key */
	asm("movdqa xmm0, xmm11");
	asm("pshufb xmm0, [rip + PiccoloKSShufw0]");
	asm("movdqa [rsi], xmm0");
	/* Post-Whitening Key */
	asm("movdqa xmm1, xmm12");
	asm("pshufb xmm1, [rip + PiccoloKSShufw1]");
	asm("movdqa [rsi+512], xmm1");
	/* Even keys */
	/* --------- */
	/* Isolate interleaved k0 */
	asm("movdqa xmm0, xmm11");
	asm("pshufb xmm0, [rip + PiccoloKSShuf0]");
	/* Isolate interleaved k2 */
	asm("movdqa xmm2, xmm11");
	asm("pshufb xmm2, [rip + PiccoloKSShuf2]");
	/* Isolate interleaved k4 */
	asm("movdqa xmm4, xmm12");
	asm("pshufb xmm4, [rip + PiccoloKSShuf0]");
	/* Isolate interleaved k6 */
	asm("movdqa xmm6, xmm12");
	asm("pshufb xmm6, [rip + PiccoloKSShuf2]");
	/* Odd keys */
	/* -------- */
	/* Isolate interleaved k1 */
	asm("movdqa xmm1, xmm11");
	asm("pshufb xmm1, [rip + PiccoloKSShuf1]");
	/* Isolate interleaved k3 */
	asm("movdqa xmm3, xmm11");
	asm("pshufb xmm3, [rip + PiccoloKSShuf3]");
	/* Isolate interleaved k5 */
	asm("movdqa xmm5, xmm12");
	asm("pshufb xmm5, [rip + PiccoloKSShuf1]");
	/* Isolate interleaved k7 */
	asm("movdqa xmm7, xmm12");
	asm("pshufb xmm7, [rip + PiccoloKSShuf3]");

	/* Compute the pairs */
	/* 2 - 3 */
	asm("movdqa xmm13, xmm2");
	asm("movdqa xmm14, xmm3");
	asm("pxor   xmm13, xmm14");
	asm("pxor   xmm13, ["tostr(PiccoloTcon128_)"]");	
	asm("movdqa [rsi+16], xmm13");
	/* 4 - 5 */
	asm("movdqa xmm13, xmm4");
	asm("movdqa xmm14, xmm5");
	asm("pxor   xmm13, xmm14");
	asm("movdqa xmm8, xmm13");
	asm("movdqa xmm9, xmm13");
	asm("mov    rcx, 2*2");
	asm("pxor   xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm13");
	asm("mov    rcx, 2*7");
	asm("pxor   xmm8, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm8");
	asm("mov    rcx, 2*9");
	asm("pxor   xmm9, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm9");
	/* 6 - 7 */
	asm("movdqa xmm13, xmm6");
	asm("movdqa xmm14, xmm7");
	asm("pxor   xmm13, xmm14");
	asm("movdqa xmm8, xmm13");
	asm("mov    rcx, 2*3");
	asm("pxor   xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm13");
	asm("mov    rcx, 2*5");
	asm("pxor   xmm8, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm8");
	/* 2 - 1 */
	asm("movdqa xmm13, xmm2");
	asm("movdqa xmm14, xmm1");
	asm("pxor   xmm13, xmm14");
	asm("movdqa xmm8, xmm13");
	asm("mov    rcx, 2*4");
	asm("pxor   xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm13");
	asm("mov    rcx, 2*20");
	asm("pxor   xmm8, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm8");
	/* 0 - 3 */
	asm("movdqa xmm13, xmm0");
	asm("movdqa xmm14, xmm3");
	asm("pxor   xmm13, xmm14");
	asm("movdqa xmm8, xmm13");
	asm("movdqa xmm9, xmm13");
	asm("mov    rcx, 2*6");
	asm("pxor   xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm13");
	asm("mov    rcx, 2*11");
	asm("pxor   xmm8, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm8");
	asm("mov    rcx, 2*13");
	asm("pxor   xmm9, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm9");
	/* 6 - 1 */
	asm("movdqa xmm13, xmm6");
	asm("movdqa xmm14, xmm1");
	asm("pxor   xmm13, xmm14");
	asm("movdqa xmm8, xmm13");
	asm("mov    rcx, 2*8");
	asm("pxor   xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm13");
	asm("mov    rcx, 2*24");
	asm("pxor   xmm8, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm8");
	/* 2 - 7 */
	asm("movdqa xmm13, xmm2");
	asm("movdqa xmm14, xmm7");
	asm("pxor   xmm13, xmm14");
	asm("movdqa xmm8, xmm13");
	asm("movdqa xmm9, xmm13");
	asm("mov    rcx, 2*10");
	asm("pxor   xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm13");
	asm("mov    rcx, 2*15");
	asm("pxor   xmm8, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm8");
	asm("mov    rcx, 2*17");
	asm("pxor   xmm9, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm9");
	/* 4 - 1 */
	asm("movdqa xmm13, xmm4");
	asm("movdqa xmm14, xmm1");
	asm("pxor   xmm13, xmm14");
	asm("movdqa xmm8, xmm13");
	asm("mov    rcx, 2*12");
	asm("pxor   xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm13");
	asm("mov    rcx, 2*28");
	asm("pxor   xmm8, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm8");
	/* 6 - 5 */
	asm("movdqa xmm13, xmm6");
	asm("movdqa xmm14, xmm5");
	asm("pxor   xmm13, xmm14");
	asm("movdqa xmm8, xmm13");
	asm("movdqa xmm9, xmm13");
	asm("mov    rcx, 2*14");
	asm("pxor   xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm13");
	asm("mov    rcx, 2*19");
	asm("pxor   xmm8, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm8");
	asm("mov    rcx, 2*21");
	asm("pxor   xmm9, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm9");
	/* 0 - 1 */
	asm("movdqa xmm13, xmm0");
	asm("movdqa xmm14, xmm1");
	asm("pxor   xmm13, xmm14");
	asm("mov    rcx, 2*16");
	asm("pxor   xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm13");
	/* 4 - 3 */
	asm("movdqa xmm13, xmm4");
	asm("movdqa xmm14, xmm3");
	asm("pxor   xmm13, xmm14");
	asm("movdqa xmm8, xmm13");
	asm("movdqa xmm9, xmm13");
	asm("mov    rcx, 2*18");
	asm("pxor   xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm13");
	asm("mov    rcx, 2*23");
	asm("pxor   xmm8, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm8");
	asm("mov    rcx, 2*25");
	asm("pxor   xmm9, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm9");	
	/* 0 - 7 */
	asm("movdqa xmm13, xmm0");
	asm("movdqa xmm14, xmm7");
	asm("pxor   xmm13, xmm14");
	asm("movdqa xmm8, xmm13");
	asm("movdqa xmm9, xmm13");
	asm("mov    rcx, 2*22");
	asm("pxor   xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm13");
	asm("mov    rcx, 2*27");
	asm("pxor   xmm8, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm8");
	asm("mov    rcx, 2*29");
	asm("pxor   xmm9, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm9");
	/* 2 - 5 */
	asm("movdqa xmm13, xmm2");
	asm("movdqa xmm14, xmm5");
	asm("pxor   xmm13, xmm14");
	asm("movdqa xmm8, xmm13");
	asm("mov    rcx, 2*26");
	asm("pxor   xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm13");
	asm("mov    rcx, 2*31");
	asm("pxor   xmm8, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm8");
	/* 6 - 3 */
	asm("movdqa xmm13, xmm6");
	asm("movdqa xmm14, xmm3");
	asm("pxor   xmm13, xmm14");
	asm("mov    rcx, 2*30");
	asm("pxor   xmm13, ["tostr(PiccoloTcon128_)"+8*rcx-16]");
	asm("movdqa [rsi+8*rcx], xmm13");
#endif
	Pop_All_Regs();
	asm (".att_syntax noprefix");

	return;
}
#endif

#ifdef Piccolo80
/* Piccolo main encryption block: it supposes that the scheduled 
   keys are in memory pointed by the second argument */
__attribute__((noinline)) void Piccolo80vperm_core(const u8* message, const u8* subkeys, u8* ciphertext)
{ 	
	/*	Note : message is in rdi, subkeys in rsi and ciphertext in rdx 	*/
	/*	__cdecl calling convention		                        */	
	asm (".intel_syntax noprefix");
	Push_All_Regs();
	/* Key Index */
	asm("xor "tostr(RoundCounter_)", "tostr(RoundCounter_)"");
	/* Load constants (SBoxes, multiplications ...) */
	asm("movdqa  "tostr(PiccoloSBoxL_)", [rip + PiccoloSBoxL]");
	asm("movdqa  "tostr(PiccoloSBoxH_)", [rip + PiccoloSBoxH]");
	asm("movdqa  "tostr(TwoMulPiccoloSBoxL_)", [rip + TwoMulPiccoloSBoxL]");
	asm("movdqa  "tostr(ThreeMulPiccoloSBoxL_)", [rip + ThreeMulPiccoloSBoxL]");
	asm("movdqa  "tostr(PiccoloThreeShuf_)", [rip + PiccoloThreeShuf]");
	asm("movdqa  "tostr(PiccoloOneShufa_)", [rip + PiccoloOneShufa]");
	asm("movdqa  "tostr(PiccoloOneShufb_)", [rip + PiccoloOneShufb]");

	/* Load the masks */
	asm("movdqa  "tostr(PiccoloAndMaskL_)", [rip + PiccoloAndMaskL]");

	/* Load Piccolo's Round Permutation PiccoloRP */
	asm("movdqa  "tostr(PiccoloRP_)", [rip + PiccoloRP]");

	/* Scheduled keys from [rsi] and above */
	/* Load the messages and format them */
	format_input(Plaintext_, Plaintext_+8, State_, Tmp1_, Tmp2_, Tmp3_);

	/* Pre Whitening AddRoundKey */
	asm("pxor "tostr(State_)", ["tostr(Keys_)"+"tostr(RoundCounter_)"]");
	asm("add     "tostr(RoundCounter_)", 16");

	PiccoloROUND();
	PiccoloROUND();
	PiccoloROUND();
	PiccoloROUND();
	PiccoloROUND();

	PiccoloROUND();
	PiccoloROUND();
	PiccoloROUND();
	PiccoloROUND();
	PiccoloROUND();

	PiccoloROUND();
	PiccoloROUND();
	PiccoloROUND();
	PiccoloROUND();
	PiccoloROUND();

	PiccoloROUND();
	PiccoloROUND();
	PiccoloROUND();
	PiccoloROUND();
	PiccoloROUND();

	PiccoloROUND();
	PiccoloROUND();
	PiccoloROUND();
	PiccoloROUND();
	PiccoloLASTROUND();

	/* Post Whitening AddRoundKey */
	asm("pxor "tostr(State_)", ["tostr(Keys_)"+"tostr(RoundCounter_)"]");

	/* Move back the result in the input message, formatted */
	format_output(Ciphertext_, State_, Tmp1_, Tmp2_, Tmp3_);

	Pop_All_Regs();
	asm (".att_syntax noprefix");

	return;
}
/* Piccolo80: two plaintexts and two keys as input  */
void Piccolo80vperm_cipher(const u64 plaintext_in[VPERM_P], const u16 keys_in[VPERM_P][KEY80], u64 ciphertext_out[VPERM_P]){
        /* Key schedule: subkeys are of size 2*264 bytes */
        __attribute__ ((aligned (16))) u8 subkeys[VPERM_P * Piccolo80_SUBKEYS_SIZE];
        /* 128-bit aligned buffers for xmm memory load   */
        __attribute__ ((aligned (16))) u8 keys[VPERM_P * KEY80 * sizeof(u16)];
        __attribute__ ((aligned (16))) u8 plaintext[VPERM_P * sizeof(u64)];
        __attribute__ ((aligned (16))) u8 ciphertext[VPERM_P * sizeof(u64)];

        /* Copy the input to the aligned buffers */
        memcpy(plaintext, plaintext_in, sizeof(plaintext));
        memcpy(keys, keys_in, sizeof(keys));

#ifdef AVX
        /* Be sure to never enter the 'C' state when mixing VEX and non-VEX code 
         * (see http://www.agner.org/optimize/microarchitecture.pdf, 9.12)
         */
        asm("vzeroupper");
#endif

#ifdef MEASURE_PERF
	key_schedule_start = rdtsc();
#endif
        /* Compute the subkeys */
        Piccolo80vperm_key_schedule(keys, subkeys);
#ifdef MEASURE_PERF
	key_schedule_end = rdtsc();
#endif

#ifdef MEASURE_PERF
	encrypt_start = rdtsc();
#endif
        /* Call the core encryption */
        Piccolo80vperm_core(plaintext, subkeys, ciphertext);
#ifdef MEASURE_PERF
	encrypt_end = rdtsc();
#endif

       /* Copy back the result */
        memcpy(ciphertext_out, ciphertext, sizeof(ciphertext));

        return;
}
#endif

#ifdef Piccolo128
/* Piccolo main encryption block: it supposes that the scheduled 
   keys are in memory pointed by the second argument 	*/
__attribute__((noinline)) void Piccolo128vperm_core(const u8* message, const u8* subkeys, u8* ciphertext)
{ 	
        /*      Note : message is in rdi, subkeys in rsi and ciphertext in rdx  */
        /*      __cdecl calling convention                                      */
	asm (".intel_syntax noprefix");
	Push_All_Regs();
	/* Key Index */
	asm("xor "tostr(RoundCounter_)", "tostr(RoundCounter_)"");
	/* Load constants (SBoxes, multiplications ...) */
	asm("movdqa  "tostr(PiccoloSBoxL_)", [rip + PiccoloSBoxL]");
	asm("movdqa  "tostr(PiccoloSBoxH_)", [rip + PiccoloSBoxH]");
	asm("movdqa  "tostr(TwoMulPiccoloSBoxL_)", [rip + TwoMulPiccoloSBoxL]");
	asm("movdqa  "tostr(ThreeMulPiccoloSBoxL_)", [rip + ThreeMulPiccoloSBoxL]");
	asm("movdqa  "tostr(PiccoloThreeShuf_)", [rip + PiccoloThreeShuf]");
	asm("movdqa  "tostr(PiccoloOneShufa_)", [rip + PiccoloOneShufa]");
	asm("movdqa  "tostr(PiccoloOneShufb_)", [rip + PiccoloOneShufb]");

	/* Load the masks */
	asm("movdqa  "tostr(PiccoloAndMaskL_)", [rip + PiccoloAndMaskL]");

	/* Load Piccolo's Round Permutation PiccoloRP */
	asm("movdqa  "tostr(PiccoloRP_)", [rip + PiccoloRP]");

	/* Scheduled keys from [rsi] and above */
	/* Load the messages and format them */
	format_input(Plaintext_, Plaintext_+8, State_, Tmp1_, Tmp2_, Tmp3_);

	/* Pre Whitening AddRoundKey */
	asm("pxor "tostr(State_)", ["tostr(Keys_)"+"tostr(RoundCounter_)"]");
	asm("add     "tostr(RoundCounter_)", 16");

	PiccoloROUND();
	PiccoloROUND();
	PiccoloROUND();
	PiccoloROUND();
	PiccoloROUND();

	PiccoloROUND();
	PiccoloROUND();
	PiccoloROUND();
	PiccoloROUND();
	PiccoloROUND();

	PiccoloROUND();
	PiccoloROUND();
	PiccoloROUND();
	PiccoloROUND();
	PiccoloROUND();

	PiccoloROUND();
	PiccoloROUND();
	PiccoloROUND();
	PiccoloROUND();
	PiccoloROUND();

	PiccoloROUND();
	PiccoloROUND();
	PiccoloROUND();
	PiccoloROUND();
	PiccoloROUND();

	PiccoloROUND();
	PiccoloROUND();
	PiccoloROUND();
	PiccoloROUND();
	PiccoloROUND();
	PiccoloLASTROUND();

	/* Post Whitening AddRoundKey */
	asm("pxor "tostr(State_)", ["tostr(Keys_)"+"tostr(RoundCounter_)"]");

	/* Move back the result in the input message, formatted */
	format_output(Ciphertext_, State_, Tmp1_, Tmp2_, Tmp3_);

	Pop_All_Regs();
	asm (".att_syntax noprefix");

	return;
}

/* Piccolo128 vperm: two plaintexts and two keys as input  */
void Piccolo128vperm_cipher(const u64 plaintext_in[VPERM_P], const u16 keys_in[VPERM_P][KEY128], u64 ciphertext_out[VPERM_P]){
	/* Key schedule: subkeys are of size 2*264 bytes */
	__attribute__ ((aligned (16))) u8 subkeys[VPERM_P * Piccolo128_SUBKEYS_SIZE];
        /* 128-bit aligned buffers for xmm memory load 	 */
	__attribute__ ((aligned (16))) u8 keys[VPERM_P * KEY128 * sizeof(u16)];
	__attribute__ ((aligned (16))) u8 plaintext[VPERM_P * sizeof(u64)];
	__attribute__ ((aligned (16))) u8 ciphertext[VPERM_P * sizeof(u64)];

	/* Copy the input to the aligned buffers */
	memcpy(plaintext, plaintext_in, sizeof(plaintext));
	memcpy(keys, keys_in, sizeof(keys));

#ifdef AVX
        /* Be sure to never enter the 'C' state when mixing VEX and non-VEX code 
         * (see http://www.agner.org/optimize/microarchitecture.pdf, 9.12)
         */
        asm("vzeroupper");
#endif

#ifdef MEASURE_PERF
        key_schedule_start = rdtsc();
#endif
	/* Compute the subkeys */
	Piccolo128vperm_key_schedule(keys, subkeys);
#ifdef MEASURE_PERF
        key_schedule_end = rdtsc();
#endif

#ifdef MEASURE_PERF
        encrypt_start = rdtsc();
#endif
	/* Call the core encryption */
	Piccolo128vperm_core(plaintext, subkeys, ciphertext);
#ifdef MEASURE_PERF
        encrypt_end = rdtsc();
#endif

	/* Copy back the result */
        memcpy(ciphertext_out, ciphertext, sizeof(ciphertext));

	return;
}
#endif

/* Reactivate arguments related warnings */
#if GCC_VERSION > 40600
#pragma GCC diagnostic pop
#endif

#endif
