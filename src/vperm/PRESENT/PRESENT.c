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
#ifdef PRESENT80
__attribute__((noinline)) void PRESENT80vperm_key_schedule(const u8* masterKey, u8* roundKeys);
__attribute__((noinline)) void PRESENT80vperm_core(const u8* message, const u8* subkeys, u8* ciphertext);
void PRESENT80vperm_cipher(const u64 plaintext_in[VPERM_P], const u16 keys_in[VPERM_P][KEY80], u64 ciphertext_out[VPERM_P]);
#endif
#ifdef PRESENT128
__attribute__((noinline)) void PRESENT128vperm_key_schedule(const u8* masterKey, u8* roundKeys);
__attribute__((noinline)) void PRESENT128vperm_core(const u8* message, const u8* subkeys, u8* ciphertext);
void PRESENT128vperm_cipher(const u64 plaintext_in[VPERM_P], const u16 keys_in[VPERM_P][KEY128], u64 ciphertext_out[VPERM_P]);
#endif
#endif

/* Desactivate arguments related warnings */
#if GCC_VERSION > 40600
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif

/* PRESENT SBox (high and low nibbles) */ 
__attribute__((visibility("hidden"),aligned(16))) u8 PRESENTSBoxL[] = {0x0c, 0x05, 0x06, 0x0b, 0x09, 0x00, 0x0a, 0x0d, 0x03, 0x0e, 0x0f, 0x08, 0x04, 0x07, 0x01, 0x02};
__attribute__((visibility("hidden"),aligned(16))) u8 PRESENTSBoxH[] = {0xc0, 0x50, 0x60, 0xb0, 0x90, 0x00, 0xa0, 0xd0, 0x30, 0xe0, 0xf0, 0x80, 0x40, 0x70, 0x10, 0x20};

__attribute__((visibility("hidden"),aligned(16))) u8 PRESENTAndMaskL[] = {0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f};
__attribute__((visibility("hidden"),aligned(16))) u8 PRESENTAndMaskH[] = {0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0};

__attribute__((visibility("hidden"),aligned(16))) u8 PRESENTPlayerShuf[] = {0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15};

__attribute__((visibility("hidden"),aligned(16))) u8 PRESENTPlayerMask1[] = {0xaa, 0x00, 0xaa, 0x00, 0xaa, 0x00, 0xaa, 0x00, 0xaa, 0x00, 0xaa, 0x00, 0xaa, 0x00, 0xaa, 0x00};
__attribute__((visibility("hidden"),aligned(16))) u8 PRESENTPlayerMask2[] = {0xcc, 0xcc, 0x00, 0x00, 0xcc, 0xcc, 0x00, 0x00, 0xcc, 0xcc, 0x00, 0x00, 0xcc, 0xcc, 0x00, 0x00};

/* Input transform shuffle */
__attribute__((visibility("hidden"),aligned(16))) u8 PRESENTInShuffleEven[] = {0, 0xff, 1, 0xff, 2, 0xff, 3, 0xff, 4, 0xff, 5, 0xff, 6, 0xff, 7, 0xff};
__attribute__((visibility("hidden"),aligned(16))) u8 PRESENTInShuffleOdd[]  = {0xff, 0, 0xff, 1, 0xff, 2, 0xff, 3, 0xff, 4, 0xff, 5, 0xff, 6, 0xff, 7};

/* Output transform shuffle */
__attribute__((visibility("hidden"),aligned(16))) u8 PRESENTOutShuffleEven[] = {14, 12, 10, 8, 6, 4, 2, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
__attribute__((visibility("hidden"),aligned(16))) u8 PRESENTOutShuffleOdd[]  = {15, 13, 11, 9, 7, 5, 3, 1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

#ifdef PRESENT80
/* Round counter constant for the key schedule */ 
__attribute__((visibility("hidden"),aligned(16))) u8 PRESENTRCounter80[] = {0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00};
#endif

#ifdef PRESENT128
/* Round counter constant for the key schedule */ 
__attribute__((visibility("hidden"),aligned(16))) u8 PRESENTRCounter128[] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
#endif

/* gp register allocation */
#define Plaintext_		rdi
#define Ciphertext_		rdx
#define Keys_	 		rsi
#define RoundCounter_		rcx
#define PRESENTRCounter80_	rax
#define PRESENTRCounter128_	rbx
/* xmm register allocation */
#define PRESENTSBoxL_	 	xmm0
#define PRESENTSBoxH_	 	xmm1
#define PRESENTAndMaskL_  	xmm2
#define PRESENTAndMaskH_  	xmm3
#define PRESENTPlayerShuf_ 	xmm4
#define PRESENTPlayerMask1_	xmm5
#define PRESENTPlayerMask2_	xmm6
#define State_			xmm7
#define Tmp1_			xmm8
#define Tmp2_			xmm9
#define Tmp3_			xmm10
#define Tmp4_			xmm11
#define Tmp5_			xmm12
#define Tmp6_			xmm13
#define Tmp7_			xmm14
#define Tmp8_			xmm15

#ifdef AVX
  #define PRESENTROUND PRESENTROUND_AVX
  #define bit_permute_step32 bit_permute_step32_AVX
  #define format_input format_input_AVX
  #define format_output format_output_AVX
#else
  #define PRESENTROUND PRESENTROUND_SSSE
  #define bit_permute_step32 bit_permute_step32_SSSE
  #define format_input format_input_SSSE
  #define format_output format_output_SSSE
#endif

/* ---------------------------------------------------------*/
/* ---------------------- SSSE -----------------------------*/
/* ---------------------------------------------------------*/
/* The format message primitive */
/* Interleaves nibbles of 16 bytes pointed register */
#define format_input_SSSE(in0, in1, xmmout, tmp1, tmp2, tmp3) do {\
	/* Mov the two quadwords in temp registers */\
	asm("mov    rax, ["tostr(in0)"]");\
	asm("mov    rbx, ["tostr(in1)"]");\
	asm("bswap  rax");\
	asm("bswap  rbx");\
	asm("movq    "tostr(tmp1)", rax");\
	asm("movq    "tostr(tmp2)", rbx");\
	asm("movq    "tostr(xmmout)", "tostr(tmp1)"");\
	asm("movq    "tostr(tmp3)", "tostr(tmp2)"");\
	/* Keep the low parts */\
	asm("pand    "tostr(tmp1)", [rip + "tostr(PRESENTAndMaskL)"]");\
	asm("pand    "tostr(tmp2)", [rip + "tostr(PRESENTAndMaskL)"]");\
	/* Keep the high parts */\
	asm("pand    "tostr(xmmout)", [rip + "tostr(PRESENTAndMaskH)"]");\
	asm("pand    "tostr(tmp3)", [rip + "tostr(PRESENTAndMaskH)"]");\
	/* Shift the elements. Word1 high is put low, Word2 low is put high */\
	asm("psrlq   "tostr(xmmout)", 4");\
	asm("psllq   "tostr(tmp2)", 4");\
	/* Shuffle */\
	asm("pshufb  "tostr(tmp1)", [rip + "tostr(PRESENTInShuffleEven)"]");\
	asm("pshufb  "tostr(tmp2)", [rip + "tostr(PRESENTInShuffleEven)"]");\
	asm("pshufb  "tostr(xmmout)", [rip + "tostr(PRESENTInShuffleOdd)"]");\
	asm("pshufb  "tostr(tmp3)", [rip + "tostr(PRESENTInShuffleOdd)"]");\
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
	asm("pshufb  "tostr(tmp1)", [rip + "tostr(PRESENTOutShuffleEven)"]");\
	asm("pshufb  "tostr(tmp2)", [rip + "tostr(PRESENTOutShuffleOdd)"]");\
	asm("movdqa  "tostr(tmp3)", "tostr(tmp1)"");\
	asm("movdqa  "tostr(xmmin)", "tostr(tmp2)"");\
	/* Shift and mask for Word1 */\
	asm("pand    "tostr(tmp1)", [rip + "tostr(PRESENTAndMaskL)"]");\
	asm("pand    "tostr(tmp2)", [rip + "tostr(PRESENTAndMaskL)"]");\
	asm("psllq   "tostr(tmp2)", 4");\
	asm("pxor   "tostr(tmp1)", "tostr(tmp2)"");\
	/* Shift and mask for Word2 */\
	asm("pand    "tostr(tmp3)", [rip + "tostr(PRESENTAndMaskH)"]");\
	asm("pand    "tostr(xmmin)", [rip + "tostr(PRESENTAndMaskH)"]");\
	asm("psrlq   "tostr(tmp3)", 4");\
	asm("pxor    "tostr(tmp3)", "tostr(xmmin)"");\
	/* Save Word1 to memory */\
	asm("movq    ["tostr(out)"], "tostr(tmp1)"");\
	/* Merge the two Words */\
	asm("movq    ["tostr(out)"+8], "tostr(tmp3)"");\
} while(0);


/* The bit_permute_step primitive */
/* SSSE primitive */
#define bit_permute_step32_SSSE(in, out, mask, shift, tmp1) do {\
	asm("movdqa "tostr(tmp1)", "tostr(in)"");\
	asm("psrld  "tostr(tmp1)", "tostr(shift)"");\
	asm("pxor   "tostr(tmp1)", "tostr(in)"");\
	asm("pand   "tostr(tmp1)", "tostr(mask)"");\
	asm("movdqa "tostr(out)",  "tostr(tmp1)"");\
	asm("pslld  "tostr(out)",  "tostr(shift)"");\
	asm("pxor   "tostr(tmp1)", "tostr(in)"");\
	asm("pxor   "tostr(out)",  "tostr(tmp1)"");\
} while(0);

/* PRESENT round - SSSE version */
#define PRESENTROUND_SSSE() do {\
	/* AddRoundKey  -----------------*/\
	asm("pxor "tostr(State_)", ["tostr(Keys_)"+"tostr(RoundCounter_)"]");\
	asm("add  "tostr(RoundCounter_)", 16");\
	/* Save the state */\
	asm("movdqa "tostr(Tmp1_)", "tostr(State_)"");\
	/* SBox layer ------------------ */\
	/* Low nibbles SBox */\
	asm("movdqa "tostr(Tmp3_)", "tostr(PRESENTSBoxL_)"");\
	asm("pand   "tostr(Tmp1_)", "tostr(PRESENTAndMaskL_)"");\
	asm("pshufb "tostr(Tmp3_)", "tostr(Tmp1_)"");\
	/* High nibbles SBox */\
	asm("movdqa "tostr(Tmp4_)", "tostr(PRESENTSBoxH_)"");\
	asm("psrlw  "tostr(State_)", 4");\
	asm("pand   "tostr(State_)", "tostr(PRESENTAndMaskL_)"");\
	asm("pshufb "tostr(Tmp4_)", "tostr(State_)"");\
	/* Merge the two results*/\
	asm("pxor   "tostr(Tmp3_)", "tostr(Tmp4_)"");\
	/* PLayer ---------------------- */\
	/* Bit permutation inside words */\
	/* x = bit_permute_step(x, 0x00aa00aa, 7); Bit index swap 0,3 */\
	bit_permute_step32(Tmp3_, Tmp5_, PRESENTPlayerMask1_, 7, Tmp6_);\
	\
	/* x = bit_permute_step(x, 0x0000cccc, 14); Bit index swap 1,4 */\
	bit_permute_step32(Tmp5_, State_, PRESENTPlayerMask2_, 14, Tmp6_);\
	/* Byte shuffling to complete the PLayer step */\
	asm("pshufb "tostr(State_)", "tostr(PRESENTPlayerShuf_)"");\
\
} while(0);

/* ---------------------------------------------------------*/
/* ---------------------- AVX ------------------------------*/
/* ---------------------------------------------------------*/
/* The format message primitive */
/* Interleaves nibbles of 16 bytes pointed register */
#define format_input_AVX(in0, in1, xmmout, tmp1, tmp2, tmp3) do {\
	/* Mov the two quadwords in temp registers */\
	asm("mov    rax, ["tostr(in0)"]");\
	asm("mov    rbx, ["tostr(in1)"]");\
	asm("bswap  rax");\
	asm("bswap  rbx");\
	asm("movq    "tostr(tmp1)", rax");\
	asm("movq    "tostr(tmp2)", rbx");\
	/* Keep the high parts */\
	asm("vpand    "tostr(xmmout)", "tostr(tmp1)", [rip + "tostr(PRESENTAndMaskH)"]");\
	asm("vpand    "tostr(tmp3)", "tostr(tmp2)", [rip + "tostr(PRESENTAndMaskH)"]");\
	/* Keep the low parts */\
	asm("vpand    "tostr(tmp1)", "tostr(tmp1)", [rip + "tostr(PRESENTAndMaskL)"]");\
	asm("vpand    "tostr(tmp2)", "tostr(tmp2)", [rip + "tostr(PRESENTAndMaskL)"]");\
	/* Shift the elements. Word1 high is put low, Word2 low is put high */\
	asm("psrlq   "tostr(xmmout)", 4");\
	asm("psllq   "tostr(tmp2)", 4");\
	/* Shuffle */\
	asm("pshufb  "tostr(tmp1)", [rip + "tostr(PRESENTInShuffleEven)"]");\
	asm("pshufb  "tostr(tmp2)", [rip + "tostr(PRESENTInShuffleEven)"]");\
	asm("pshufb  "tostr(xmmout)", [rip + "tostr(PRESENTInShuffleOdd)"]");\
	asm("pshufb  "tostr(tmp3)", [rip + "tostr(PRESENTInShuffleOdd)"]");\
	/* Merge */\
	asm("pxor   "tostr(xmmout)", "tostr(tmp1)"");\
	asm("pxor   "tostr(xmmout)", "tostr(tmp2)"");\
	asm("pxor   "tostr(xmmout)", "tostr(tmp3)"");\
} while(0);

/* Interleaves nibbles from a xmm register to memory */
#define format_output_AVX(out, xmmin, tmp1, tmp2, tmp3) do {\
	/* Shuffle */\
	asm("vpshufb "tostr(tmp1)", "tostr(xmmin)", [rip + "tostr(PRESENTOutShuffleEven)"]");\
	asm("vpshufb "tostr(tmp2)", "tostr(xmmin)", [rip + "tostr(PRESENTOutShuffleOdd)"]");\
	asm("movdqa  "tostr(tmp3)", "tostr(tmp1)"");\
	asm("movdqa  "tostr(xmmin)", "tostr(tmp2)"");\
	/* Shift and mask for Word1 */\
	asm("pand    "tostr(tmp1)", [rip + "tostr(PRESENTAndMaskL)"]");\
	asm("pand    "tostr(tmp2)", [rip + "tostr(PRESENTAndMaskL)"]");\
	asm("psllq   "tostr(tmp2)", 4");\
	asm("pxor   "tostr(tmp1)", "tostr(tmp2)"");\
	/* Shift and mask for Word2 */\
	asm("pand    "tostr(tmp3)", [rip + "tostr(PRESENTAndMaskH)"]");\
	asm("pand    "tostr(xmmin)", [rip + "tostr(PRESENTAndMaskH)"]");\
	asm("psrlq   "tostr(tmp3)", 4");\
	asm("pxor    "tostr(tmp3)", "tostr(xmmin)"");\
	/* Save Word1 to memory */\
	asm("movq    ["tostr(out)"], "tostr(tmp1)"");\
	/* Merge the two Words */\
	asm("movq    ["tostr(out)"+8], "tostr(tmp3)"");\
} while(0);


/* The bit_permute_step primitive */
/* AVX primitive */
#define bit_permute_step32_AVX(in, out, mask, shift, tmp1) do {\
	asm("vpsrld  "tostr(tmp1)", "tostr(in)", "tostr(shift)"");\
	asm("pxor    "tostr(tmp1)", "tostr(in)"");\
	asm("pand    "tostr(tmp1)", "tostr(mask)"");\
	asm("vpslld  "tostr(out)",  "tostr(tmp1)", "tostr(shift)"");\
	asm("pxor    "tostr(tmp1)", "tostr(in)"");\
	asm("pxor    "tostr(out)",  "tostr(tmp1)"");\
} while(0);

/* PRESENT round - AVX version */
#define PRESENTROUND_AVX() do {\
	/* AddRoundKey  -----------------*/\
	asm("pxor "tostr(State_)", ["tostr(Keys_)"+"tostr(RoundCounter_)"]");\
	asm("add  "tostr(RoundCounter_)", 16");\
	/* Save the state */\
	/* SBox layer ------------------ */\
	/* Low nibbles SBox */\
	asm("vpand   "tostr(Tmp1_)", "tostr(State_)", "tostr(PRESENTAndMaskL_)"");\
	asm("vpshufb "tostr(Tmp3_)", "tostr(PRESENTSBoxL_)", "tostr(Tmp1_)"");\
	/* High nibbles SBox */\
	asm("vpsrlw  "tostr(Tmp2_)", "tostr(State_)", 4");\
	asm("pand    "tostr(Tmp2_)", "tostr(PRESENTAndMaskL_)"");\
	asm("vpshufb "tostr(Tmp4_)", "tostr(PRESENTSBoxH_)", "tostr(Tmp2_)"");\
	/* Merge the two results*/\
	asm("pxor   "tostr(Tmp3_)", "tostr(Tmp4_)"");\
	/* PLayer ---------------------- */\
	/* Bit permutation inside words */\
	/* x = bit_permute_step(x, 0x00aa00aa, 7); Bit index swap 0,3 */\
	bit_permute_step32(Tmp3_, Tmp5_, PRESENTPlayerMask1_, 7, Tmp6_);\
\
	/* x = bit_permute_step(x, 0x0000cccc, 14); Bit index swp 1,4 */\
	bit_permute_step32(Tmp5_, State_, PRESENTPlayerMask2_, 14, Tmp6_);\
	/* Byte shuffling to complete the PLayer step */\
	asm("pshufb "tostr(State_)", "tostr(PRESENTPlayerShuf_)"");\
\
} while(0);

#define format_keys_SSSE(in0, in1, xmmout, tmp1, tmp2, tmp3) do {\
	/* Mov the two quadwords in temp registers */\
	asm("movq    "tostr(tmp1)", "tostr(in0)"");\
	asm("movq    "tostr(tmp2)", "tostr(in1)"");\
	asm("movq    "tostr(xmmout)", "tostr(tmp1)"");\
	asm("movq    "tostr(tmp3)", "tostr(tmp2)"");\
	/* Keep the low parts */\
	asm("pand    "tostr(tmp1)", [rip + "tostr(PRESENTAndMaskL)"]");\
	asm("pand    "tostr(tmp2)", [rip + "tostr(PRESENTAndMaskL)"]");\
	/* Keep the high parts */\
	asm("pand    "tostr(xmmout)", [rip + "tostr(PRESENTAndMaskH)"]");\
	asm("pand    "tostr(tmp3)", [rip + "tostr(PRESENTAndMaskH)"]");\
	/* Shift the elements. Word1 high is put low, Word2 low is put high */\
	asm("psrlq   "tostr(xmmout)", 4");\
	asm("psllq   "tostr(tmp2)", 4");\
	/* Shuffle */\
	asm("pshufb  "tostr(tmp1)", [rip + "tostr(PRESENTInShuffleEven)"]");\
	asm("pshufb  "tostr(tmp2)", [rip + "tostr(PRESENTInShuffleEven)"]");\
	asm("pshufb  "tostr(xmmout)", [rip + "tostr(PRESENTInShuffleOdd)"]");\
	asm("pshufb  "tostr(tmp3)", [rip + "tostr(PRESENTInShuffleOdd)"]");\
	/* Merge */\
	asm("pxor   "tostr(xmmout)", "tostr(tmp1)"");\
	asm("pxor   "tostr(xmmout)", "tostr(tmp2)"");\
	asm("pxor   "tostr(xmmout)", "tostr(tmp3)"");\
} while(0);
#define format_keys_AVX(in0, in1, xmmout, tmp1, tmp2, tmp3) do {\
	/* Mov the two quadwords in temp registers */\
	asm("movq    "tostr(tmp1)", "tostr(in0)"");\
	asm("movq    "tostr(tmp2)", "tostr(in1)"");\
	/* Keep the high parts */\
	asm("vpand    "tostr(xmmout)", "tostr(tmp1)", [rip + "tostr(PRESENTAndMaskH)"]");\
	asm("vpand    "tostr(tmp3)", "tostr(tmp2)", [rip + "tostr(PRESENTAndMaskH)"]");\
	/* Keep the low parts */\
	asm("vpand    "tostr(tmp1)", "tostr(tmp1)", [rip + "tostr(PRESENTAndMaskL)"]");\
	asm("vpand    "tostr(tmp2)", "tostr(tmp2)", [rip + "tostr(PRESENTAndMaskL)"]");\
	/* Shift the elements. Word1 high is put low, Word2 low is put high */\
	asm("psrlq   "tostr(xmmout)", 4");\
	asm("psllq   "tostr(tmp2)", 4");\
	/* Shuffle */\
	asm("pshufb  "tostr(tmp1)", [rip + "tostr(PRESENTInShuffleEven)"]");\
	asm("pshufb  "tostr(tmp2)", [rip + "tostr(PRESENTInShuffleEven)"]");\
	asm("pshufb  "tostr(xmmout)", [rip + "tostr(PRESENTInShuffleOdd)"]");\
	asm("pshufb  "tostr(tmp3)", [rip + "tostr(PRESENTInShuffleOdd)"]");\
	/* Merge */\
	asm("pxor   "tostr(xmmout)", "tostr(tmp1)"");\
	asm("pxor   "tostr(xmmout)", "tostr(tmp2)"");\
	asm("pxor   "tostr(xmmout)", "tostr(tmp3)"");\
} while(0);
#ifdef AVX
  #define format_keys format_keys_AVX
#else
  #define format_keys format_keys_SSSE
#endif

#ifdef PRESENT80
__attribute__((visibility("hidden"),aligned(16))) u8 PRESENTKSSBMask1_80[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0};
__attribute__((visibility("hidden"),aligned(16))) u8 PRESENTKSSBMask2_80[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f};
__attribute__((visibility("hidden"),aligned(16))) u8 KSMaskLow_80[] = {0xff, 0x0ff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};


#define ROTR_XMM_SSSE80(low, high, tmph, tmpl, Mask) do{\
	/* Save stuff */\
	asm("movdqa  "tostr(tmph)", "tostr(high)"");\
	asm("movdqa  "tostr(tmpl)", "tostr(low)"");\
	/* Low -------*/\
	/* Shift high right by 3 to get the low part of new low */\
	asm("movdqa  "tostr(low)", "tostr(high)"");\
	asm("psrlq   "tostr(low)", 3");\
	/* Remove unused part of low */\
	asm("pand    "tostr(low)", "tostr(Mask)"");\
	/* High -------*/\
	/* Shift high right by 19 to get the low part of new high */\
	asm("psrlq   "tostr(high)", 19");\
	/* Shift low left by 45 to get the first high part of new high */\
	asm("psllq   "tostr(tmpl)", 45");\
	/* Shift high left by 61 to get the second high part of new high */\
	asm("psllq   "tostr(tmph)", 61");\
	/* Merge */\
	asm("pxor    "tostr(high)", "tostr(tmpl)"");\
	asm("pxor    "tostr(high)", "tostr(tmph)"");\
} while(0);

#define ROTR_XMM_AVX80(low, high, tmph, tmpl, Mask) do{\
	/* Save stuff */\
	/* High -------*/\
	/* Shift low left by 45 to get the first high part of new high */\
	asm("vpsllq  "tostr(tmpl)", "tostr(low)", 45");\
	/* Shift high left by 61 to get the second high part of new high */\
	asm("vpsllq  "tostr(tmph)", "tostr(high)", 61");\
	/* Low -------*/\
	/* Shift high right by 3 to get the low part of new low */\
	asm("vpsrlq  "tostr(low)", "tostr(high)", 3");\
	/* Remove unused part of low */\
	/* Shift high right by 19 to get the low part of new high */\
	asm("psrlq   "tostr(high)", 19");\
	asm("pand    "tostr(low)", "tostr(Mask)"");\
	/* Merge */\
	asm("pxor    "tostr(high)", "tostr(tmpl)"");\
	asm("pxor    "tostr(high)", "tostr(tmph)"");\
} while(0);


#define KSSBox_SSSE80(high, tmp1, tmp2, Mask1, Mask2, SBH) do {\
	asm("movdqa  "tostr(tmp1)", "tostr(high)"");\
	asm("movdqa  "tostr(tmp2)", "tostr(SBH)"");\
	asm("pand    "tostr(tmp1)", "tostr(Mask1)"");\
	asm("psrlq   "tostr(tmp1)", 4");\
	asm("pshufb  "tostr(tmp2)", "tostr(tmp1)"");\
	asm("pand    "tostr(high)", "tostr(Mask2)"");\
	asm("pand    "tostr(tmp2)", "tostr(Mask1)"");\
	asm("pxor    "tostr(high)", "tostr(tmp2)"");\
} while(0);

#define KSSBox_AVX80(high, tmp1, tmp2, Mask1, Mask2, SBH) do {\
	asm("vpand   "tostr(tmp1)", "tostr(high)", "tostr(Mask1)"");\
	asm("psrlq   "tostr(tmp1)", 4");\
	asm("vpshufb "tostr(tmp2)", "tostr(SBH)", "tostr(tmp1)"");\
	asm("pand    "tostr(high)", "tostr(Mask2)"");\
	asm("pand    "tostr(tmp2)", "tostr(Mask1)"");\
	asm("pxor    "tostr(high)", "tostr(tmp2)"");\
} while(0);


#define KEYSCHED_ROUND_SSSE80(low, high) do {\
	/* Xor high with counter */\
	asm("pxor "tostr(high)",  ["tostr(PRESENTRCounter80_)"+rcx-16]");\
	/* Rotate */\
 	ROTR_XMM80(low, high, xmm2, xmm3, xmm12);\
	/* Apply the SBox on high */\
	KSSBox80(high, xmm2, xmm3, xmm10, xmm11, xmm13);\
	/* Format the keys to store them */\
	asm("movdqa xmm4, "tostr(high)"");\
	asm("psrldq xmm4, 8");\
	/* We only keep the high parts */\
	format_keys(high, xmm4, xmm6, xmm7, xmm8, xmm9);\
	/* Store the key  */\
	asm("movdqa [rsi+rcx], xmm6");\
	asm("add rcx, 16");\
} while(0);

#define KEYSCHED_ROUND_AVX80(low, high) do {\
	/* Xor high with counter */\
	asm("pxor "tostr(high)",  ["tostr(PRESENTRCounter80_)"+rcx-16]");\
	/* Rotate */\
 	ROTR_XMM80(low, high, xmm2, xmm3, xmm12);\
	/* Apply the SBox on high */\
	KSSBox80(high, xmm2, xmm3, xmm10, xmm11, xmm13);\
	/* Format the keys to store them */\
	asm("vpsrldq xmm4, "tostr(high)", 8");\
	/* We only keep the high parts */\
	format_keys(high, xmm4, xmm6, xmm7, xmm8, xmm9);\
	/* Store the key  */\
	asm("movdqa [rsi+rcx], xmm6");\
	asm("add rcx, 16");\
} while(0);


#ifdef AVX
  #define ROTR_XMM80 ROTR_XMM_AVX80
  #define KSSBox80 KSSBox_AVX80
  #define KEYSCHED_ROUND80 KEYSCHED_ROUND_AVX80
#else
  #define ROTR_XMM80 ROTR_XMM_SSSE80
  #define KSSBox80 KSSBox_SSSE80
  #define KEYSCHED_ROUND80 KEYSCHED_ROUND_SSSE80
#endif

__attribute__((noinline)) void PRESENT80vperm_key_schedule(const u8* masterKey, u8* roundKeys)
{
        /*      Note : master key in rdi and round keys in rsi  */
        /*      __cdecl calling convention                      */
	asm (".intel_syntax noprefix");
	Push_All_Regs();
#ifdef AVX
	/* Return to clean non VEX state */
	asm("vzeroupper");
#endif
	/* Put the masks inside xmm to avoid memory usage */
	asm("movdqa xmm10, [rip + PRESENTKSSBMask1_80]");
	asm("movdqa xmm11, [rip + PRESENTKSSBMask2_80]");
	asm("movdqa xmm12, [rip + KSMaskLow_80]");
	asm("movdqa xmm13, [rip + PRESENTSBoxH]");
	
	asm("xor rcx, rcx");

	/* Handle endianness */
	asm("mov rax, [rdi]");
	asm("mov rbx, [rdi+2]");
	asm("bswap rax");
	asm("bswap rbx");
	asm("shr rax, 48");
	asm("mov [rdi], rbx");
	asm("mov [rdi+8], ax");

	asm("mov rax, [rdi+10]");
	asm("mov rbx, [rdi+10+2]");
	asm("bswap rax");
	asm("bswap rbx");
	asm("shr rax, 48");
	asm("mov [rdi+10], rbx");
	asm("mov [rdi+10+8], ax");

	asm("lea "tostr(PRESENTRCounter80_)", [rip + PRESENTRCounter80]");

	/* Key 0 */
	format_keys([rdi+2], [rdi+10+2], xmm4, xmm5, xmm6, xmm7);
	asm("movdqa [rsi+rcx], xmm4");
	asm("add rcx, 16");

	/* From now on, we format the two keys as follows */
	/* xmm1 = high1 | high0 */
	/* xmm0 = low1  | low0 */
	asm("movq    xmm0, [rdi]");
	asm("movq    xmm1, [rdi+2]");
	asm("movhps  xmm0, [rdi+10]");
	asm("movhps  xmm1, [rdi+10+2]");
	asm("pand    xmm0, xmm12");

	KEYSCHED_ROUND80(xmm0, xmm1);
	KEYSCHED_ROUND80(xmm0, xmm1);
	KEYSCHED_ROUND80(xmm0, xmm1);
	KEYSCHED_ROUND80(xmm0, xmm1);

	KEYSCHED_ROUND80(xmm0, xmm1);
	KEYSCHED_ROUND80(xmm0, xmm1);
	KEYSCHED_ROUND80(xmm0, xmm1);
	KEYSCHED_ROUND80(xmm0, xmm1);

	KEYSCHED_ROUND80(xmm0, xmm1);
	KEYSCHED_ROUND80(xmm0, xmm1);
	KEYSCHED_ROUND80(xmm0, xmm1);
	KEYSCHED_ROUND80(xmm0, xmm1);

	KEYSCHED_ROUND80(xmm0, xmm1);
	KEYSCHED_ROUND80(xmm0, xmm1);
	KEYSCHED_ROUND80(xmm0, xmm1);
	KEYSCHED_ROUND80(xmm0, xmm1);

	KEYSCHED_ROUND80(xmm0, xmm1);
	KEYSCHED_ROUND80(xmm0, xmm1);
	KEYSCHED_ROUND80(xmm0, xmm1);
	KEYSCHED_ROUND80(xmm0, xmm1);

	KEYSCHED_ROUND80(xmm0, xmm1);
	KEYSCHED_ROUND80(xmm0, xmm1);
	KEYSCHED_ROUND80(xmm0, xmm1);
	KEYSCHED_ROUND80(xmm0, xmm1);

	KEYSCHED_ROUND80(xmm0, xmm1);
	KEYSCHED_ROUND80(xmm0, xmm1);
	KEYSCHED_ROUND80(xmm0, xmm1);
	KEYSCHED_ROUND80(xmm0, xmm1);

	KEYSCHED_ROUND80(xmm0, xmm1);
	KEYSCHED_ROUND80(xmm0, xmm1);
	KEYSCHED_ROUND80(xmm0, xmm1);

	Pop_All_Regs();
	asm (".att_syntax noprefix");

	return;
}
#endif

#ifdef PRESENT128
__attribute__((visibility("hidden"),aligned(16))) u8 PRESENTKSSBMask1_128[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f};
__attribute__((visibility("hidden"),aligned(16))) u8 PRESENTKSSBMask2_128[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0};
__attribute__((visibility("hidden"),aligned(16))) u8 PRESENTKSSBMask3_128[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00};


#define ROTR_XMM_SSSE128(low, high, tmph, tmpl) do{\
	/* Save stuff */\
	asm("movdqa  "tostr(tmph)", "tostr(high)"");\
	asm("movdqa  "tostr(tmpl)", "tostr(low)"");\
	/* Shift high right by 3 to get the low part of new low */\
	asm("psrlq   "tostr(tmph)", 3");\
	/* Shift low left by 61 to get the high part of new low */\
	asm("psllq   "tostr(low)", 61");\
	/* Shift low right by 3 to get the low part of new high */\
	asm("psrlq   "tostr(tmpl)", 3");\
	/* Shift high left by 61 to get the low part of new high */\
	asm("psllq   "tostr(high)", 61");\
	/* Merge and get new high and new low */\
	asm("pxor    "tostr(low)", "tostr(tmph)"");\
	asm("pxor    "tostr(high)", "tostr(tmpl)"");\
} while(0);

#define ROTR_XMM_AVX128(low, high, tmph, tmpl) do{\
	/* Save stuff */\
	/* Shift high right by 3 to get the low part of new low */\
	asm("vpsrlq  "tostr(tmph)", "tostr(high)", 3");\
	/* Shift low right by 3 to get the low part of new high */\
	asm("vpsrlq  "tostr(tmpl)", "tostr(low)", 3");\
	/* Shift low left by 61 to get the high part of new low */\
	asm("psllq   "tostr(low)", 61");\
	/* Shift high left by 61 to get the low part of new high */\
	asm("psllq   "tostr(high)", 61");\
	/* Merge and get new high and new low */\
	asm("pxor    "tostr(low)", "tostr(tmph)"");\
	asm("pxor    "tostr(high)", "tostr(tmpl)"");\
} while(0);


#define KSSBox_SSSE128(high, tmp1, tmp2, tmp3, tmp4, Mask1, Mask2, Mask3, SBL, SBH) do {\
	asm("movdqa  "tostr(tmp1)", "tostr(high)"");\
	asm("movdqa  "tostr(tmp2)", "tostr(high)"");\
	asm("movdqa  "tostr(tmp3)", "tostr(SBL)"");\
	asm("movdqa  "tostr(tmp4)", "tostr(SBH)"");\
	asm("pand    "tostr(tmp1)", "tostr(Mask1)"");\
	asm("pand    "tostr(tmp2)", "tostr(Mask2)"");\
	asm("psrlq   "tostr(tmp2)", 4");\
	asm("pshufb  "tostr(tmp3)", "tostr(tmp1)"");\
	asm("pshufb  "tostr(tmp4)", "tostr(tmp2)"");\
	asm("pand    "tostr(high)", "tostr(Mask3)"");\
	asm("pand    "tostr(tmp3)", "tostr(Mask1)"");\
	asm("pand    "tostr(tmp4)", "tostr(Mask2)"");\
	asm("pxor    "tostr(high)", "tostr(tmp3)"");\
	asm("pxor    "tostr(high)", "tostr(tmp4)"");\
} while(0);

#define KSSBox_AVX128(high, tmp1, tmp2, tmp3, tmp4, Mask1, Mask2, Mask3, SBL, SBH) do {\
	asm("vpand   "tostr(tmp1)", "tostr(high)", "tostr(Mask1)"");\
	asm("vpand   "tostr(tmp2)", "tostr(high)", "tostr(Mask2)"");\
	asm("psrlq   "tostr(tmp2)", 4");\
	asm("vpshufb "tostr(tmp3)", "tostr(SBL)", "tostr(tmp1)"");\
	asm("vpshufb "tostr(tmp4)", "tostr(SBH)", "tostr(tmp2)"");\
	asm("pand    "tostr(high)", "tostr(Mask3)"");\
	asm("pand    "tostr(tmp3)", "tostr(Mask1)"");\
	asm("pand    "tostr(tmp4)", "tostr(Mask2)"");\
	asm("pxor    "tostr(high)", "tostr(tmp3)"");\
	asm("pxor    "tostr(high)", "tostr(tmp4)"");\
} while(0);

#define KEYSCHED_ROUND_SSSE128(low, high) do {\
	/* Xor high and low with counter */\
	asm("pxor "tostr(low)",  ["tostr(PRESENTRCounter128_)"+rcx-16]");\
	/* Rotate */\
 	ROTR_XMM128(low, high, xmm2, xmm3);\
	/* Apply the SBox on high */\
	KSSBox128(high, xmm2, xmm3, xmm4, xmm5, xmm10, xmm11, xmm12, xmm13, xmm14);\
	/* Format the keys to store them */\
	asm("movdqa xmm4, "tostr(high)"");\
	asm("psrldq xmm4, 8");\
	/* We only keep the high parts */\
	format_keys(high, xmm4, xmm6, xmm7, xmm8, xmm9);\
	/* Store the key  */\
	asm("movdqa [rsi+rcx], xmm6");\
	asm("add rcx, 16");\
} while(0);

#define KEYSCHED_ROUND_AVX128(low, high) do {\
	/* Xor high and low with counter */\
	asm("pxor "tostr(low)",  ["tostr(PRESENTRCounter128_)"+rcx-16]");\
	/* Rotate */\
 	ROTR_XMM128(low, high, xmm2, xmm3);\
	/* Apply the SBox on high */\
	KSSBox128(high, xmm2, xmm3, xmm4, xmm5, xmm10, xmm11, xmm12, xmm13, xmm14);\
	/* Format the keys to store them */\
	asm("vpsrldq xmm4, "tostr(high)", 8");\
	/* We only keep the high parts */\
	format_keys(high, xmm4, xmm6, xmm7, xmm8, xmm9);\
	/* Store the key  */\
	asm("movdqa [rsi+rcx], xmm6");\
	asm("add rcx, 16");\
} while(0);

#ifdef AVX
  #define ROTR_XMM128 ROTR_XMM_AVX128
  #define KSSBox128 KSSBox_AVX128
  #define KEYSCHED_ROUND128 KEYSCHED_ROUND_AVX128
#else
  #define ROTR_XMM128 ROTR_XMM_SSSE128
  #define KSSBox128 KSSBox_SSSE128
  #define KEYSCHED_ROUND128 KEYSCHED_ROUND_SSSE128
#endif


__attribute__((visibility("hidden"),aligned(16))) u8 PRESENT128KeyEndian[] = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};

__attribute__((noinline)) void PRESENT128vperm_key_schedule(const u8* masterKey, u8* roundKeys)
{
	asm (".intel_syntax noprefix");
	Push_All_Regs();

	/* Put the masks inside xmm to avoid memory usage */
	asm("movdqa xmm10, [rip + PRESENTKSSBMask1_128]");
	asm("movdqa xmm11, [rip + PRESENTKSSBMask2_128]");
	asm("movdqa xmm12, [rip + PRESENTKSSBMask3_128]");
	asm("movdqa xmm13, [rip + PRESENTSBoxL]");
	asm("movdqa xmm14, [rip + PRESENTSBoxH]");
	
	asm("xor rcx, rcx");

	/* Handle endianness */
	asm("movdqa xmm4, [rdi]");
	asm("movdqa xmm5, [rdi+16]");
	asm("pshufb xmm4, [rip + "tostr(PRESENT128KeyEndian)"]");
	asm("pshufb xmm5, [rip + "tostr(PRESENT128KeyEndian)"]");
	asm("movdqa [rdi], xmm4");
	asm("movdqa [rdi+16], xmm5");

	asm("lea "tostr(PRESENTRCounter128_)", [rip + PRESENTRCounter128]");

	/* Key 0 */
	format_keys([rdi+8], [rdi+16+8], xmm4, xmm5, xmm6, xmm7);
	asm("movdqa [rsi+rcx], xmm4");
	asm("add rcx, 16");

	/* From now on, we format the two keys as follows */
	/* xmm1 = high1 | high0 */
	/* xmm0 = low1  | low0 */
	asm("movq    xmm0, [rdi]");
	asm("movq    xmm1, [rdi+8]");
	asm("movhps  xmm0, [rdi+16]");
	asm("movhps  xmm1, [rdi+16+8]");

	KEYSCHED_ROUND128(xmm0, xmm1);
	KEYSCHED_ROUND128(xmm0, xmm1);
	KEYSCHED_ROUND128(xmm0, xmm1);
	KEYSCHED_ROUND128(xmm0, xmm1);

	KEYSCHED_ROUND128(xmm0, xmm1);
	KEYSCHED_ROUND128(xmm0, xmm1);
	KEYSCHED_ROUND128(xmm0, xmm1);
	KEYSCHED_ROUND128(xmm0, xmm1);

	KEYSCHED_ROUND128(xmm0, xmm1);
	KEYSCHED_ROUND128(xmm0, xmm1);
	KEYSCHED_ROUND128(xmm0, xmm1);
	KEYSCHED_ROUND128(xmm0, xmm1);

	KEYSCHED_ROUND128(xmm0, xmm1);
	KEYSCHED_ROUND128(xmm0, xmm1);
	KEYSCHED_ROUND128(xmm0, xmm1);
	KEYSCHED_ROUND128(xmm0, xmm1);

	KEYSCHED_ROUND128(xmm0, xmm1);
	KEYSCHED_ROUND128(xmm0, xmm1);
	KEYSCHED_ROUND128(xmm0, xmm1);
	KEYSCHED_ROUND128(xmm0, xmm1);

	KEYSCHED_ROUND128(xmm0, xmm1);
	KEYSCHED_ROUND128(xmm0, xmm1);
	KEYSCHED_ROUND128(xmm0, xmm1);
	KEYSCHED_ROUND128(xmm0, xmm1);

	KEYSCHED_ROUND128(xmm0, xmm1);
	KEYSCHED_ROUND128(xmm0, xmm1);
	KEYSCHED_ROUND128(xmm0, xmm1);
	KEYSCHED_ROUND128(xmm0, xmm1);

	KEYSCHED_ROUND128(xmm0, xmm1);
	KEYSCHED_ROUND128(xmm0, xmm1);
	KEYSCHED_ROUND128(xmm0, xmm1);

	Pop_All_Regs();
	asm (".att_syntax noprefix");\

	return;
}
#endif


#ifdef PRESENT80
/* PRESENT80 main encryption block: it supposes that the scheduled 
   keys are in memory pointed by the second argument */
__attribute__((noinline)) void PRESENT80vperm_core(const u8* message, const u8* subkeys, u8* ciphertext)
{ 	
        /*      Note : message is in rdi, subkeys in rsi and ciphertext in rdx  */
        /*      __cdecl calling convention                                      */
	asm (".intel_syntax noprefix");
	Push_All_Regs();

	/* Key Index */
	asm("xor "tostr(RoundCounter_)", "tostr(RoundCounter_)"");
	/* Load constants (SBoxes) */
	asm("movdqa  "tostr(PRESENTSBoxL_)", [rip + PRESENTSBoxL]");
	asm("movdqa  "tostr(PRESENTSBoxH_)", [rip + PRESENTSBoxH]");
	/* Load the the And mask */
	asm("movdqa  "tostr(PRESENTAndMaskL_)", [rip + PRESENTAndMaskL]");
	asm("movdqa  "tostr(PRESENTAndMaskH_)", [rip + PRESENTAndMaskH]");

	/* Load the the PLayer byte shuffle */
	asm("movdqa  "tostr(PRESENTPlayerShuf_)", [rip + PRESENTPlayerShuf]");

	/* Load the PLayer And masks */
	asm("movdqa "tostr(PRESENTPlayerMask1_)", [rip + PRESENTPlayerMask1]");
	asm("movdqa "tostr(PRESENTPlayerMask2_)", [rip + PRESENTPlayerMask2]");

	/* Scheduled keys from [rsi] and above */
	/* Load the messages and format them */
	format_input(Plaintext_, Plaintext_+8, State_, Tmp1_, Tmp2_, Tmp3_);

	PRESENTROUND();
	PRESENTROUND();
	PRESENTROUND();
	PRESENTROUND();

	PRESENTROUND();
	PRESENTROUND();
	PRESENTROUND();
	PRESENTROUND();

	PRESENTROUND();
	PRESENTROUND();
	PRESENTROUND();
	PRESENTROUND();

	PRESENTROUND();
	PRESENTROUND();
	PRESENTROUND();
	PRESENTROUND();

	PRESENTROUND();
	PRESENTROUND();
	PRESENTROUND();
	PRESENTROUND();

	PRESENTROUND();
	PRESENTROUND();
	PRESENTROUND();
	PRESENTROUND();

	PRESENTROUND();
	PRESENTROUND();
	PRESENTROUND();
	PRESENTROUND();

	PRESENTROUND();
	PRESENTROUND();
	PRESENTROUND();

	/* Last AddRoundKey */
	asm("pxor "tostr(State_)", ["tostr(Keys_)"+"tostr(RoundCounter_)"]");
	
	/* Move back the result in the input message */
	format_output(Ciphertext_, State_, Tmp1_, Tmp2_, Tmp3_);

	Pop_All_Regs();
	asm (".att_syntax noprefix");

	return;
}

/* PRESENT80: two plaintexts and two keys as input  */
void PRESENT80vperm_cipher(const u64 plaintext_in[VPERM_P], const u16 keys_in[VPERM_P][KEY80], u64 ciphertext_out[VPERM_P]){
        /* Key schedule: subkeys are of size 2*264 bytes */
        __attribute__ ((aligned (16))) u8 subkeys[VPERM_P * PRESENT80_SUBKEYS_SIZE];
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
        PRESENT80vperm_key_schedule(keys, subkeys);
#ifdef MEASURE_PERF
        key_schedule_end = rdtsc();
#endif

#ifdef MEASURE_PERF
        encrypt_start = rdtsc();
#endif
        /* Call the c(re encryption */
        PRESENT80vperm_core(plaintext, subkeys, ciphertext);
#ifdef MEASURE_PERF
        encrypt_end = rdtsc();
#endif

       /* Copy back the result */
        memcpy(ciphertext_out, ciphertext, sizeof(ciphertext));

        return;
}
#endif

#ifdef PRESENT128
/* PRESENT128 main encryption block: it supposes that the scheduled 
   keys are in memory pointed by the second argument */
__attribute__((noinline)) void PRESENT128vperm_core(const u8* message, const u8* subkeys, u8* ciphertext)
{ 
        /*      Note : message is in rdi, subkeys in rsi and ciphertext in rdx  */
        /*      __cdecl calling convention                                      */	
	asm (".intel_syntax noprefix");\
	Push_All_Regs();

	/* Key Index */
	asm("xor "tostr(RoundCounter_)", "tostr(RoundCounter_)"");
	/* Load constants (SBoxes) */
	asm("movdqa  "tostr(PRESENTSBoxL_)", [rip + PRESENTSBoxL]");
	asm("movdqa  "tostr(PRESENTSBoxH_)", [rip + PRESENTSBoxH]");
	/* Load the the And mask */
	asm("movdqa  "tostr(PRESENTAndMaskL_)", [rip + PRESENTAndMaskL]");
	asm("movdqa  "tostr(PRESENTAndMaskH_)", [rip + PRESENTAndMaskH]");

	/* Load the the PLayer byte shuffle */
	asm("movdqa  "tostr(PRESENTPlayerShuf_)", [rip + PRESENTPlayerShuf]");

	/* Load the PLayer And masks */
	asm("movdqa "tostr(PRESENTPlayerMask1_)", [rip + PRESENTPlayerMask1]");
	asm("movdqa "tostr(PRESENTPlayerMask2_)", [rip + PRESENTPlayerMask2]");

	/* Scheduled keys from [rsi] and above */
	/* Load the messages and format them */
	format_input(Plaintext_, Plaintext_+8, State_, Tmp1_, Tmp2_, Tmp3_);

	PRESENTROUND();
	PRESENTROUND();
	PRESENTROUND();
	PRESENTROUND();

	PRESENTROUND();
	PRESENTROUND();
	PRESENTROUND();
	PRESENTROUND();

	PRESENTROUND();
	PRESENTROUND();
	PRESENTROUND();
	PRESENTROUND();

	PRESENTROUND();
	PRESENTROUND();
	PRESENTROUND();
	PRESENTROUND();

	PRESENTROUND();
	PRESENTROUND();
	PRESENTROUND();
	PRESENTROUND();

	PRESENTROUND();
	PRESENTROUND();
	PRESENTROUND();
	PRESENTROUND();

	PRESENTROUND();
	PRESENTROUND();
	PRESENTROUND();
	PRESENTROUND();

	PRESENTROUND();
	PRESENTROUND();
	PRESENTROUND();

	/* Last AddRoundKey */
	asm("pxor "tostr(State_)", ["tostr(Keys_)"+"tostr(RoundCounter_)"]");

	/* Move back the result in the input message */
	format_output(Ciphertext_, State_, Tmp1_, Tmp2_, Tmp3_);

	Pop_All_Regs();
	asm (".att_syntax noprefix");\

	return;
}

/* PRESENT128: two plaintexts and two keys as input  */
void PRESENT128vperm_cipher(const u64 plaintext_in[VPERM_P], const u16 keys_in[VPERM_P][KEY128], u64 ciphertext_out[VPERM_P]){
        /* Key schedule: subkeys are of size 2*264 bytes */
        __attribute__ ((aligned (16))) u8 subkeys[VPERM_P * PRESENT128_SUBKEYS_SIZE];
        /* 128-bit aligned buffers for xmm memory load   */
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
        PRESENT128vperm_key_schedule(keys, subkeys);
#ifdef MEASURE_PERF
        key_schedule_end = rdtsc();
#endif

#ifdef MEASURE_PERF
        encrypt_start = rdtsc();
#endif
        /* Call the c(re encryption */
        PRESENT128vperm_core(plaintext, subkeys, ciphertext);
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
