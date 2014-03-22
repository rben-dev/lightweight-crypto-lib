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

    The current source code is part of the common functions and headers 
    source tree.

    Project: Lightweight cryptography library
    File:    src/common/bitslice_common.h

-------------------------- CeCILL-B HEADER ----------------------------------*/
word mask0, mask1, mask2, mask3, mask4, mask5, mask6, mask7, mask_odd, mask_oddh, mask_key1, mask_key2, mask128_key1, mask128_key2, mask128_and_b21, mask128_and_b22, mask512_key1, mask512_key2;
word mask_unpack8_l0, mask_unpack8_l1, mask_unpack8_h0, mask_unpack8_h1;
word mask_unpack16_l0,mask_unpack16_l1, mask_unpack16_h0, mask_unpack16_h1;
word mask_unpack64_l0,mask_unpack64_l1, mask_unpack64_h0, mask_unpack64_h1;
word mask_u, mask_l, mask88, mask44, mask22, mask11, mask_one;  /* masks for unpacking 4-bit nibbles */
word mask16_sr01, mask16_sr23;                              /* masks for shift rows */
word mask_byte_endian;
word mask_byte_endian64;
word mask_byte_endian80;

word mask_u64, mask_l64;

#define CONSTANT(b)     _mm_set1_epi8((b))          	    /* set each byte in a 128-bit register to be "b" */
#define SET		_mm_set_epi8			    /* set bytes of a 128-bit vector */
#define SET32		_mm_set_epi32			    /* set 32-bit words of a 128-bit vector */
#define XOR(x,y)        _mm_xor_si128((x),(y))      	    /* XOR(x,y) = x ^ y, where x and y are two 128-bit word */
#define AND(x,y)        _mm_and_si128((x),(y))      	    /* AND(x,y) = x & y, where x and y are two 128-bit word */
#define ANDNOT(x,y)     _mm_andnot_si128((x),(y))   	    /* ANDNOT(x,y) = (!x) & y, where x and y are two 128-bit word */
#define OR(x,y)         _mm_or_si128((x),(y))      	    /* OR(x,y)  = x | y, where x and y are two 128-bit word */
#define LOAD(p)         _mm_loadu_si128((word *)(p)) 	    /* load 16 bytes from the memory adress p, return a 128-bit word, where p is the multiple of 16 */
#define PSHUFB(x,y)     _mm_shuffle_epi8((x),(y))   	    /* x byte ordering is reordered according to value of b  */
#define PUNPCKHBW(x,y)  _mm_unpackhi_epi8((x),(y))  	    /* interleaves the higher 8 bytes of x and y */
#define PUNPCKLBW(x,y)  _mm_unpacklo_epi8((x),(y))  	    /* interleaves the lower 8 bytes of x and y */
#define PUNPCKHDQ(x,y)  _mm_unpackhi_epi32((x),(y)) 	    /* */
#define PUNPCKHQDQ(x,y) _mm_unpackhi_epi64((x),(y)) 	    /* */
#define PUNPCKLDQ(x,y)  _mm_unpacklo_epi32((x),(y)) 	    /* */
#define PUNPCKLQDQ(x,y) _mm_unpacklo_epi64((x),(y)) 	    /* */
#define PMOVMSKB(x)     _mm_movemask_epi8 ((x))     	    /* Creates a 16-bit mask made up of the most significant bit of each byte of the source */ 
							    /* operand and returns the result in the low 16-bit of the output 			    */
#define PSHIFTR(x,i)    _mm_srli_epi16((x),(i))    	    /* Shift right each 16-bit word of x by i positions */
#define PSHIFTL(x,i)    _mm_slli_epi16((x),(i))    	    /* Shift left each 16-bit word of x by i positions */
#define STORE(x,p)      _mm_storeu_si128((word *)(p), (x))  /* store the 128-bit register x back to memory addressed by p */
#define INTERLEAVEL16(x,y)  _mm_unpacklo_epi16((x), (y))    /* interleaves lower 16-bit nibbles */
#define INTERLEAVEH16(x,y)  _mm_unpackhi_epi16((x), (y))    /* interleaves higher 16-bit nibbles */
#define INTERLEAVEL32(x,y)  _mm_unpacklo_epi32((x), (y))    /* interleaves lower 32-bit nibbles */
#define INTERLEAVEH32(x,y)  _mm_unpackhi_epi32((x), (y))    /* interleaves higher 32-bit nibbles */
#define INTERLEAVEL64(x,y)  _mm_unpacklo_epi64((x), (y))    /* interleaves lower 64-bit nibbles */
#define INTERLEAVEH64(x,y)  _mm_unpackhi_epi64((x), (y))    /* interleaves higher 64-bit nibbles */

#define SHLB128(x,i)    _mm_slli_si128((x),(i))
#define SHRB128(x,i)    _mm_srli_si128((x),(i))

#define SHLQ64(x, i)	_mm_slli_epi64((x),(i))
#define SHRQ64(x, i)	_mm_srli_epi64((x),(i))

#define PSHUF32(x,y) 	_mm_shuffle_epi32((x),(y))

#define XOR_Key(r0, r1, r2, r3, key0, key1, key2, key3) do {\
	r0 = XOR(r0,key0);\
	r1 = XOR(r1,key1);\
	r2 = XOR(r2,key2);\
	r3 = XOR(r3,key3);\
} while(0);

#define Sbox(x3, x2, x1, x0, t) do {\
	x2 = XOR(x2, x1);		x3 = XOR(x3, x1);\
	t  = x2;			x2 = AND(x2, x3);\
	x1 = XOR(x1, x2);		t  = XOR(t , x0);\
	x2 = x1;		 	x1 = AND(x1, t);\
	x1 = XOR(x1, x3);		t  = XOR(t , x0);\
	t  = OR(t ,	x2);		x2 = XOR(x2, x0);\
	x2 = XOR(x2, x1);		t  = XOR(t , x3);\
	x2 = XOR(x2, mask_one);		x0 = XOR(x0, t);\
	x3 = x2;			x2 = AND(x2, x1);\
	x2 = XOR(x2, t);		x2 = XOR(x2, mask_one);\
} while(0);

#define packing8(r0, r1, r2, r3, t0, t1, w0, w1, w2, w3) do {\
	t1 = PSHIFTL(r0, 4);\
	t0 = PUNPCKLBW(t1, r0);\
	t1 = PUNPCKHBW(t1, r0);\
	\
	w0 = AND(        t0   , mask0);\
	w1 = AND(PSHIFTL(t0,1), mask0);\
	w2 = AND(PSHIFTL(t0,2), mask0);\
	w3 = AND(PSHIFTL(t0,3), mask0);\
	\
	w0 = XOR(w0, AND(PSHIFTR(t1, 1), mask1));\
	w1 = XOR(w1, AND(        t1    , mask1));\
	w2 = XOR(w2, AND(PSHIFTL(t1, 1), mask1));\
	w3 = XOR(w3, AND(PSHIFTL(t1, 2), mask1));\
	\
	t1 = PSHIFTL(r1, 4);\
	t0 = PUNPCKLBW(t1, r1);\
	t1 = PUNPCKHBW(t1, r1);\
	\
	w0 = XOR(w0, AND(PSHIFTR(t0, 2), mask2));\
	w1 = XOR(w1, AND(PSHIFTR(t0, 1), mask2));\
	w2 = XOR(w2, AND(        t0    , mask2));\
	w3 = XOR(w3, AND(PSHIFTL(t0, 1), mask2));\
	\
	w0 = XOR(w0, AND(PSHIFTR(t1, 3), mask3));\
	w1 = XOR(w1, AND(PSHIFTR(t1, 2), mask3));\
	w2 = XOR(w2, AND(PSHIFTR(t1, 1), mask3));\
	w3 = XOR(w3, AND(        t1    , mask3));\
	\
	t1 = PSHIFTL(r2, 4);\
	t0 = PUNPCKLBW(t1, r2);\
	t1 = PUNPCKHBW(t1, r2);\
	\
	w0 = XOR(w0, AND(PSHIFTR(t0, 4), mask4));\
	w1 = XOR(w1, AND(PSHIFTR(t0, 3), mask4));\
	w2 = XOR(w2, AND(PSHIFTR(t0, 2), mask4));\
	w3 = XOR(w3, AND(PSHIFTR(t0, 1), mask4));\
	\
	w0 = XOR(w0, AND(PSHIFTR(t1, 5), mask5));\
	w1 = XOR(w1, AND(PSHIFTR(t1, 4), mask5));\
	w2 = XOR(w2, AND(PSHIFTR(t1, 3), mask5));\
	w3 = XOR(w3, AND(PSHIFTR(t1, 2), mask5));\
	\
	t1 = PSHIFTL(r3, 4);\
	t0 = PUNPCKLBW(t1, r3);\
	t1 = PUNPCKHBW(t1, r3);\
	\
	w0 = XOR(w0, AND(PSHIFTR(t0, 6), mask6));\
	w1 = XOR(w1, AND(PSHIFTR(t0, 5), mask6));\
	w2 = XOR(w2, AND(PSHIFTR(t0, 4), mask6));\
	w3 = XOR(w3, AND(PSHIFTR(t0, 3), mask6));\
	\
	r0 = XOR(w0, AND(PSHIFTR(t1, 7), mask7));\
	r1 = XOR(w1, AND(PSHIFTR(t1, 6), mask7));\
	r2 = XOR(w2, AND(PSHIFTR(t1, 5), mask7));\
	r3 = XOR(w3, AND(PSHIFTR(t1, 4), mask7));\
} while(0);

#define unpacking8(r0,r1,r2,r3,r4,r5,r6,r7,t,in0,in1,in2,in3) do {\
	r0 = AND(in0, mask0);\
	t  = AND(in1, mask0);\
	t  = PSHIFTR(t , 1);\
	r0 = XOR(r0, t );\
	t  = AND(in2, mask0);\
	t  = PSHIFTR(t , 2);\
	r0 = XOR(r0, t );\
	t  = AND(in3, mask0);\
	t  = PSHIFTR(t , 3);\
	r0 = XOR(r0, t );\
	t  = PSHIFTL(r0, 4);\
	r0 = XOR(r0, t );\
	r0 = PSHUFB(r0, mask_odd);\
	\
	r1 = AND(in0, mask1);\
	r1 = PSHIFTL(r1, 1);\
	t  = AND(in1, mask1);\
	r1 = XOR(r1, t );\
	t  = AND(in2, mask1);\
	t  = PSHIFTR(t , 1);\
	r1 = XOR(r1, t );\
	t  = AND(in3, mask1);\
	t  = PSHIFTR(t , 2);\
	r1 = XOR(r1, t );\
	t  = PSHIFTL(r1, 4);\
	r1 = XOR(r1, t );\
	r1 = PSHUFB(r1, mask_oddh);\
	\
	r2 = AND(in0, mask2);\
	r2 = PSHIFTL(r2, 2);\
	t  = AND(in1, mask2);\
	t  = PSHIFTL(t , 1);\
	r2 = XOR(r2, t );\
	t  = AND(in2, mask2);\
	r2 = XOR(r2, t );\
	t  = AND(in3, mask2);\
	t  = PSHIFTR(t , 1);\
	r2 = XOR(r2, t );\
	t  = PSHIFTL(r2, 4);\
	r2 = XOR(r2, t );\
	r2 = PSHUFB(r2, mask_odd);\
	\
	r3 = AND(in0, mask3);\
	r3 = PSHIFTL(r3, 3);\
	t  = AND(in1, mask3);\
	t  = PSHIFTL(t , 2);\
	r3 = XOR(r3, t );\
	t  = AND(in2, mask3);\
	t  = PSHIFTL(t , 1);\
	r3 = XOR(r3, t );\
	t  = AND(in3, mask3);\
	r3 = XOR(r3, t );\
	t  = PSHIFTL(r3, 4);\
	r3 = XOR(r3, t );\
	r3 = PSHUFB(r3, mask_oddh);\
	\
	r4 = AND(in0, mask4);\
	r4 = PSHIFTL(r4, 4);\
	t  = AND(in1, mask4);\
	t  = PSHIFTL(t , 3);\
	r4 = XOR(r4, t );\
	t  = AND(in2, mask4);\
	t  = PSHIFTL(t , 2);\
	r4 = XOR(r4, t );\
	t  = AND(in3, mask4);\
	t  = PSHIFTL(t , 1);\
	r4 = XOR(r4, t );\
	t  = PSHIFTL(r4, 4);\
	r4 = XOR(r4, t );\
	r4 = PSHUFB(r4, mask_odd);\
	\
	r5 = AND(in0, mask5);\
	r5 = PSHIFTL(r5, 5);\
	t  = AND(in1, mask5);\
	t  = PSHIFTL(t , 4);\
	r5 = XOR(r5, t );\
	t  = AND(in2, mask5);\
	t  = PSHIFTL(t , 3);\
	r5 = XOR(r5, t );\
	t  = AND(in3, mask5);\
	t  = PSHIFTL(t , 2);\
	r5 = XOR(r5, t );\
	t  = PSHIFTL(r5, 4);\
	r5 = XOR(r5, t );\
	r5 = PSHUFB(r5, mask_oddh);\
	\
	r6 = AND(in0, mask6);\
	r6 = PSHIFTL(r6, 6);\
	t  = AND(in1, mask6);\
	t  = PSHIFTL(t , 5);\
	r6 = XOR(r6, t );\
	t  = AND(in2, mask6);\
	t  = PSHIFTL(t , 4);\
	r6 = XOR(r6, t );\
	t  = AND(in3, mask6);\
	t  = PSHIFTL(t , 3);\
	r6 = XOR(r6, t );\
	t  = PSHIFTL(r6, 4);\
	r6 = XOR(r6, t );\
	r6 = PSHUFB(r6, mask_odd);\
	\
	r7 = AND(in0, mask7);\
	r7 = PSHIFTL(r7, 7);\
	t  = AND(in1, mask7);\
	t  = PSHIFTL(t , 6);\
	r7 = XOR(r7, t );\
	t  = AND(in2, mask7);\
	t  = PSHIFTL(t , 5);\
	r7 = XOR(r7, t );\
	t  = AND(in3, mask7);\
	t  = PSHIFTL(t , 4);\
	r7 = XOR(r7, t );\
	t  = PSHIFTL(r7, 4);\
	r7 = XOR(r7, t );\
	r7 = PSHUFB(r7, mask_oddh);\
	r0 = XOR(r0, r1); r1 = XOR(r2, r3); r2=XOR(r4, r5); r3 = XOR(r6, r7);\
} while(0);

#define SWAP8(l, h, t0) do {\
	t0 = l;\
	l = PUNPCKLBW(l , h);\
	h = PUNPCKHBW(t0, h);\
	t0 = l; l = h; h = t0;\
} while(0);

#define uSWAP8(x, y, t0) do {\
	t0 = x;\
	x = XOR(PSHUFB(x , mask_unpack8_l0), PSHUFB(y, mask_unpack8_h0));\
	y = XOR(PSHUFB(t0, mask_unpack8_l1), PSHUFB(y, mask_unpack8_h1));\
	t0 = x; x = y; y = t0;\
} while(0);

#define SWAP16(x,y,t0) do {\
	t0 = x;\
	x = INTERLEAVEL16(x,y);\
	y = INTERLEAVEH16(t0,y);\
} while(0);

#define SWAP64(x,y,t0) do {\
	t0 = x;\
	x = INTERLEAVEL64(x,y);\
	y = INTERLEAVEH64(t0,y);\
} while(0);

#define uINTERLEAVE16(x, y, t0) do {\
	t0 = x;\
	x = XOR(PSHUFB(x , mask_unpack16_l0), PSHUFB(y, mask_unpack16_h0));\
	y = XOR(PSHUFB(t0, mask_unpack16_l1), PSHUFB(y, mask_unpack16_h1));\
} while(0);

#define uSWAP16(x,y, t0) uINTERLEAVE16(x, y, t0);

#define uSWAP64(x, y, t0) do {\
	t0 = x;\
	x = XOR(PSHUFB(x , mask_unpack64_l0), PSHUFB(y, mask_unpack64_h0));\
	y = XOR(PSHUFB(t0, mask_unpack64_l1), PSHUFB(y, mask_unpack64_h1));\
} while(0);

#define SWAP4(a, b, t0, t1) do {\
	t0 = AND(a, mask_u);\
	t1 = PSHIFTL(AND(a, mask_l), 4);\
	\
	a = PSHIFTR(AND(b, mask_u), 4);\
	b  = AND(b, mask_l);\
	\
	a  = XOR(t0, a);\
	b  = XOR(t1, b);\
} while(0);
	
/*   t0 = a; a = b; b = t0; */


/* SWAP4 with big endian */
#define SWAP4BE(a, b, t0, t1) do {\
	t0 = AND(a, mask_u);\
	t1 = PSHIFTL(AND(a, mask_l), 4);\
	\
	a  = AND(b, mask_l);\
	b = PSHIFTR(AND(b, mask_u), 4);\
	\
	a  = XOR(t1, a);\
	b  = XOR(t0, b);\
} while(0);

/*   t0 = a; a = b; b = t0; */

#define uSWAP4(a, b, t0, t1) do {\
	t0 = AND(a, mask_u);\
	t1 = AND(b, mask_u);\
	a  = AND(a, mask_l);\
	b  = AND(b, mask_l);\
	b = XOR(PSHIFTL(a, 4), b);\
	a = XOR(t0, PSHIFTR(t1,4));\
} while(0);

/*uSWAP4 with big endian */
#define uSWAP4BE(a, b, t0, t1) do {\
	t0 = AND(a, mask_u);\
	t1 = AND(b, mask_u);\
	a  = AND(a, mask_l);\
	b  = AND(b, mask_l);\
	a = XOR(PSHIFTL(a, 4), b);\
	b = XOR(t0, PSHIFTR(t1,4));\
} while(0);


#define BitSlice4(a, b, c, d, t0, t1, t2) do {\
	t0 = XOR(XOR(        AND(a, mask88)   , PSHIFTR(AND(b, mask88), 1)), XOR(PSHIFTR(AND(c, mask88), 2), PSHIFTR(AND(d, mask88), 3)));\
	t1 = XOR(XOR(PSHIFTL(AND(a, mask44),1),         AND(b, mask44))    , XOR(PSHIFTR(AND(c, mask44), 1), PSHIFTR(AND(d, mask44), 2)));\
	t2 = XOR(XOR(PSHIFTL(AND(a, mask22),2), PSHIFTL(AND(b, mask22), 1)), XOR(        AND(c, mask22),     PSHIFTR(AND(d, mask22), 1)));\
	d =  XOR(XOR(PSHIFTL(AND(a, mask11),3), PSHIFTL(AND(b, mask11), 2)), XOR(PSHIFTL(AND(c, mask11), 1),         AND(d, mask11)    ));\
	c = t2;\
	b = t1;\
	a = t0;\
} while(0);

#define uBitSlice4(a, b, c, d, t0, t1, t2) BitSlice4(a, b, c, d, t0, t1, t2);


/*
	Step 1: t0, a0, a1, a2, a3, a4, a5, a6
	t0 = A0A1   B0B1   A2A3   B2B3   ... A14A15B14B15
	a0 = A16A17 B16B17 A18A19 B18B19 ... A30A31B30B31
	...
	Step 2:
	t1 = A0--   B0--  A1--  B1--         A07-- B07--
	a7 = A8--   B8--  A9--  B9--         A15-- B15--

	output sequence: t0, a3, a0, a4, a1, a5, a2, a6
 */
#define packing16(a0, a1, a2, a3, a4, a5, a6, a7, t0, t1, t2) do {\
	SWAP4(a0, a1, t0, t1);\
	SWAP4(a2, a3, t0, t1);\
	SWAP4(a4, a5, t0, t1);\
	SWAP4(a6, a7, t0, t1);\
	\
	SWAP8(a0, a1, t0);\
	SWAP8(a2, a3, t0);\
	SWAP8(a4, a5, t0);\
	SWAP8(a6, a7, t0);\
	\
	SWAP8(a0, a1, t0);\
	SWAP8(a2, a3, t0);\
	SWAP8(a4, a5, t0);\
	SWAP8(a6, a7, t0);\
	\
	BitSlice4(a0, a2, a4, a6, t0, t1, t2);\
	BitSlice4(a1, a3, a5, a7, t0, t1, t2);\
	\
	t0 = a1; a1 = a2; a2 = a4; a4 = t0;\
	t0 = a3; a3 = a6; a6 = a5; a5 = t0;\
} while(0);

#define unpacking16(a0, a1, a2, a3, a4, a5, a6, a7, t0, t1, t2) do {\
	t0 = a4; a4 = a2; a2 = a1; a1 = t0;\
	t0 = a5; a5 = a6; a6 = a3; a3 = t0;\
	\
	uBitSlice4(a0, a2, a4, a6, t0, t1, t2);\
	uBitSlice4(a1, a3, a5, a7, t0, t1, t2);\
	\
	uSWAP8(a0, a1, t0);\
	uSWAP8(a2, a3, t0);\
	uSWAP8(a4, a5, t0);\
	uSWAP8(a6, a7, t0);\
	\
	uSWAP8(a0, a1, t0);\
	uSWAP8(a2, a3, t0);\
	uSWAP8(a4, a5, t0);\
	uSWAP8(a6, a7, t0);\
	\
	uSWAP4(a0, a1, t0, t1);\
	uSWAP4(a2, a3, t0, t1);\
	uSWAP4(a4, a5, t0, t1);\
	uSWAP4(a6, a7, t0, t1);\
} while(0);

/* now the results are in the order t0, a3, a2, a1, a0, b3, b2, b1, b0, c3, c2, c1, c0, d3, d2, d1 // */
/* d0, t0,  a2, a3, a1, a0, b2, b3, b1, b0, c2, c3, c1, c0 */

/* tbd */
#define packing32(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, t0, t1, t2) do {\
	packing16(a0, a1,  a2,  a3,  a4,  a5,  a6,  a7, t0, t1, t2);\
	packing16(a8, a9, a10, a11, a12, a13, a14, a15, t0, t1, t2);\
	SWAP16(a0, a8, t0);\
	SWAP16(a1, a9, t0);\
	SWAP16(a2, a10, t0);\
	SWAP16(a3, a11, t0);\
	SWAP16(a4, a12, t0);\
	SWAP16(a5, a13, t0);\
	SWAP16(a6, a14, t0);\
	SWAP16(a7, a15, t0);\
} while(0);

#define unpacking32(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, t0, t1, t2) do {\
	uSWAP16(a0, a8, t0);\
	uSWAP16(a1, a9, t0);\
	uSWAP16(a2, a10, t0);\
	uSWAP16(a3, a11, t0);\
	uSWAP16(a4, a12, t0);\
	uSWAP16(a5, a13, t0);\
	uSWAP16(a6, a14, t0);\
	uSWAP16(a7, a15, t0);\
	unpacking16(a0, a1,  a2,  a3,  a4,  a5,  a6,  a7, t0, t1, t2);\
	unpacking16(a8, a9, a10, a11, a12, a13, a14, a15, t0, t1, t2);\
} while(0);

#define init() do {\
	mask0 = CONSTANT(0x80);  /* set all 16 bytes of mask0 to the value 0x80 */\
	mask1 = CONSTANT(0x40);\
	mask2 = CONSTANT(0x20);\
	mask3 = CONSTANT(0x10);\
	mask4 = CONSTANT(0x08);\
	mask5 = CONSTANT(0x04);\
	mask6 = CONSTANT(0x02);\
	mask7 = CONSTANT(0x01);\
	mask_one = CONSTANT(0xff);\
	mask_odd = SET(0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80, 15,13,11,9,7,5,3,1);\
	mask_oddh = SET( 15,13,11,9,7,5,3,1,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80);\
	mask_key1 = SET(0x0, 0x80, 0x80, 0x80, 0x80, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6 ,5);\
	mask_key2 = SET(0x80, 3, 2, 1, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80);\
	mask128_key1 = SET(0x0, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80);\
	mask128_key2 = SET(0x80, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6 ,5, 4, 3, 2, 1);\
	\
	mask512_key1 = SET(0x1, 0x0, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80);\
	mask512_key2 = SET(0x80, 0x80, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6 ,5, 4, 3, 2);\
	\
	mask128_and_b21 = SET(0, 0, 0xff, 0xff,0xff, 0xff,0xff, 0xff,0xff, 0xff,0xff, 0xff,0xff, 0xff,0xff, 0xff);\
	mask128_and_b22 = SET(0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);\
	\
	mask_u = CONSTANT(0xf0);\
	mask_l = CONSTANT(0x0f);\
	mask88  = CONSTANT(0x88);\
	mask44  = CONSTANT(0x44);\
	mask22  = CONSTANT(0x22);\
	mask11  = CONSTANT(0x11);\
	mask_one = CONSTANT(0xff);\
	mask_unpack64_l0 = SET(0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80, 7, 6, 5, 4, 3, 2, 1, 0);\
	mask_unpack64_l1 = SET(0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80, 15, 14, 13, 12, 11, 10, 9, 8);\
	mask_unpack64_h0 = SET(7, 6, 5, 4, 3, 2, 1, 0, 0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80);\
	mask_unpack64_h1 = SET(15, 14, 13, 12, 11, 10, 9, 8, 0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80);\
	mask_unpack16_l0 = SET(0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80, 13, 12, 9, 8, 5, 4, 1, 0);\
	mask_unpack16_l1 = SET(0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80, 15, 14, 11, 10, 7, 6, 3, 2);\
	mask_unpack16_h0 = SET(13, 12,  9,  8, 5, 4, 1, 0, 0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80);\
	mask_unpack16_h1 = SET(15, 14, 11, 10, 7, 6, 3, 2, 0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80);\
	\
	mask_unpack8_l0 = SET(0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80, 14, 12, 10, 8, 6, 4, 2, 0);\
	mask_unpack8_l1 = SET(0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80, 15, 13, 11, 9, 7, 5, 3, 1);\
	mask_unpack8_h0 = SET(14, 12, 10, 8, 6, 4, 2, 0, 0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80);\
	mask_unpack8_h1 = SET(15, 13, 11, 9, 7, 5, 3, 1, 0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80);\
	mask_u64 = SET(0xff, 0xff, 0xff, 0xff,0xff, 0xff, 0xff, 0xff,0,0,0,0,0,0,0,0);\
	mask_l64 = SET(0,0,0,0,0,0,0,0, 0xff, 0xff, 0xff, 0xff,0xff, 0xff, 0xff, 0xff);\
	\
	mask16_sr01 = SET(13, 12, 11, 10, 9, 8, 15, 14, 7, 6, 5, 4, 3, 2, 1, 0);\
	mask16_sr23 = SET(9, 8, 15, 14, 13, 12, 11, 10, 3, 2, 1, 0, 7, 6, 5, 4);\
	mask_byte_endian   = SET(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);\
	mask_byte_endian64 = SET(8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7);\
	mask_byte_endian80 = SET(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7);\
} while(0);

word mask_l16, mask_r16;
#define cross16(r, a, b) do {\
	r = XOR(AND(a, mask_l16), AND(b, mask_r16));\
} while(0);

#define pack_lr(r0, r1, r2, r3, a0, a1, a2, a3, b0, b1, b2, b3) do {\
	cross(r0, a0, b0);\
	cross(r1, a1, b1);\
	cross(r2, a2, b2);\
	cross(r3, a3, b3);\
} while(0);

#define AddKey(r0, r1, r2, r3, a0, a1, a2, a3)	XOR_Key(r0, r1, r2, r3, a0, a1, a2, a3)

#define inverse_nibble_endian(a, t0, t1) do {\
        t0 = AND(a, mask_l);\
        t1 = AND(a, mask_u);\
        t0 = PSHIFTL(t0, 4);\
        t1 = PSHIFTR(t1, 4);\
        a  = XOR(t0, t1);\
} while(0);

#define inverse_bytes_endian(a) do {\
        a  = PSHUFB(a, mask_byte_endian);\
} while(0);

#define inverse_bytes_endian64(a) do {\
        a  = PSHUFB(a, mask_byte_endian64);\
} while(0);

#define inverse_bytes_endian80(a) do {\
        a  = PSHUFB(a, mask_byte_endian80);\
} while(0);
