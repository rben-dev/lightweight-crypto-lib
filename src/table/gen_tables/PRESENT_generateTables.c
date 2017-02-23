/*------------------------ MIT License HEADER ------------------------------------
    Copyright ANSSI and NTU (2015)
    Contributors:
    Ryad BENADJILA [ryadbenadjila@gmail.com] and
    Jian GUO [ntu.guo@gmail.com] and
    Victor LOMNE [victor.lomne@gmail.com] and
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
/* PRESENTgenerateTables.c */
/* author: Victor LOMNE - victor.lomne@gmail.com */



#include <stdio.h>

/* PRESENT Sbox */
unsigned char sbox[16] = {0x0C, 0x05, 0x06, 0x0B, 0x09, 0x00, 0x0A, 0X0D, 0x03, 0x0E, 0x0F, 0x08, 0x04, 0x07, 0x01, 0x02};



/****************************************************************************************************/
void main(void)
{
	unsigned char il, ih, twoSboxes;
	unsigned int i;
	unsigned long long T0_PRESENT[256], T1_PRESENT[256], T2_PRESENT[256], T3_PRESENT[256], T4_PRESENT[256], T5_PRESENT[256], T6_PRESENT[256], T7_PRESENT[256], TroundCounters80[31], TroundCounters128[31], TsboxKS80[16], TsboxKS128[256];
	FILE * ptr;

	/* loop over the possible input values to compute for T0, T1, T2, T3, T4, T5, T6 and T7 */
	for(i = 0; i < 256; i++)
	{
		/* compute low and high parts of i */
		il = i & 0x0f;
		ih = (i & 0xf0) >> 4;

		/* compute two sboxes look-up */
		twoSboxes = (sbox[ih] << 4) | sbox[il];

		/* compute T0 */
		T0_PRESENT[i]  = ((unsigned long long)( (twoSboxes >> 0) & 0x01 )) << 0;
		T0_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 1) & 0x01 )) << 16;
		T0_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 2) & 0x01 )) << 32;
		T0_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 3) & 0x01 )) << 48;
		T0_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 4) & 0x01 )) << 1;
		T0_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 5) & 0x01 )) << 17;
		T0_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 6) & 0x01 )) << 33;
		T0_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 7) & 0x01 )) << 49;

		/* compute T1 */
		T1_PRESENT[i]  = ((unsigned long long)( (twoSboxes >> 0) & 0x01 )) << 2;
		T1_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 1) & 0x01 )) << 18;
		T1_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 2) & 0x01 )) << 34;
		T1_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 3) & 0x01 )) << 50;
		T1_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 4) & 0x01 )) << 3;
		T1_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 5) & 0x01 )) << 19;
		T1_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 6) & 0x01 )) << 35;
		T1_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 7) & 0x01 )) << 51;

		/* compute T2 */
		T2_PRESENT[i]  = ((unsigned long long)( (twoSboxes >> 0) & 0x01 )) << 4;
		T2_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 1) & 0x01 )) << 20;
		T2_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 2) & 0x01 )) << 36;
		T2_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 3) & 0x01 )) << 52;
		T2_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 4) & 0x01 )) << 5;
		T2_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 5) & 0x01 )) << 21;
		T2_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 6) & 0x01 )) << 37;
		T2_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 7) & 0x01 )) << 53;

		/* compute T3 */
		T3_PRESENT[i]  = ((unsigned long long)( (twoSboxes >> 0) & 0x01 )) << 6;
		T3_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 1) & 0x01 )) << 22;
		T3_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 2) & 0x01 )) << 38;
		T3_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 3) & 0x01 )) << 54;
		T3_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 4) & 0x01 )) << 7;
		T3_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 5) & 0x01 )) << 23;
		T3_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 6) & 0x01 )) << 39;
		T3_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 7) & 0x01 )) << 55;

		/* compute T4 */
		T4_PRESENT[i]  = ((unsigned long long)( (twoSboxes >> 0) & 0x01 )) << 8;
		T4_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 1) & 0x01 )) << 24;
		T4_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 2) & 0x01 )) << 40;
		T4_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 3) & 0x01 )) << 56;
		T4_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 4) & 0x01 )) << 9;
		T4_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 5) & 0x01 )) << 25;
		T4_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 6) & 0x01 )) << 41;
		T4_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 7) & 0x01 )) << 57;

		/* compute T5 */
		T5_PRESENT[i]  = ((unsigned long long)( (twoSboxes >> 0) & 0x01 )) << 10;
		T5_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 1) & 0x01 )) << 26;
		T5_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 2) & 0x01 )) << 42;
		T5_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 3) & 0x01 )) << 58;
		T5_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 4) & 0x01 )) << 11;
		T5_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 5) & 0x01 )) << 27;
		T5_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 6) & 0x01 )) << 43;
		T5_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 7) & 0x01 )) << 59;

		/* compute T6 */
		T6_PRESENT[i]  = ((unsigned long long)( (twoSboxes >> 0) & 0x01 )) << 12;
		T6_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 1) & 0x01 )) << 28;
		T6_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 2) & 0x01 )) << 44;
		T6_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 3) & 0x01 )) << 60;
		T6_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 4) & 0x01 )) << 13;
		T6_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 5) & 0x01 )) << 29;
		T6_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 6) & 0x01 )) << 45;
		T6_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 7) & 0x01 )) << 61;

		/* compute T7 */
		T7_PRESENT[i]  = ((unsigned long long)( (twoSboxes >> 0) & 0x01 )) << 14;
		T7_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 1) & 0x01 )) << 30;
		T7_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 2) & 0x01 )) << 46;
		T7_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 3) & 0x01 )) << 62;
		T7_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 4) & 0x01 )) << 15;
		T7_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 5) & 0x01 )) << 31;
		T7_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 6) & 0x01 )) << 47;
		T7_PRESENT[i] |= ((unsigned long long)( (twoSboxes >> 7) & 0x01 )) << 63;

		/* compute TsboxKS128 */
		TsboxKS128[i] = ((unsigned long long)twoSboxes) << 56;
	}

	/* compute TroundCounters80 */
	for(i = 0; i < 31; i++)
		TroundCounters80[i] = ((unsigned long long)(i+1)) << 18;

	/* compute TsboxKS80 */
	for(i = 0; i < 16; i++)
		TsboxKS80[i] = ((unsigned long long)sbox[i]) << 60;

	/* compute TroundCounters128 */
	for(i = 0; i < 31; i++)
		TroundCounters128[i] = ((unsigned long long)(i+1)) << 1;



	/* open a pointer and create the file PRESENTtables.h */
	ptr = fopen("../PRESENT/PRESENT_tables.h", "w");
	if(ptr == NULL)
	{
		printf("Unable to create file PRESENT_tables.h\n");
		return;
	}

	/* write T0 */
	fprintf(ptr, "unsigned long long T0_PRESENT[256] = {");
	for(i = 0; i < 256; i++)
	{
		fprintf(ptr, "0x%016llx", T0_PRESENT[i]);
		if(i == 255)
			fprintf(ptr, "};\n\n");
		else
			fprintf(ptr, ", ");
	}

	/* write T1 */
	fprintf(ptr, "unsigned long long T1_PRESENT[256] = {");
	for(i = 0; i < 256; i++)
	{
		fprintf(ptr, "0x%016llx", T1_PRESENT[i]);
		if(i == 255)
			fprintf(ptr, "};\n\n");
		else
			fprintf(ptr, ", ");
	}

	/* write T2 */
	fprintf(ptr, "unsigned long long T2_PRESENT[256] = {");
	for(i = 0; i < 256; i++)
	{
		fprintf(ptr, "0x%016llx", T2_PRESENT[i]);
		if(i == 255)
			fprintf(ptr, "};\n\n");
		else
			fprintf(ptr, ", ");
	}

	/* write T3 */
	fprintf(ptr, "unsigned long long T3_PRESENT[256] = {");
	for(i = 0; i < 256; i++)
	{
		fprintf(ptr, "0x%016llx", T3_PRESENT[i]);
		if(i == 255)
			fprintf(ptr, "};\n\n");
		else
			fprintf(ptr, ", ");
	}

	/* write T4 */
	fprintf(ptr, "unsigned long long T4_PRESENT[256] = {");
	for(i = 0; i < 256; i++)
	{
		fprintf(ptr, "0x%016llx", T4_PRESENT[i]);
		if(i == 255)
			fprintf(ptr, "};\n\n");
		else
			fprintf(ptr, ", ");
	}

	/* write T5 */
	fprintf(ptr, "unsigned long long T5_PRESENT[256] = {");
	for(i = 0; i < 256; i++)
	{
		fprintf(ptr, "0x%016llx", T5_PRESENT[i]);
		if(i == 255)
			fprintf(ptr, "};\n\n");
		else
			fprintf(ptr, ", ");
	}

	/* write T6 */
	fprintf(ptr, "unsigned long long T6_PRESENT[256] = {");
	for(i = 0; i < 256; i++)
	{
		fprintf(ptr, "0x%016llx", T6_PRESENT[i]);
		if(i == 255)
			fprintf(ptr, "};\n\n");
		else
			fprintf(ptr, ", ");
	}

	/* write T7 */
	fprintf(ptr, "unsigned long long T7_PRESENT[256] = {");
	for(i = 0; i < 256; i++)
	{
		fprintf(ptr, "0x%016llx", T7_PRESENT[i]);
		if(i == 255)
			fprintf(ptr, "};\n\n");
		else
			fprintf(ptr, ", ");
	}

	/* write TroundCounters80 */
	fprintf(ptr, "unsigned long long TroundCounters80[31] = {");
	for(i = 0; i < 31; i++)
	{
		fprintf(ptr, "0x%016llx", TroundCounters80[i]);
		if(i == 30)
			fprintf(ptr, "};\n\n");
		else
			fprintf(ptr, ", ");
	}

	/* write TsboxKS80 */
	fprintf(ptr, "unsigned long long TsboxKS80[16] = {");
	for(i = 0; i < 16; i++)
	{
		fprintf(ptr, "0x%016llx", TsboxKS80[i]);
		if(i == 15)
			fprintf(ptr, "};\n\n");
		else
			fprintf(ptr, ", ");
	}

	/* write TroundCounters128 */
	fprintf(ptr, "unsigned long long TroundCounters128[31] = {");
	for(i = 0; i < 31; i++)
	{
		fprintf(ptr, "0x%016llx", TroundCounters128[i]);
		if(i == 30)
			fprintf(ptr, "};\n\n");
		else
			fprintf(ptr, ", ");
	}

	/* write TsboxKS128 */
	fprintf(ptr, "unsigned long long TsboxKS128[256] = {");
	for(i = 0; i < 256; i++)
	{
		fprintf(ptr, "0x%016llx", TsboxKS128[i]);
		if(i == 255)
			fprintf(ptr, "};\n\n");
		else
			fprintf(ptr, ", ");
	}

	/* close the pointer */
	fclose(ptr);

	return;

}
