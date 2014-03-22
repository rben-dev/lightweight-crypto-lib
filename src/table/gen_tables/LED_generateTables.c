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

    The current source code is part of the table based implementations
    source tree.

    Project: Lightweight cryptography library
    File:    src/table/gen_tables/LED_generateTables.c

-------------------------- CeCILL-B HEADER ----------------------------------*/
/* LEDgenerateTables.c */
/* author: Victor LOMNE - victor.lomne@gmail.com */



#include <stdio.h>

/* LED Sbox */
unsigned char sbox[16] = {0x0C, 0x05, 0x06, 0x0B, 0x09, 0x00, 0x0A, 0X0D, 0x03, 0x0E, 0x0F, 0x08, 0x04, 0x07, 0x01, 0x02};

/* LED xtime (tabulated multiplication by x in the finite field x^4 + x + 1) */
unsigned char xtime[16] = {0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E, 0x03, 0x01, 0x07, 0x05, 0x0B, 0x09, 0x0F, 0x0D};

/* Round constants */
unsigned char RC[48] = {0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F, 0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B, 0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E, 0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A, 0x34, 0x29, 0x12, 0x24, 0x08, 0x11, 0x22, 0x04};



/****************************************************************************************************/
void main(void)
{
	unsigned int i;
	unsigned char il, ih;
	unsigned long long T0_LED[256], T1_LED[256], T2_LED[256], T3_LED[256], T4_LED[256], T5_LED[256], T6_LED[256], T7_LED[256], Tcon64_LED[32], Tcon128_LED[48];
	FILE * ptr;

	/* loop over the possible input values to compute for T0, T1, T2, T3, T4, T5, T6 and T7 */
	/* T0, T1, T2, T3, T4, T5, T6 and T7 allow to compute MixColumnsSerial(ShiftRows(SubCells(i))) */
	for(i = 0; i < 256; i++)
	{
		/* compute low and high parts of i */
		ih = i & 0x0f;
		il = (i & 0xf0) >> 4;

		/* compute T0 */
		T0_LED[i]  = ((unsigned long long)( xtime[xtime[sbox[il]]]                                     )) << 4;
		T0_LED[i] |= ((unsigned long long)( xtime[xtime[sbox[ih]]]                                     )) << 0;
		T0_LED[i] |= ((unsigned long long)( xtime[xtime[xtime[sbox[il]]]]                              )) << 20;
		T0_LED[i] |= ((unsigned long long)( xtime[xtime[xtime[sbox[ih]]]]                              )) << 16;
		T0_LED[i] |= ((unsigned long long)( xtime[xtime[xtime[sbox[il]]]] ^ xtime[sbox[il]] ^ sbox[il] )) << 36;
		T0_LED[i] |= ((unsigned long long)( xtime[xtime[xtime[sbox[ih]]]] ^ xtime[sbox[ih]] ^ sbox[ih] )) << 32;
		T0_LED[i] |= ((unsigned long long)( xtime[sbox[il]]                                            )) << 52;
		T0_LED[i] |= ((unsigned long long)( xtime[sbox[ih]]                                            )) << 48;

		/* compute T1 */
		T1_LED[i]  = ((unsigned long long)( xtime[xtime[sbox[il]]]                                     )) << 12;
		T1_LED[i] |= ((unsigned long long)( xtime[xtime[sbox[ih]]]                                     )) << 8;
		T1_LED[i] |= ((unsigned long long)( xtime[xtime[xtime[sbox[il]]]]                              )) << 28;
		T1_LED[i] |= ((unsigned long long)( xtime[xtime[xtime[sbox[ih]]]]                              )) << 24;
		T1_LED[i] |= ((unsigned long long)( xtime[xtime[xtime[sbox[il]]]] ^ xtime[sbox[il]] ^ sbox[il] )) << 44;
		T1_LED[i] |= ((unsigned long long)( xtime[xtime[xtime[sbox[ih]]]] ^ xtime[sbox[ih]] ^ sbox[ih] )) << 40;
		T1_LED[i] |= ((unsigned long long)( xtime[sbox[il]]                                            )) << 60;
		T1_LED[i] |= ((unsigned long long)( xtime[sbox[ih]]                                            )) << 56;

		/* compute T2 */
		T2_LED[i]  = ((unsigned long long)( sbox[ih]                                                                 )) << 4;
		T2_LED[i] |= ((unsigned long long)( sbox[il]                                                                 )) << 8;
		T2_LED[i] |= ((unsigned long long)( xtime[xtime[sbox[ih]]] ^ xtime[sbox[ih]]                                 )) << 20;
		T2_LED[i] |= ((unsigned long long)( xtime[xtime[sbox[il]]] ^ xtime[sbox[il]]                                 )) << 24;
		T2_LED[i] |= ((unsigned long long)( xtime[xtime[xtime[sbox[ih]]]] ^ xtime[xtime[sbox[ih]]] ^ xtime[sbox[ih]] )) << 36;
		T2_LED[i] |= ((unsigned long long)( xtime[xtime[xtime[sbox[il]]]] ^ xtime[xtime[sbox[il]]] ^ xtime[sbox[il]] )) << 40;
		T2_LED[i] |= ((unsigned long long)( xtime[sbox[ih]]                                                          )) << 52;
		T2_LED[i] |= ((unsigned long long)( xtime[sbox[il]]                                                          )) << 56;

		/* compute T3 */
		T3_LED[i]  = ((unsigned long long)( sbox[il]                                                                 )) << 0;
		T3_LED[i] |= ((unsigned long long)( sbox[ih]                                                                 )) << 12;
		T3_LED[i] |= ((unsigned long long)( xtime[xtime[sbox[il]]] ^ xtime[sbox[il]]                                 )) << 16;
		T3_LED[i] |= ((unsigned long long)( xtime[xtime[sbox[ih]]] ^ xtime[sbox[ih]]                                 )) << 28;
		T3_LED[i] |= ((unsigned long long)( xtime[xtime[xtime[sbox[il]]]] ^ xtime[xtime[sbox[il]]] ^ xtime[sbox[il]] )) << 32;
		T3_LED[i] |= ((unsigned long long)( xtime[xtime[xtime[sbox[ih]]]] ^ xtime[xtime[sbox[ih]]] ^ xtime[sbox[ih]] )) << 44;
		T3_LED[i] |= ((unsigned long long)( xtime[sbox[il]]                                                          )) << 48;
		T3_LED[i] |= ((unsigned long long)( xtime[sbox[ih]]                                                          )) << 60;

		/* compute T4 */
		T4_LED[i]  = ((unsigned long long)( xtime[sbox[il]]                                                                     )) << 12;
		T4_LED[i] |= ((unsigned long long)( xtime[sbox[ih]]                                                                     )) << 8;
		T4_LED[i] |= ((unsigned long long)( xtime[xtime[sbox[il]]] ^ sbox[il]                                                   )) << 28;
		T4_LED[i] |= ((unsigned long long)( xtime[xtime[sbox[ih]]] ^ sbox[ih]                                                   )) << 24;
		T4_LED[i] |= ((unsigned long long)( xtime[xtime[xtime[sbox[il]]]] ^ xtime[sbox[il]]                                     )) << 44;
		T4_LED[i] |= ((unsigned long long)( xtime[xtime[xtime[sbox[ih]]]] ^ xtime[sbox[ih]]                                     )) << 40;
		T4_LED[i] |= ((unsigned long long)( xtime[xtime[xtime[sbox[il]]]] ^ xtime[xtime[sbox[il]]] ^ xtime[sbox[il]] ^ sbox[il] )) << 60;
		T4_LED[i] |= ((unsigned long long)( xtime[xtime[xtime[sbox[ih]]]] ^ xtime[xtime[sbox[ih]]] ^ xtime[sbox[ih]] ^ sbox[ih] )) << 56;

		/* compute T5 */
		T5_LED[i]  = ((unsigned long long)( xtime[sbox[il]]                                                                     )) << 4;
		T5_LED[i] |= ((unsigned long long)( xtime[sbox[ih]]                                                                     )) << 0;
		T5_LED[i] |= ((unsigned long long)( xtime[xtime[sbox[il]]] ^ sbox[il]                                                   )) << 20;
		T5_LED[i] |= ((unsigned long long)( xtime[xtime[sbox[ih]]] ^ sbox[ih]                                                   )) << 16;
		T5_LED[i] |= ((unsigned long long)( xtime[xtime[xtime[sbox[il]]]] ^ xtime[sbox[il]]                                     )) << 36;
		T5_LED[i] |= ((unsigned long long)( xtime[xtime[xtime[sbox[ih]]]] ^ xtime[sbox[ih]]                                     )) << 32;
		T5_LED[i] |= ((unsigned long long)( xtime[xtime[xtime[sbox[il]]]] ^ xtime[xtime[sbox[il]]] ^ xtime[sbox[il]] ^ sbox[il] )) << 52;
		T5_LED[i] |= ((unsigned long long)( xtime[xtime[xtime[sbox[ih]]]] ^ xtime[xtime[sbox[ih]]] ^ xtime[sbox[ih]] ^ sbox[ih] )) << 48;

		/* compute T6 */
		T6_LED[i]  = ((unsigned long long)( xtime[sbox[il]]                                            )) << 0;
		T6_LED[i] |= ((unsigned long long)( xtime[sbox[ih]]                                            )) << 12;
		T6_LED[i] |= ((unsigned long long)( xtime[xtime[sbox[il]]] ^ xtime[sbox[il]]                   )) << 16;
		T6_LED[i] |= ((unsigned long long)( xtime[xtime[sbox[ih]]] ^ xtime[sbox[ih]]                   )) << 28;
		T6_LED[i] |= ((unsigned long long)( xtime[xtime[xtime[sbox[il]]]] ^ sbox[il]                   )) << 32;
		T6_LED[i] |= ((unsigned long long)( xtime[xtime[xtime[sbox[ih]]]] ^ sbox[ih]                   )) << 44;
		T6_LED[i] |= ((unsigned long long)( xtime[xtime[xtime[sbox[il]]]] ^ xtime[sbox[il]] ^ sbox[il] )) << 48;
		T6_LED[i] |= ((unsigned long long)( xtime[xtime[xtime[sbox[ih]]]] ^ xtime[sbox[ih]] ^ sbox[ih] )) << 60;

		/* compute T7 */
		T7_LED[i]  = ((unsigned long long)( xtime[sbox[ih]]                                            )) << 4;
		T7_LED[i] |= ((unsigned long long)( xtime[sbox[il]]                                            )) << 8;
		T7_LED[i] |= ((unsigned long long)( xtime[xtime[sbox[ih]]] ^ xtime[sbox[ih]]                   )) << 20;
		T7_LED[i] |= ((unsigned long long)( xtime[xtime[sbox[il]]] ^ xtime[sbox[il]]                   )) << 24;
		T7_LED[i] |= ((unsigned long long)( xtime[xtime[xtime[sbox[ih]]]] ^ sbox[ih]                   )) << 36;
		T7_LED[i] |= ((unsigned long long)( xtime[xtime[xtime[sbox[il]]]] ^ sbox[il]                   )) << 40;
		T7_LED[i] |= ((unsigned long long)( xtime[xtime[xtime[sbox[ih]]]] ^ xtime[sbox[ih]] ^ sbox[ih] )) << 52;
		T7_LED[i] |= ((unsigned long long)( xtime[xtime[xtime[sbox[il]]]] ^ xtime[sbox[il]] ^ sbox[il] )) << 56;
	}

	/* compute Tcon64_LED */
	for(i = 0; i < 32; i++)
	{
		/* nibble 0 of row 0 */
		Tcon64_LED[i]  = ((unsigned long long)(  0 ^ ((64 & 0xF0) >> 4) )) << 4;

		/* nibble 0 of row 1 */
		Tcon64_LED[i] |= ((unsigned long long)(  1 ^ ((64 & 0xF0) >> 4) )) << 20;

		/* nibble 0 of row 2 */
		Tcon64_LED[i] |= ((unsigned long long)(  2 ^  (64 & 0x0F)       )) << 36;

		/* nibble 0 of row 3 */
		Tcon64_LED[i] |= ((unsigned long long)(  3 ^ (64 & 0x0F)        )) << 52;

		/* nibble 1 of row 0 */
		Tcon64_LED[i] |= ((unsigned long long)( (RC[i] & 0x38)          >> 3)) << 0;

		/* nibble 1 of row 1 */
		Tcon64_LED[i] |= ((unsigned long long)( (RC[i] & 0x07)              )) << 16;

		/* nibble 1 of row 2 */
		Tcon64_LED[i] |= ((unsigned long long)( (RC[i] & 0x38)          >> 3)) << 32;

		/* nibble 1 of row 3 */
		Tcon64_LED[i] |= ((unsigned long long)( (RC[i] & 0x07)              )) << 48;
	}

	/* compute Tcon128_LED */
	for(i = 0; i < 48; i++)
	{
		/* nibble 0 of row 0 */
		Tcon128_LED[i]  = ((unsigned long long)(  0 ^ ((128 & 0xF0) >> 4) )) << 4;

		/* nibble 0 of row 1 */
		Tcon128_LED[i] |= ((unsigned long long)(  1 ^ ((128 & 0xF0) >> 4) )) << 20;

		/* nibble 0 of row 2 */
		Tcon128_LED[i] |= ((unsigned long long)(  2 ^  (128 & 0x0F)       )) << 36;

		/* nibble 0 of row 3 */
		Tcon128_LED[i] |= ((unsigned long long)(  3 ^ (128 & 0x0F)        )) << 52;

		/* nibble 1 of row 0 */
		Tcon128_LED[i] |= ((unsigned long long)( (RC[i] & 0x38)          >> 3)) << 0;

		/* nibble 1 of row 1 */
		Tcon128_LED[i] |= ((unsigned long long)( (RC[i] & 0x07)              )) << 16;

		/* nibble 1 of row 2 */
		Tcon128_LED[i] |= ((unsigned long long)( (RC[i] & 0x38)          >> 3)) << 32;

		/* nibble 1 of row 3 */
		Tcon128_LED[i] |= ((unsigned long long)( (RC[i] & 0x07)              )) << 48;
	}

	/* open a pointer and create the file LEDtables.h */
	ptr = fopen("../LED/LED_tables.h", "w");
	if(ptr == NULL)
	{
		printf("Unable to create file LED_tables.h\n");
		return;
	}

	/* write T0 */
	fprintf(ptr, "unsigned long long T0_LED[256] = {");
	for(i = 0; i < 256; i++)
	{
		fprintf(ptr, "0x%016llx", T0_LED[i]);
		if(i == 255)
			fprintf(ptr, "};\n\n");
		else
			fprintf(ptr, ", ");
	}

	/* write T1 */
	fprintf(ptr, "unsigned long long T1_LED[256] = {");
	for(i = 0; i < 256; i++)
	{
		fprintf(ptr, "0x%016llx", T1_LED[i]);
		if(i == 255)
			fprintf(ptr, "};\n\n");
		else
			fprintf(ptr, ", ");
	}

	/* write T2 */
	fprintf(ptr, "unsigned long long T2_LED[256] = {");
	for(i = 0; i < 256; i++)
	{
		fprintf(ptr, "0x%016llx", T2_LED[i]);
		if(i == 255)
			fprintf(ptr, "};\n\n");
		else
			fprintf(ptr, ", ");
	}

	/* write T3 */
	fprintf(ptr, "unsigned long long T3_LED[256] = {");
	for(i = 0; i < 256; i++)
	{
		fprintf(ptr, "0x%016llx", T3_LED[i]);
		if(i == 255)
			fprintf(ptr, "};\n\n");
		else
			fprintf(ptr, ", ");
	}

	/* write T4 */
	fprintf(ptr, "unsigned long long T4_LED[256] = {");
	for(i = 0; i < 256; i++)
	{
		fprintf(ptr, "0x%016llx", T4_LED[i]);
		if(i == 255)
			fprintf(ptr, "};\n\n");
		else
			fprintf(ptr, ", ");
	}

	/* write T5 */
	fprintf(ptr, "unsigned long long T5_LED[256] = {");
	for(i = 0; i < 256; i++)
	{
		fprintf(ptr, "0x%016llx", T5_LED[i]);
		if(i == 255)
			fprintf(ptr, "};\n\n");
		else
			fprintf(ptr, ", ");
	}

	/* write T6 */
	fprintf(ptr, "unsigned long long T6_LED[256] = {");
	for(i = 0; i < 256; i++)
	{
		fprintf(ptr, "0x%016llx", T6_LED[i]);
		if(i == 255)
			fprintf(ptr, "};\n\n");
		else
			fprintf(ptr, ", ");
	}

	/* write T7 */
	fprintf(ptr, "unsigned long long T7_LED[256] = {");
	for(i = 0; i < 256; i++)
	{
		fprintf(ptr, "0x%016llx", T7_LED[i]);
		if(i == 255)
			fprintf(ptr, "};\n\n");
		else
			fprintf(ptr, ", ");
	}

	/* write Tcon64_LED */
	fprintf(ptr, "unsigned long long Tcon64_LED[32]  = {");
	for(i = 0; i < 32; i++)
	{
		fprintf(ptr, "0x%016llx", Tcon64_LED[i]);
		if(i == 31)
			fprintf(ptr, "};\n\n");
		else
			fprintf(ptr, ", ");
	}

	/* write Tcon128_LED */
	fprintf(ptr, "unsigned long long Tcon128_LED[48] = {");
	for(i = 0; i < 48; i++)
	{
		fprintf(ptr, "0x%016llx", Tcon128_LED[i]);
		if(i == 47)
			fprintf(ptr, "};\n\n");
		else
			fprintf(ptr, ", ");
	}

	/* close the pointer */
	fclose(ptr);

	return;
}
