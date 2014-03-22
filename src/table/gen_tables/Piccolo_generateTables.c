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
    File:    src/table/gen_tables/Piccolo_generateTables.c

-------------------------- CeCILL-B HEADER ----------------------------------*/
/*PICCOLOgenerateTables.c */
/* author: Victor LOMNE - victor.lomne@gmail.com */



#include <stdio.h>

/* PICCOLO Sbox */
unsigned char sbox[16] = {0x0E, 0x04, 0x0B, 0x02, 0x03, 0x08, 0x00, 0X09, 0x01, 0x0A, 0x07, 0x0F, 0x06, 0x0C, 0x05, 0x0D};

/* PICCOLO xtime (tabulated multiplication by x in the finite field x^4 + x + 1) */
unsigned char xtime[16] = {0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E, 0x03, 0x01, 0x07, 0x05, 0x0B, 0x09, 0x0F, 0x0D};



/****************************************************************************************************/
void main(void)
{
	unsigned int i, temp;
	unsigned char il, ih;
	unsigned int T0_Piccolo[256], T1_Piccolo[256];
	unsigned long long T2_Piccolo[256], T3_Piccolo[256], T4_Piccolo[256], T5_Piccolo[256], Tcon80_Piccolo[25], Tcon128_Piccolo[31];
	FILE * ptr;

	/* loop over the possible input values to compute for T0, T1, T2, T3, T4 and T5 */
	/* T0, T1, T2, T3 T4 and T5 allow to compute the Feistel function */
	for(i = 0; i < 256; i++)
	{
		/* compute low and high parts of i */
		il = i & 0x0f;
		ih = (i & 0xf0) >> 4;

		/* compute T0 */
		T0_Piccolo[i] =  (sbox[il] ^ sbox[ih]) << 12;
		T0_Piccolo[i] |= (sbox[il] ^ xtime[sbox[ih]] ^ sbox[ih]) << 8;
		T0_Piccolo[i] |= (xtime[sbox[il]] ^ sbox[il] ^ xtime[sbox[ih]]) << 4;
		T0_Piccolo[i] |= (xtime[sbox[il]] ^ sbox[ih]);

		/* compute T1 */
		T1_Piccolo[i] =  (xtime[sbox[il]] ^ sbox[il] ^ xtime[sbox[ih]]) << 12;
		T1_Piccolo[i] |= (xtime[sbox[il]] ^ sbox[ih]) << 8;
		T1_Piccolo[i] |= (sbox[il] ^ sbox[ih]) << 4;
		T1_Piccolo[i] |= (sbox[il] ^ xtime[sbox[ih]] ^ sbox[ih]);

		/* compute T2 and T3 */
		T2_Piccolo[i] = ((unsigned long long)(sbox[il] | (sbox[ih] << 4))) << 16;
		T3_Piccolo[i] = ((unsigned long long)(sbox[il] | (sbox[ih] << 4))) << 24;

		/* compute T4 and T5 */
		T4_Piccolo[i] = (unsigned long long)(sbox[il] | (sbox[ih] << 4)) << 48;
		T5_Piccolo[i] = (unsigned long long)(sbox[il] | (sbox[ih] << 4)) << 56;
	}

	/* loop over the 25 rounds to compute constants (in Tcon80_Piccolo) for PICCOLO80 key schedule */
	for(i = 0; i < 25; i++)
	{
		temp = ( (((i+1) & 0x1f) << 27) | (((i+1) & 0x1f) << 17) | (((i+1) & 0x1f) << 10) | ((i+1) & 0x1f) ) ^ 0x0f1e2d3c;
		Tcon80_Piccolo[i] = ((unsigned long long)(temp & 0xff000000) >> 8) | ((unsigned long long)(temp & 0x00ff0000) << 8) | ((unsigned long long)(temp & 0x0000ff00) << 40) | ((unsigned long long)(temp & 0x000000ff) << 56);
	}

	/* loop over the 31 rounds to compute constants (in Tcon128_Piccolo) for PICCOLO128 key schedule */
	for(i = 0; i < 31; i++)
	{
		temp = ( (((i+1) & 0x1f) << 27) | (((i+1) & 0x1f) << 17) | (((i+1) & 0x1f) << 10) | ((i+1) & 0x1f) ) ^ 0x6547a98b;
		Tcon128_Piccolo[i] = ((unsigned long long)(temp & 0xff000000) >> 8) | ((unsigned long long)(temp & 0x00ff0000) << 8) | ((unsigned long long)(temp & 0x0000ff00) << 40) | ((unsigned long long)(temp & 0x000000ff) << 56);
	}

	/* open a pointer and create the file PICCOLOtables.h */
	ptr = fopen("../Piccolo/Piccolo_tables.h", "w");
	if(ptr == NULL)
	{
		printf("Unable to create file Piccolo_tables.h\n");
		return;
	}

	/* write T0 */
	fprintf(ptr, "unsigned int T0_Piccolo[256] = {");
	for(i = 0; i < 256; i++)
	{
		fprintf(ptr, "0x%04x", T0_Piccolo[i]);
		if(i == 255)
			fprintf(ptr, "};\n\n");
		else
			fprintf(ptr, ", ");
	}

	/* write T1 */
	fprintf(ptr, "unsigned int T1_Piccolo[256] = {");
	for(i = 0; i < 256; i++)
	{
		fprintf(ptr, "0x%04x", T1_Piccolo[i]);
		if(i == 255)
			fprintf(ptr, "};\n\n");
		else
			fprintf(ptr, ", ");
	}

	/* write T2 */
	fprintf(ptr, "unsigned long long T2_Piccolo[256] = {");
	for(i = 0; i < 256; i++)
	{
		fprintf(ptr, "0x%016llx", T2_Piccolo[i]);
		if(i == 255)
			fprintf(ptr, "};\n\n");
		else
			fprintf(ptr, ", ");
	}

	/* write T3 */
	fprintf(ptr, "unsigned long long T3_Piccolo[256] = {");
	for(i = 0; i < 256; i++)
	{
		fprintf(ptr, "0x%016llx", T3_Piccolo[i]);
		if(i == 255)
			fprintf(ptr, "};\n\n");
		else
			fprintf(ptr, ", ");
	}

	/* write T4 */
	fprintf(ptr, "unsigned long long T4_Piccolo[256] = {");
	for(i = 0; i < 256; i++)
	{
		fprintf(ptr, "0x%016llx", T4_Piccolo[i]);
		if(i == 255)
			fprintf(ptr, "};\n\n");
		else
			fprintf(ptr, ", ");
	}

	/* write T5 */
	fprintf(ptr, "unsigned long long T5_Piccolo[256] = {");
	for(i = 0; i < 256; i++)
	{
		fprintf(ptr, "0x%016llx", T5_Piccolo[i]);
		if(i == 255)
			fprintf(ptr, "};\n\n");
		else
			fprintf(ptr, ", ");
	}

	/* write Tcon80_Piccolo */
	fprintf(ptr, "unsigned long long Tcon80_Piccolo[25] = {");
	for(i = 0; i < 25; i++)
	{
		fprintf(ptr, "0x%016llx", Tcon80_Piccolo[i]);
		if(i == 24)
			fprintf(ptr, "};\n\n");
		else
			fprintf(ptr, ", ");
	}

	/* write Tcon128_Piccolo */
	fprintf(ptr, "unsigned long long Tcon128_Piccolo[31] = {");
	for(i = 0; i < 31; i++)
	{
		fprintf(ptr, "0x%016llx", Tcon128_Piccolo[i]);
		if(i == 30)
			fprintf(ptr, "};\n\n");
		else
			fprintf(ptr, ", ");
	}

	/* close the pointer */
	fclose(ptr);

	return;
}
