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
