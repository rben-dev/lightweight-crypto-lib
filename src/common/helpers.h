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
#define _GNU_SOURCE
#include <signal.h>
#include <dlfcn.h>

#define MAIN_INCLUDE
#include <common/basic_helpers.h>
#include <common/log.h>
#include <common/test_vectors.h>

#define MAX(x,y) ((x)>(y)?(x):(y))
#define MIN(x,y) ((x)<(y)?(x):(y))

/* Colors depending */
char* cipher_to_color(char* cipher, char* key_size){
	if(use_colors == 0){
		return ANSI_COLOR_NONE;
	}
	if(strcmp(cipher, "LED") == 0){
		if(strcmp(key_size, "64") == 0){
			return ANSI_COLOR_CYAN;
		}
		if(strcmp(key_size, "128") == 0){
			return ANSI_STYLE_INVERTED ANSI_COLOR_CYAN;
		}
	}
	if(strcmp(cipher, "PRESENT") == 0){
		if(strcmp(key_size, "80") == 0){
			return ANSI_COLOR_YELLOW;
		}
		if(strcmp(key_size, "128") == 0){
			return ANSI_STYLE_INVERTED ANSI_COLOR_YELLOW;
		}
	}
	if(strcmp(cipher, "Piccolo") == 0){
		if(strcmp(key_size, "80") == 0){
			return ANSI_COLOR_MAGENTA;
		}
		if(strcmp(key_size, "128") == 0){
			return ANSI_STYLE_INVERTED ANSI_COLOR_MAGENTA;
		}
	}
	return ANSI_COLOR_NONE;
}

char* type_to_color(char* type){
	if(use_colors == 0){
		return ANSI_COLOR_NONE;
	}
        if(strcmp(type, "table") == 0){
		return ANSI_COLOR_LGRAY;
	}
        if(strcmp(type, "vperm") == 0){
		return ANSI_COLOR_LBLUE;
	}
        if(strcmp(type, "bitslice8") == 0){
		return ANSI_COLOR_RED;
	}
        if(strcmp(type, "bitslice16") == 0){
		return ANSI_COLOR_RED;
	}
        if(strcmp(type, "bitslice32") == 0){
		return ANSI_COLOR_RED;
	}
	return ANSI_COLOR_NONE;
}

/* Pretty printing helper */
void hex_print(color col, background bg, style st, char* label, char* in, unsigned int length){
        unsigned int i;
        if(label != NULL){
                custom_printf(col, bg, st, "%s: ", label);
        }
        for(i=0; i < length; i++){
                custom_printf(col, bg, st, "%02x ", (unsigned char)(in[i]));
        }
        custom_printf(col, bg, st, "\n");
        return;
}

/* Randomize helper */
void randomize(u8* in, unsigned int size){
        unsigned int i;
        for(i=0; i < size; i++){
                in[i] = rand();
        }
        return;
}


unsigned char try_ssse3 = 0;
unsigned char try_avx = 0;
void catch_SIGILL(void){
	if(try_ssse3 == 1){
		printf("Sorry, but your CPU does not seem to support SSSE3 instructions!\n");
		printf("You will have to fall back on table based implementations ...\n");
		exit(-2);
	}
	if(try_avx == 1){
		printf("Sorry, but your CPU does not seem to support AVX instructions!\n");
		printf("You will have to fall back on non AVX implementations (vperm without AVX, bitslice or table based) ...\n");
		exit(-3);
	}
	printf("Unknown error: don't know what to do with the catched SIGILL!\n");
	exit(-1);
}

/* Check the compatibility of the current running inside the constructor */
__attribute__ ((constructor)) void check_CPU_features(void){
	/* Register the signal handled in case of signal */
	signal(SIGILL, (void*)catch_SIGILL);
	
#if defined(BITSLICE) || defined(VPERM)
	try_ssse3 = 1;
	/* In case of bitslice and vperm SSE, we need SSSE3 */
	asm (".intel_syntax noprefix");
	asm ("pshufb xmm0, xmm1");
        asm (".att_syntax noprefix");
	try_ssse3 = 2;
#endif

#if defined(AVX)
	try_avx = 1;
	/* In case of vperm AVX, we need AVX */
	asm (".intel_syntax noprefix");
	asm ("vpshufb xmm0, xmm1, xmm2");
        asm (".att_syntax noprefix");
	try_avx = 2;
#endif
	return;
}

#define SANITY_CHECK(cipher_, type_, parallelism_, key_size_) do {\
	if(sizeof(test_vectors ## cipher_ ## key_size_) % sizeof(u64) != 0){\
		custom_printf_error("There is an issue with the test vectors size ...\n");\
                exit(-1);\
	}\
	if((sizeof(test_vectors ## cipher_ ## key_size_)/sizeof(u64) != sizeof(keys ## key_size_ ## cipher_ ## key_size_)/(2*KEY ## key_size_))){\
		custom_printf_error("There is an issue with the test keys sizes ...\n");\
                exit(-1);\
	}\
	if((strcmp(tostr(cipher_), "Piccolo") != 0) && (strcmp(tostr(cipher_), "PRESENT") != 0) && (strcmp(tostr(cipher_), "LED") != 0)){\
                custom_printf_error("Unkown cipher name %s\n", tostr(cipher_));\
                exit(-1);\
	}\
	if((strcmp(tostr(type_), "table") != 0) && (strcmp(tostr(type_), "vperm") != 0) && (strcmp(tostr(type_), "bitslice8") != 0) && (strcmp(tostr(type_), "bitslice16") != 0) && (strcmp(tostr(type_), "bitslice32") != 0)){\
		custom_printf_error("Unkown implementation type %s\n", tostr(type_));\
		exit(-1);\
	}\
	if(strcmp(tostr(type_), "table") == 0){\
		if(parallelism_ != TABLE_P){\
			custom_printf_error("Wrong parallelism %d for implementation type %s\n", parallelism_, tostr(type_));\
			exit(-1);\
		}\
	}\
	if(strcmp(tostr(type_), "vperm") == 0){\
		if(parallelism_ != VPERM_P){\
			custom_printf_error("Wrong parallelism %d for implementation type %s\n", parallelism_, tostr(type_));\
			exit(-1);\
		}\
	}\
        if((strcmp(tostr(type_), "bitslice8") == 0) || (strcmp(tostr(type_), "bitslice16") == 0) || (strcmp(tostr(type_), "bitslice32") == 0)){\
                if((parallelism_ != BITSLICE8_P) && (parallelism_ != BITSLICE16_P) && (parallelism_ != BITSLICE32_P)){\
                        custom_printf_error("Wrong parallelism %d for implementation type %s\n", parallelism_, tostr(type_));\
                        exit(-1);\
                }\
        }\
	if((strcmp(tostr(cipher_), "Piccolo") == 0) || (strcmp(tostr(cipher_), "PRESENT") == 0)){\
		if((key_size_ != 80) && (key_size_ != 128)){\
                      	custom_printf_error("Wrong key size %d for cipher %s\n", key_size_, tostr(cipher_));\
                        exit(-1);\
		}\
	}\
        if(strcmp(tostr(cipher_), "LED") == 0){\
                if((key_size_ != 64) && (key_size_ != 128)){\
                        custom_printf_error("Wrong key size %d for cipher %s\n", key_size_, tostr(cipher_));\
                        exit(-1);\
                }\
        }\
} while(0);

unsigned long long samples = SAMPLES;
/* Measuring performance */
#ifdef MEASURE_PERF														
#define CHECK_PERF(cipher_, type_, parallelism_, key_size_) do {\
	SANITY_CHECK(cipher_, type_, parallelism_, key_size_);\
	u64 plaintext_in[parallelism_];\
        u16 keys_in[parallelism_][KEY ## key_size_];\
        u64 ciphertext_out[parallelism_];\
	unsigned long long real_samples = samples/parallelism_;\
        double key_schedule_average = 0;\
        double encrypt_average = 0;\
        unsigned int i;\
        for(i=0; i<real_samples; i++){\
                randomize((u8*)plaintext_in, sizeof(plaintext_in));\
                randomize((u8*)keys_in, sizeof(keys_in));\
		cipher_ ## key_size_ ## type_ ## _cipher(plaintext_in, (const u16 (*)[KEY ## key_size_])keys_in, ciphertext_out);\
                key_schedule_average += (double)(*pkey_schedule_end -  *pkey_schedule_start);\
                encrypt_average += (double)(*pencrypt_end - *pencrypt_start);\
        }\
        key_schedule_average = key_schedule_average / (double)(sizeof(plaintext_in) * real_samples);\
	encrypt_average = encrypt_average / (double)(sizeof(plaintext_in) * real_samples);\
	if(use_colors == 1){\
        	custom_printf(nocolor, nobg, underlined, "=>  PERFORMANCE RESULTS for");\
		custom_printf(nocolor, nobg, nostyle, " %s%s%s"ANSI_RESET" %s%s\n"ANSI_RESET, cipher_to_color(tostr(cipher_), tostr(key_size_)), tostr(cipher_), tostr(key_size_), type_to_color(tostr(type_)), tostr(type_));\
        	custom_printf(nocolor, nobg, nostyle, "=>  The block cipher runs in "ANSI_STYLE_DIM ANSI_COLOR_GREEN"%f"ANSI_RESET" cycles/byte ("ANSI_STYLE_DIM ANSI_COLOR_GREEN"%llu"ANSI_RESET" samples)\n", (float)(key_schedule_average + encrypt_average), samples);\
	        custom_printf(nocolor, nobg, nostyle, "=>    |- "ANSI_STYLE_UNDERLINED"Key schedule"ANSI_RESET" part is "ANSI_STYLE_DIM ANSI_COLOR_GREEN"%f"ANSI_RESET" cycles/byte\n", (float)key_schedule_average);\
        	custom_printf(nocolor, nobg, nostyle, "=>    |- "ANSI_STYLE_UNDERLINED"Encryption"ANSI_RESET" part is "ANSI_STYLE_DIM ANSI_COLOR_GREEN"%f"ANSI_RESET" cycles/byte\n", (float)encrypt_average);\
		if(strcmp(tostr(type_), "vperm") == 0){\
		        custom_printf(nocolor, nobg, nostyle, "=>  Warning: minor realignment overheads are not measured\n");\
		}\
	}\
	else{\
        	custom_printf(nocolor, nobg, underlined, "=>  PERFORMANCE RESULTS for");\
		custom_printf(nocolor, nobg, nostyle, " %s%s%s"" %s%s\n", cipher_to_color(tostr(cipher_), tostr(key_size_)), tostr(cipher_), tostr(key_size_), type_to_color(tostr(type_)), tostr(type_));\
        	custom_printf(nocolor, nobg, nostyle, "=>  The block cipher runs in ""%f"" cycles/byte (""%llu"" samples)\n", (float)(key_schedule_average + encrypt_average), samples);\
	        custom_printf(nocolor, nobg, nostyle, "=>    |- ""Key schedule"" part is ""%f"" cycles/byte\n", (float)key_schedule_average);\
        	custom_printf(nocolor, nobg, nostyle, "=>    |- ""Encryption"" part is ""%f"" cycles/byte\n", (float)encrypt_average);\
		if(strcmp(tostr(type_), "vperm") == 0){\
	        	custom_printf(nocolor, nobg, nostyle, "=>  Warning: minor realignment overheads are not measured\n");\
		}\
	}\
} while(0);
#else
#define CHECK_PERF(cipher_, type_, parallelism_, key_size_) do {\
} while(0);
#endif																

#ifdef TEST_VECTORS
/* Checking the test vectors */
#define CHECK_VECTORS(cipher_, type_, parallelism_, key_size_) do {\
	SANITY_CHECK(cipher_, type_, parallelism_, key_size_);\
	u64 plaintext_in[parallelism_];\
        u16 keys_in[parallelism_][KEY ## key_size_];\
        u64 ciphertext_out[parallelism_];\
        unsigned int i, j, k;\
	unsigned int to_process =  sizeof(test_vectors ## cipher_ ## key_size_)/(parallelism_*sizeof(u64));\
	if(sizeof(test_vectors ## cipher_ ## key_size_)%(parallelism_*sizeof(u64)) != 0){\
		to_process++;\
	}\
	k = 0;\
	for(i=0; i < to_process; i++){\
		memset(plaintext_in, 0, sizeof(plaintext_in));\
		memset(keys_in, 0, sizeof(keys_in));\
		if((i+1 == to_process) && (sizeof(test_vectors ## cipher_ ## key_size_)%(parallelism_*sizeof(u64)) != 0)){\
			memcpy(plaintext_in, (u8*)test_vectors ## cipher_ ## key_size_ + i*parallelism_*sizeof(u64), sizeof(test_vectors ## cipher_ ## key_size_)%(parallelism_*sizeof(u64)));\
			memcpy(keys_in, (u8*)keys ## key_size_ ## cipher_ ## key_size_ + i*parallelism_*(key_size_/8), sizeof(keys ## key_size_ ## cipher_ ## key_size_)%(parallelism_*(key_size_/8)));\
		}\
		else{\
			memcpy(plaintext_in, (u8*)test_vectors ## cipher_ ## key_size_ + i*parallelism_*sizeof(u64), parallelism_*sizeof(u64));\
			memcpy(keys_in, (u8*)keys ## key_size_ ## cipher_ ## key_size_ + i*parallelism_*(key_size_/8), parallelism_*(key_size_/8));\
		}\
		cipher_ ## key_size_ ## type_ ## _cipher(plaintext_in, (const u16 (*)[KEY ## key_size_])keys_in, ciphertext_out);\
       		custom_printf(nocolor, nobg, nostyle, "########################################\n");\
		if(use_colors == 1){\
	       		custom_printf(nocolor, nobg, nostyle, "Cipher %s%s%s"ANSI_RESET", Type: %s%s"ANSI_RESET", Parallelism: %s%s"ANSI_RESET" blocks\n", cipher_to_color(tostr(cipher_), tostr(key_size_)), tostr(cipher_), tostr(key_size_), type_to_color(tostr(type_)), tostr(type_), type_to_color(tostr(type_)), tostr(parallelism_));\
		}\
		else{\
	       		custom_printf(nocolor, nobg, nostyle, "Cipher %s%s%s"", Type: %s%s"", Parallelism: %s%s"" blocks\n", cipher_to_color(tostr(cipher_), tostr(key_size_)), tostr(cipher_), tostr(key_size_), type_to_color(tostr(type_)), tostr(type_), type_to_color(tostr(type_)), tostr(parallelism_));\
		}\
        	for(j = 0; j < parallelism_; j++){\
			/* Break if we have encrypted more values than necessary */\
			if((i*parallelism_ + j) >= (sizeof(test_vectors ## cipher_ ## key_size_)/sizeof(u64))){\
				printf("Not printing the other blocks (fillers due to parallelism)\n");\
				break;\
			}\
                	hex_print(nocolor, nobg, dim, "Plaintext is   ", ((char*)plaintext_in) + j * sizeof(u64), sizeof(u64));\
                	hex_print(nocolor, nobg, nostyle, "Master key is  ", ((char*)keys_in) + j * KEY ## key_size_ * sizeof(u16), KEY ## key_size_ * sizeof(u16));\
                	hex_print(nocolor, nobg, bold, "Ciphertext is  ", ((char*)ciphertext_out) + j * sizeof(u64), sizeof(u64));\
                	printf("----------------------------------------\n");\
			if(memcmp(&(ciphertext_out[j]), &(test_vectors ## cipher_ ## key_size_ ## results[k]), sizeof(u64)) != 0){\
				custom_printf_error("bad test vector result for %s%s %s\n", tostr(cipher_), tostr(key_size_), tostr(type_));\
                		hex_print(red, nobg, bold, "Got            ", ((char*)ciphertext_out) + j * sizeof(u64), sizeof(u64));\
                		hex_print(red, nobg, bold, "Instead of     ", ((char*)test_vectors ## cipher_ ## key_size_ ## results) + k * sizeof(u64), sizeof(u64));\
				exit(-1);\
			}\
			k++;\
        	}\
	}\
} while(0);
#else
#define CHECK_VECTORS(cipher_, type_, parallelism_, key_size_) do {\
} while(0);
#endif

u8 check_vectors = 0;
u8 check_perf = 0;
/* Check test vectors and performance */
#define CHECK(cipher_, type_, parallelism_, key_size_) do {\
	if(check_vectors == 1){\
		CHECK_VECTORS(cipher_, type_, parallelism_, key_size_);\
	}\
	if(check_perf == 1){\
		CHECK_PERF(cipher_, type_, parallelism_, key_size_);\
	}\
} while(0);

/* Declaration of the exported functions */
#ifdef TABLE
#ifdef LED64
void (*LED64table_key_schedule)(const u8* masterKey64, u8* roundKeys64);
void (*LED64table_core)(const u8* plaintext, const u8* roundKeys64, u8* ciphertext);
void (*LED64table_cipher)(const u64 plaintext_in[TABLE_P], const u16 keys_in[TABLE_P][KEY64], u64 ciphertext_out[TABLE_P]);
#endif
#ifdef LED128
void (*LED128table_key_schedule)(const u8* masterKey128, u8* roundKeys128);
void (*LED128table_core)(const u8* plaintext, const u8* roundKeys128, u8* ciphertext);
void (*LED128table_cipher)(const u64 plaintext_in[TABLE_P], const u16 keys_in[TABLE_P][KEY128], u64 ciphertext_out[TABLE_P]);
#endif
#ifdef PRESENT80
void (*PRESENT80table_key_schedule)(const u8* masterKey80, u8* roundKeys80);
void (*PRESENT80table_core)(const u8* plaintext, const u8* roundKeys80, u8* ciphertext);
void (*PRESENT80table_cipher)(const u64 plaintext_in[TABLE_P], const u16 keys_in[TABLE_P][KEY80], u64 ciphertext_out[TABLE_P]);
#endif
#ifdef PRESENT128
void (*PRESENT128table_key_schedule)(const u8* masterKey128, u8* roundKeys128);
void (*PRESENT128table_core)(const u8* plaintext, const u8* roundKeys128, u8* ciphertext);
void (*PRESENT128table_cipher)(const u64 plaintext_in[TABLE_P], const u16 keys_in[TABLE_P][KEY128], u64 ciphertext_out[TABLE_P]);
#endif
#ifdef Piccolo80
void (*Piccolo80table_key_schedule)(const u8* masterKey80, u8* roundKeys80);
void (*Piccolo80table_core)(const u8* plaintext, const u8* roundKeys80, u8* ciphertext);
void (*Piccolo80table_cipher)(const u64 plaintext_in[TABLE_P], const u16 keys_in[TABLE_P][KEY80], u64 ciphertext_out[TABLE_P]);
#endif
#ifdef Piccolo128
void (*Piccolo128table_key_schedule)(const u8* masterKey128, u8* roundKeys128);
void (*Piccolo128table_core)(const u8* plaintext, const u8* roundKeys128, u8* ciphertext);
void (*Piccolo128table_cipher)(const u64 plaintext_in[TABLE_P], const u16 keys_in[TABLE_P][KEY128], u64 ciphertext_out[TABLE_P]);
#endif
#endif

#ifdef VPERM
#ifdef LED64
void (*LED64vperm_key_schedule)(const u8* masterKey, u8* roundKeys);
void (*LED64vperm_core)(const u8* message, const u8* subkeys, u8* ciphertext);
void (*LED64vperm_cipher)(const u64 plaintext_in[VPERM_P], const u16 keys_in[VPERM_P][KEY64], u64 ciphertext_out[VPERM_P]);
#endif
#ifdef LED128
void (*LED128vperm_key_schedule)(const u8* masterKey, u8* roundKeys);
void (*LED128vperm_core)(const u8* message,  const u8* subkeys, u8* ciphertext);
void (*LED128vperm_cipher)(const u64 plaintext_in[VPERM_P], const u16 keys_in[VPERM_P][KEY128], u64 ciphertext_out[VPERM_P]);
#endif
#ifdef PRESENT80
void (*PRESENT80vperm_key_schedule)(const u8* masterKey, u8* roundKeys);
void (*PRESENT80vperm_core)(const u8* message, const u8* subkeys, u8* ciphertext);
void (*PRESENT80vperm_cipher)(const u64 plaintext_in[VPERM_P], const u16 keys_in[VPERM_P][KEY80], u64 ciphertext_out[VPERM_P]);
#endif
#ifdef PRESENT128
void (*PRESENT128vperm_key_schedule)(const u8* masterKey, u8* roundKeys);
void (*PRESENT128vperm_core)(const u8* message, const u8* subkeys, u8* ciphertext);
void (*PRESENT128vperm_cipher)(const u64 plaintext_in[VPERM_P], const u16 keys_in[VPERM_P][KEY128], u64 ciphertext_out[VPERM_P]);
#endif
#ifdef Piccolo80
void (*Piccolo80vperm_key_schedule)(const u8* masterKey, u8* roundKeys);
void (*Piccolo80vperm_core)(const u8* message, const u8* subkeys, u8* ciphertext);
void (*Piccolo80vperm_cipher)(const u64 plaintext_in[VPERM_P], const u16 keys_in[VPERM_P][KEY80], u64 ciphertext_out[VPERM_P]); 
#endif
#ifdef Piccolo128
void (*Piccolo128vperm_key_schedule)(const u8* masterKey, u8* roundKeys);
void (*Piccolo128vperm_core)(const u8* message, const u8* subkeys, u8* ciphertext);
void (*Piccolo128vperm_cipher)(const u64 plaintext_in[VPERM_P], const u16 keys_in[VPERM_P][KEY128], u64 ciphertext_out[VPERM_P]);
#endif
#endif


#ifdef BITSLICE
#ifdef LED64
void (*LED64bitslice16_key_schedule)(const u8* masterKey, u8* roundKeys);
void (*LED64bitslice16_core)(const u8* message, const u8* subkeys, u8* ciphertext);
void (*LED64bitslice16_cipher)(const u64 plaintext[BITSLICE16_P], const u16 key[BITSLICE16_P][KEY64], u64 ciphertext[BITSLICE16_P]);
void (*LED64bitslice32_key_schedule)(const u8* masterKey, u8* roundKeys);
void (*LED64bitslice32_core)(const u8* message, const u8* subkeys, u8* ciphertext);
void (*LED64bitslice32_cipher)(const u64 plaintext[BITSLICE16_P], const u16 key[BITSLICE16_P][KEY64], u64 ciphertext[BITSLICE16_P]);
#endif
#ifdef LED128
void (*LED128bitslice16_key_schedule)(const u8* masterKey, u8* roundKeys);
void (*LED128bitslice16_core)(const u8* message, const u8* subkeys, u8* ciphertext);
void (*LED128bitslice16_cipher)(const u64 plaintext[BITSLICE16_P], const u16 key[BITSLICE16_P][KEY128], u64 ciphertext[BITSLICE16_P]);
void (*LED128bitslice32_key_schedule)(const u8* masterKey, u8* roundKeys);
void (*LED128bitslice32_core)(const u8* message, const u8* subkeys, u8* ciphertext);
void (*LED128bitslice32_cipher)(const u64 plaintext[BITSLICE32_P], const u16 key[BITSLICE32_P][KEY128], u64 ciphertext[BITSLICE32_P]);
#endif
#ifdef PRESENT80
void (*PRESENT80bitslice8_key_schedule)(const u8* masterKey, u8* roundKeys);
void (*PRESENT80bitslice8_core)(const u8* message, const u8* subkeys, u8* ciphertext);
void (*PRESENT80bitslice8_cipher)(const u64 plaintext[BITSLICE8_P], const u16 key[BITSLICE8_P][KEY80], u64 ciphertext[BITSLICE8_P]);
void (*PRESENT80bitslice8_cipher_)(const u64 plaintext[BITSLICE8_P], const u16 key[BITSLICE8_P][KEY80], u64 ciphertext[BITSLICE8_P]);
void (*PRESENT80bitslice16_key_schedule)(const u8* masterKey, u8* roundKeys);
void (*PRESENT80bitslice16_core)(const u8* message, const u8* subkeys, u8* ciphertext);
void (*PRESENT80bitslice16_cipher)(const u64 plaintext[BITSLICE16_P], const u16 key[BITSLICE16_P][KEY80], u64 ciphertext[BITSLICE16_P]);
void (*PRESENT80bitslice16_cipher_)(const u64 plaintext[BITSLICE16_P], const u16 key[BITSLICE16_P][KEY80], u64 ciphertext[BITSLICE16_P]);
#endif
#ifdef PRESENT128
void (*PRESENT128bitslice8_key_schedule)(const u8* masterKey, u8* roundKeys);
void (*PRESENT128bitslice8_core)(const u8* message, const u8* subkeys, u8* ciphertext);
void (*PRESENT128bitslice8_cipher)(const u64 plaintext[BITSLICE8_P], const u16 key[BITSLICE8_P][KEY128], u64 ciphertext[BITSLICE8_P]);
void (*PRESENT128bitslice8_cipher_)(const u64 plaintext[BITSLICE8_P], const u16 key[BITSLICE8_P][KEY128], u64 ciphertext[BITSLICE8_P]);
void (*PRESENT128bitslice16_key_schedule)(const u8* masterKey, u8* roundKeys);
void (*PRESENT128bitslice16_core)(const u8* message, const u8* subkeys, u8* ciphertext);
void (*PRESENT128bitslice16_cipher)(const u64 plaintext[BITSLICE16_P], const u16 key[BITSLICE16_P][KEY128], u64 ciphertext[BITSLICE16_P]);
void (*PRESENT128bitslice16_cipher_)(const u64 plaintext[BITSLICE16_P], const u16 key[BITSLICE16_P][KEY128], u64 ciphertext[BITSLICE16_P]);
#endif
#ifdef Piccolo80
void (*Piccolo80bitslice16_key_schedule)(const u8* masterKey, u8* roundKeys);
void (*Piccolo80bitslice16_core)(const u8* message, const u8* subkeys, u8* ciphertext);
void (*Piccolo80bitslice16_cipher)(const u64 plaintext[BITSLICE16_P], const u16 masterkeys[BITSLICE16_P][KEY80], u64 ciphertext[BITSLICE16_P]);
#endif
#ifdef Piccolo128
void (*Piccolo128bitslice16_key_schedule)(const u8* masterKey, u8* roundKeys);
void (*Piccolo128bitslice16_core)(const u8* message, const u8* subkeys, u8* ciphertext);
void (*Piccolo128bitslice16_cipher)(const u64 plaintext[BITSLICE16_P], const u16 masterkeys[BITSLICE16_P][KEY128], u64 ciphertext[BITSLICE16_P]);
#endif
#endif

#ifdef MEASURE_PERF
u64* pkey_schedule_start;
u64* pkey_schedule_end;
u64* pencrypt_start;
u64* pencrypt_end;
#endif

/*** The loading function ***/
void load_ciphers_symbols(void* handle){
#ifdef TABLE
#ifdef LED64
	LED64table_key_schedule = dlsym(handle, "LED64table_key_schedule");
	LED64table_cipher = dlsym(handle, "LED64table_cipher");
	LED64table_core = dlsym(handle, "LED64table_core");
#endif
#ifdef LED128
	LED128table_key_schedule = dlsym(handle, "LED128table_key_schedule");
	LED128table_cipher = dlsym(handle, "LED128table_cipher");
	LED128table_core = dlsym(handle, "LED128table_core");
#endif
#ifdef PRESENT80
	PRESENT80table_key_schedule = dlsym(handle, "PRESENT80table_key_schedule");
	PRESENT80table_core = dlsym(handle, "PRESENT80table_core");
	PRESENT80table_cipher = dlsym(handle, "PRESENT80table_cipher");
#endif
#ifdef PRESENT128
	PRESENT128table_key_schedule = dlsym(handle, "PRESENT128table_key_schedule");
	PRESENT128table_core = dlsym(handle, "PRESENT128table_core");
	PRESENT128table_cipher = dlsym(handle, "PRESENT128table_cipher");
#endif
#ifdef Piccolo80
	Piccolo80table_key_schedule = dlsym(handle, "Piccolo80table_key_schedule");
	Piccolo80table_core = dlsym(handle, "Piccolo80table_core");
	Piccolo80table_cipher = dlsym(handle, "Piccolo80table_cipher");
#endif
#ifdef Piccolo128
	Piccolo128table_key_schedule = dlsym(handle, "Piccolo128table_key_schedule");
	Piccolo128table_core = dlsym(handle, "Piccolo128table_core");
	Piccolo128table_cipher = dlsym(handle, "Piccolo128table_cipher");
#endif
#endif
#ifdef VPERM
#ifdef LED64
	LED64vperm_key_schedule = dlsym(handle, "LED64vperm_key_schedule");
 	LED64vperm_core = dlsym(handle, "LED64vperm_core");
	LED64vperm_cipher = dlsym(handle, "LED64vperm_cipher");
#endif
#ifdef LED128
	LED128vperm_key_schedule = dlsym(handle, "LED128vperm_key_schedule");
 	LED128vperm_core = dlsym(handle, "LED128vperm_core");
	LED128vperm_cipher = dlsym(handle, "LED128vperm_cipher");
#endif
#ifdef PRESENT80
 	PRESENT80vperm_key_schedule = dlsym(handle, "PRESENT80vperm_key_schedule");
 	PRESENT80vperm_core = dlsym(handle, "PRESENT80vperm_core");
	PRESENT80vperm_cipher = dlsym(handle, "PRESENT80vperm_cipher");
#endif
#ifdef PRESENT128
 	PRESENT128vperm_key_schedule = dlsym(handle, "PRESENT128vperm_key_schedule");
 	PRESENT128vperm_core = dlsym(handle, "PRESENT128vperm_core");
	PRESENT128vperm_cipher = dlsym(handle, "PRESENT128vperm_cipher");
#endif
#ifdef Piccolo80
 	Piccolo80vperm_key_schedule = dlsym(handle, "Piccolo80vperm_key_schedule");
 	Piccolo80vperm_core = dlsym(handle, "Piccolo80vperm_core");
	Piccolo80vperm_cipher = dlsym(handle, "Piccolo80vperm_cipher");
#endif
#ifdef Piccolo128
 	Piccolo128vperm_key_schedule = dlsym(handle, "Piccolo128vperm_key_schedule");
 	Piccolo128vperm_core = dlsym(handle, "Piccolo128vperm_core");
	Piccolo128vperm_cipher = dlsym(handle, "Piccolo128vperm_cipher");
#endif
#endif
#ifdef BITSLICE
#ifdef LED64
	LED64bitslice16_key_schedule = dlsym(handle, "LED64bitslice16_key_schedule");
	LED64bitslice16_core = dlsym(handle, "LED64bitslice16_core");
	LED64bitslice16_cipher = dlsym(handle, "LED64bitslice16_cipher");
	LED64bitslice32_key_schedule = dlsym(handle, "LED64bitslice32_key_schedule");
	LED64bitslice32_core = dlsym(handle, "LED64bitslice32_core");
	LED64bitslice32_cipher = dlsym(handle, "LED64bitslice32_cipher");
#endif
#ifdef LED128
	LED128bitslice16_key_schedule = dlsym(handle, "LED128bitslice16_key_schedule");
	LED128bitslice16_core = dlsym(handle, "LED128bitslice16_core");
	LED128bitslice16_cipher = dlsym(handle, "LED128bitslice16_cipher");
	LED128bitslice32_key_schedule = dlsym(handle, "LED128bitslice32_key_schedule");
	LED128bitslice32_core = dlsym(handle, "LED128bitslice32_core");
	LED128bitslice32_cipher = dlsym(handle, "LED128bitslice32_cipher");
#endif
#ifdef PRESENT80
	PRESENT80bitslice8_key_schedule = dlsym(handle, "PRESENT80bitslice8_key_schedule");
	PRESENT80bitslice8_core = dlsym(handle, "PRESENT80bitslice8_core");
	PRESENT80bitslice8_cipher = dlsym(handle, "PRESENT80bitslice8_cipher");
	PRESENT80bitslice8_cipher_ = dlsym(handle, "PRESENT80bitslice8_cipher_");
	PRESENT80bitslice16_key_schedule = dlsym(handle, "PRESENT80bitslice16_key_schedule");
	PRESENT80bitslice16_core = dlsym(handle, "PRESENT80bitslice16_core");
	PRESENT80bitslice16_cipher = dlsym(handle, "PRESENT80bitslice16_cipher");
	PRESENT80bitslice16_cipher_ = dlsym(handle, "PRESENT80bitslice16_cipher_");
#endif
#ifdef PRESENT128
	PRESENT128bitslice8_key_schedule = dlsym(handle, "PRESENT128bitslice8_key_schedule");
	PRESENT128bitslice8_core = dlsym(handle, "PRESENT128bitslice8_core");
	PRESENT128bitslice8_cipher = dlsym(handle, "PRESENT128bitslice8_cipher");
	PRESENT128bitslice8_cipher_ = dlsym(handle, "PRESENT128bitslice8_cipher_");
	PRESENT128bitslice16_key_schedule = dlsym(handle, "PRESENT128bitslice16_key_schedule");
	PRESENT128bitslice16_core = dlsym(handle, "PRESENT128bitslice16_core");
	PRESENT128bitslice16_cipher = dlsym(handle, "PRESENT128bitslice16_cipher");
	PRESENT128bitslice16_cipher_ = dlsym(handle, "PRESENT128bitslice16_cipher_");
#endif
#ifdef Piccolo80
	Piccolo80bitslice16_key_schedule = dlsym(handle, "Piccolo80bitslice16_key_schedule");
	Piccolo80bitslice16_core = dlsym(handle, "Piccolo80bitslice16_core");
	Piccolo80bitslice16_cipher = dlsym(handle, "Piccolo80bitslice16_cipher");
#endif
#ifdef Piccolo128
	Piccolo128bitslice16_key_schedule = dlsym(handle, "Piccolo128bitslice16_key_schedule");
	Piccolo128bitslice16_core = dlsym(handle, "Piccolo128bitslice16_core");
	Piccolo128bitslice16_cipher = dlsym(handle, "Piccolo128bitslice16_cipher");
#endif
#endif
#ifdef MEASURE_PERF
	pkey_schedule_start = dlsym(handle, "key_schedule_start");
	pkey_schedule_end = dlsym(handle, "key_schedule_end");
	pencrypt_start = dlsym(handle, "encrypt_start");
	pencrypt_end = dlsym(handle, "encrypt_end");
#endif
	return;
}
