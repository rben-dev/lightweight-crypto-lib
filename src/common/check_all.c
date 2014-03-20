/*------------------------ CeCILL-B HEADER ------------------------------------
    Copyright ANSSI and NTU (2014)
    Contributors:
    Ryad BENADJILA [ryad.benadjila@ssi.gouv.fr] and
    Jian GUO [ntu.guo@gmail.com] and
    Victor LOMNE [victor.lomne@ssi.gouv.fr] and
    Thomas Peyrin [thomas.peyrin@gmail.com]

    This software is a computer program whose purpose is to implement
    lightweight block ciphers with different optimizations for the x86
    platform. Three algorithms have been implemented: PRESENT, LED and 
    Piccolo. Three techniques have been explored: table based 
    implementations, vperm (for vector permutation) and bitslice 
    implementations. For more details, please refer to the SAC 2013
    paper:
    http://eprint.iacr.org/2013/445
    as we as the documentation of the project.

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
    File:    src/common/check_all.c

-------------------------- CeCILL-B HEADER ----------------------------------*/
#include <common/helpers.h>

#define _NONE 			0

#define _LED64	 	(0x1 << 0)
#define _LED128		(0x1 << 1)
#define _PRESENT80	(0x1 << 2)
#define _PRESENT128	(0x1 << 3)
#define _Piccolo80      (0x1 << 4)
#define _Piccolo128     (0x1 << 5)

#define _TABLE          (0x1 << 0)
#define _VPERM          (0x1 << 1)
#define _BITSLICE8      (0x1 << 2)
#define _BITSLICE16     (0x1 << 3)
#define _BITSLICE32     (0x1 << 4)

#define CIPHER_TYPES_NUM	6

#define NOREEXECUTE		0
#define REEXECUTE		1

typedef void (*ExecuteCheck)(void);

#define get_bit(x, pos) ((x >> pos) & 0x1)

/* The table of available implementations */
typedef struct ciphers_ {
	int cipher;
	int available_implementations;
	ExecuteCheck checking_functions[CIPHER_TYPES_NUM];
} ciphers;

#define DO_CHECK(cipher_, type_, parallelism_, key_size_) do_check_ ## cipher_ ## key_size_ ## type_ 
#define ERROR_NOT_DEFINED(type_) warning_not_defined_ ## type_ 

void do_check_LED64table(void);
void do_check_LED64vperm(void);
void do_check_LED64bitslice16(void);
void do_check_LED64bitslice32(void);

void do_check_LED128table(void);
void do_check_LED128vperm(void);
void do_check_LED128bitslice16(void);
void do_check_LED128bitslice32(void);


void do_check_PRESENT80table(void);
void do_check_PRESENT80vperm(void);
void do_check_PRESENT80bitslice8(void);
void do_check_PRESENT80bitslice16(void);

void do_check_PRESENT128table(void);
void do_check_PRESENT128vperm(void);
void do_check_PRESENT128bitslice8(void);
void do_check_PRESENT128bitslice16(void);

void do_check_Piccolo80table(void);
void do_check_Piccolo80vperm(void);
void do_check_Piccolo80bitslice16(void);

void do_check_Piccolo128table(void);
void do_check_Piccolo128vperm(void);
void do_check_Piccolo128bitslice16(void);


void warning_not_defined_led64(void);
void warning_not_defined_led128(void);
void warning_not_defined_present80(void);
void warning_not_defined_present128(void);
void warning_not_defined_piccolo80(void);
void warning_not_defined_piccolo128(void);
void warning_not_defined_table(void);
void warning_not_defined_vperm(void);
void warning_not_defined_bitslice8(void);
void warning_not_defined_bitslice16(void);
void warning_not_defined_bitslice32(void);


/****** LED64 ***/
#ifdef LED64
#ifdef TABLE
#define LED64_TABLE_CHECK DO_CHECK(LED, table, TABLE_P, 64) 
#else
#define LED64_TABLE_CHECK ERROR_NOT_DEFINED(table) 
#endif
#ifdef VPERM
#define LED64_VPERM_CHECK DO_CHECK(LED, vperm, VPERM_P, 64) 
#else
#define LED64_VPERM_CHECK ERROR_NOT_DEFINED(vperm) 
#endif
#ifdef BITSLICE
#define LED64_BITSLICE16_CHECK DO_CHECK(LED, bitslice16, BITSLICE16_P, 64) 
#define LED64_BITSLICE32_CHECK DO_CHECK(LED, bitslice32, BITSLICE32_P, 64) 
#else
#define LED64_BITSLICE16_CHECK ERROR_NOT_DEFINED(bitslice16) 
#define LED64_BITSLICE32_CHECK ERROR_NOT_DEFINED(bitslice32) 
#endif
#else
#define LED64_TABLE_CHECK ERROR_NOT_DEFINED(led64) 
#define LED64_VPERM_CHECK ERROR_NOT_DEFINED(led64) 
#define LED64_BITSLICE16_CHECK ERROR_NOT_DEFINED(led64) 
#define LED64_BITSLICE32_CHECK ERROR_NOT_DEFINED(led64) 
#endif
/****** LED128 ***/
#ifdef LED128
#ifdef TABLE
#define LED128_TABLE_CHECK DO_CHECK(LED, table, TABLE_P, 128) 
#else
#define LED128_TABLE_CHECK ERROR_NOT_DEFINED(table)
#endif
#ifdef VPERM
#define LED128_VPERM_CHECK DO_CHECK(LED, vperm, VPERM_P, 128) 
#else
#define LED128_VPERM_CHECK ERROR_NOT_DEFINED(vperm)
#endif
#ifdef BITSLICE
#define LED128_BITSLICE16_CHECK DO_CHECK(LED, bitslice16, BITSLICE16_P, 128) 
#define LED128_BITSLICE32_CHECK DO_CHECK(LED, bitslice32, BITSLICE32_P, 128) 
#else
#define LED128_BITSLICE16_CHECK ERROR_NOT_DEFINED(bitslice16)
#define LED128_BITSLICE32_CHECK ERROR_NOT_DEFINED(bitslice32)
#endif
#else
#define LED128_TABLE_CHECK ERROR_NOT_DEFINED(led128) 
#define LED128_VPERM_CHECK ERROR_NOT_DEFINED(led128) 
#define LED128_BITSLICE16_CHECK ERROR_NOT_DEFINED(led128) 
#define LED128_BITSLICE32_CHECK ERROR_NOT_DEFINED(led128) 
#endif
/****** PRESENT80 ***/
#ifdef PRESENT80
#ifdef TABLE
#define PRESENT80_TABLE_CHECK DO_CHECK(PRESENT, table, TABLE_P, 80) 
#else
#define PRESENT80_TABLE_CHECK ERROR_NOT_DEFINED(table)
#endif
#ifdef VPERM
#define PRESENT80_VPERM_CHECK DO_CHECK(PRESENT, vperm, VPERM_P, 80) 
#else
#define PRESENT80_VPERM_CHECK ERROR_NOT_DEFINED(vperm)
#endif
#ifdef BITSLICE
#define PRESENT80_BITSLICE8_CHECK DO_CHECK(PRESENT, bitslice8, BITSLICE8_P, 80) 
#define PRESENT80_BITSLICE16_CHECK DO_CHECK(PRESENT, bitslice16, BITSLICE16_P, 80) 
#else
#define PRESENT80_BITSLICE8_CHECK ERROR_NOT_DEFINED(bitslice8)
#define PRESENT80_BITSLICE16_CHECK ERROR_NOT_DEFINED(bitslice16)
#endif
#else
#define PRESENT80_TABLE_CHECK ERROR_NOT_DEFINED(present80) 
#define PRESENT80_VPERM_CHECK ERROR_NOT_DEFINED(present80) 
#define PRESENT80_BITSLICE8_CHECK ERROR_NOT_DEFINED(present80) 
#define PRESENT80_BITSLICE16_CHECK ERROR_NOT_DEFINED(present80) 
#endif
/****** PRESENT128 ***/
#ifdef PRESENT128
#ifdef TABLE
#define PRESENT128_TABLE_CHECK DO_CHECK(PRESENT, table, TABLE_P, 128)
#else
#define PRESENT128_TABLE_CHECK ERROR_NOT_DEFINED(table)
#endif
#ifdef VPERM
#define PRESENT128_VPERM_CHECK DO_CHECK(PRESENT, vperm, VPERM_P, 128)
#else
#define PRESENT128_VPERM_CHECK ERROR_NOT_DEFINED(vperm)
#endif
#ifdef BITSLICE
#define PRESENT128_BITSLICE8_CHECK DO_CHECK(PRESENT, bitslice8, BITSLICE8_P, 128) 
#define PRESENT128_BITSLICE16_CHECK DO_CHECK(PRESENT, bitslice16, BITSLICE16_P, 128) 
#else
#define PRESENT128_BITSLICE8_CHECK ERROR_NOT_DEFINED(bitslice8)
#define PRESENT128_BITSLICE16_CHECK ERROR_NOT_DEFINED(bitslice16)
#endif
#else
#define PRESENT128_TABLE_CHECK ERROR_NOT_DEFINED(present128) 
#define PRESENT128_VPERM_CHECK ERROR_NOT_DEFINED(present128) 
#define PRESENT128_BITSLICE8_CHECK ERROR_NOT_DEFINED(present128) 
#define PRESENT128_BITSLICE16_CHECK ERROR_NOT_DEFINED(present128) 
#endif
/****** Piccolo80 ***/
#ifdef Piccolo80
#ifdef TABLE
#define Piccolo80_TABLE_CHECK DO_CHECK(Piccolo, table, TABLE_P, 80) 
#else
#define Piccolo80_TABLE_CHECK ERROR_NOT_DEFINED(table)
#endif
#ifdef VPERM
#define Piccolo80_VPERM_CHECK DO_CHECK(Piccolo, vperm, VPERM_P, 80) 
#else
#define Piccolo80_VPERM_CHECK ERROR_NOT_DEFINED(vperm)
#endif
#ifdef BITSLICE
#define Piccolo80_BITSLICE16_CHECK DO_CHECK(Piccolo, bitslice16, BITSLICE16_P, 80) 
#else
#define Piccolo80_BITSLICE16_CHECK ERROR_NOT_DEFINED(bitslice16)
#endif
#else
#define Piccolo80_TABLE_CHECK ERROR_NOT_DEFINED(piccolo80) 
#define Piccolo80_VPERM_CHECK ERROR_NOT_DEFINED(piccolo80) 
#define Piccolo80_BITSLICE16_CHECK ERROR_NOT_DEFINED(piccolo80) 
#endif
/****** Piccolo128 ***/
#ifdef Piccolo128
#ifdef TABLE
#define Piccolo128_TABLE_CHECK DO_CHECK(Piccolo, table, TABLE_P, 128)
#else
#define Piccolo128_TABLE_CHECK ERROR_NOT_DEFINED(table)
#endif
#ifdef VPERM
#define Piccolo128_VPERM_CHECK DO_CHECK(Piccolo, vperm, VPERM_P, 128)
#else
#define Piccolo128_VPERM_CHECK ERROR_NOT_DEFINED(vperm)
#endif
#ifdef BITSLICE
#define Piccolo128_BITSLICE16_CHECK DO_CHECK(Piccolo, bitslice16, BITSLICE16_P, 128) 
#else
#define Piccolo128_BITSLICE16_CHECK ERROR_NOT_DEFINED(bitslice16)
#endif
#else
#define Piccolo128_TABLE_CHECK ERROR_NOT_DEFINED(piccolo128) 
#define Piccolo128_VPERM_CHECK ERROR_NOT_DEFINED(piccolo128) 
#define Piccolo128_BITSLICE16_CHECK ERROR_NOT_DEFINED(piccolo128) 
#endif


/* The available implementations */
ciphers implementations[] = {
	{_LED64,      (_TABLE|_VPERM|_BITSLICE16|_BITSLICE32), {LED64_TABLE_CHECK, LED64_VPERM_CHECK, NULL, LED64_BITSLICE16_CHECK, LED64_BITSLICE32_CHECK}},
	{_LED128,     (_TABLE|_VPERM|_BITSLICE16|_BITSLICE32), {LED128_TABLE_CHECK, LED128_VPERM_CHECK, NULL, LED128_BITSLICE16_CHECK, LED128_BITSLICE32_CHECK}},
	{_PRESENT80,  (_TABLE|_VPERM|_BITSLICE8|_BITSLICE16), {PRESENT80_TABLE_CHECK, PRESENT80_VPERM_CHECK, PRESENT80_BITSLICE8_CHECK, PRESENT80_BITSLICE16_CHECK, NULL}},
	{_PRESENT128, (_TABLE|_VPERM|_BITSLICE8|_BITSLICE16), {PRESENT128_TABLE_CHECK, PRESENT128_VPERM_CHECK, PRESENT128_BITSLICE8_CHECK, PRESENT128_BITSLICE16_CHECK, NULL}},
	{_Piccolo80,  (_TABLE|_VPERM|_BITSLICE16), {Piccolo80_TABLE_CHECK, Piccolo80_VPERM_CHECK, NULL, Piccolo80_BITSLICE16_CHECK, NULL}},
	{_Piccolo128, (_TABLE|_VPERM|_BITSLICE16), {Piccolo128_TABLE_CHECK, Piccolo128_VPERM_CHECK, NULL, Piccolo128_BITSLICE16_CHECK, NULL}}
};
	

int logtwo(u32 in){
	int i;
	for(i=31; i>=0; i--){
		if(get_bit(in, i)){
			return i;
		}
	}
	return 0;
}

int hamming(u32 in){
	int i, weight;
	weight = 0;
	for(i=31; i>=0; i--){
        	if(get_bit(in, i)){
			weight++;
		}
	}
	return weight;
}

void do_check_LED64table(void){
#ifdef LED64
#ifdef TABLE
	CHECK(LED, table, TABLE_P, 64);
#endif
#endif
}
void do_check_LED64vperm(void){
#ifdef LED64
#ifdef VPERM
	CHECK(LED, vperm, VPERM_P, 64);
#endif
#endif
}
void do_check_LED64bitslice16(void){
#ifdef LED64
#ifdef BITSLICE
	CHECK(LED, bitslice16, BITSLICE16_P, 64);
#endif
#endif
}
void do_check_LED64bitslice32(void){
#ifdef LED64
#ifdef BITSLICE
	CHECK(LED, bitslice32, BITSLICE32_P, 64);
#endif
#endif
}
void do_check_LED128table(void){
#ifdef LED128
#ifdef TABLE
	CHECK(LED, table, TABLE_P, 128);
#endif
#endif
}
void do_check_LED128vperm(void){
#ifdef LED128
#ifdef VPERM
	CHECK(LED, vperm, VPERM_P, 128);
#endif
#endif
}
void do_check_LED128bitslice16(void){
#ifdef LED128
#ifdef BITSLICE
	CHECK(LED, bitslice16, BITSLICE16_P, 128);
#endif
#endif
}
void do_check_LED128bitslice32(void){
#ifdef LED128
#ifdef BITSLICE
	CHECK(LED, bitslice32, BITSLICE32_P, 128);
#endif
#endif
}
void do_check_PRESENT80table(void){
#ifdef PRESENT80
#ifdef TABLE
	CHECK(PRESENT, table, TABLE_P, 80);
#endif
#endif
}
void do_check_PRESENT80vperm(void){
#ifdef PRESENT80
#ifdef VPERM
	CHECK(PRESENT, vperm, VPERM_P, 80);
#endif
#endif
}
void do_check_PRESENT80bitslice8(void){
#ifdef PRESENT80
#ifdef BITSLICE
	CHECK(PRESENT, bitslice8, BITSLICE8_P, 80);
#endif
#endif
}
void do_check_PRESENT80bitslice16(void){
#ifdef PRESENT80
#ifdef BITSLICE
	CHECK(PRESENT, bitslice16, BITSLICE16_P, 80);
#endif
#endif
}
void do_check_PRESENT128table(void){
#ifdef PRESENT128
#ifdef TABLE
	CHECK(PRESENT, table, TABLE_P, 128);
#endif
#endif
}
void do_check_PRESENT128vperm(void){
#ifdef PRESENT128
#ifdef VPERM
	CHECK(PRESENT, vperm, VPERM_P, 128);
#endif
#endif
}
void do_check_PRESENT128bitslice8(void){
#ifdef PRESENT128
#ifdef BITSLICE
	CHECK(PRESENT, bitslice8, BITSLICE8_P, 128);
#endif
#endif
}
void do_check_PRESENT128bitslice16(void){
#ifdef PRESENT128
#ifdef BITSLICE
	CHECK(PRESENT, bitslice16, BITSLICE16_P, 128);
#endif
#endif
}

void do_check_Piccolo80table(void){
#ifdef Piccolo80
#ifdef TABLE
	CHECK(Piccolo, table, TABLE_P, 80);
#endif
#endif
}
void do_check_Piccolo80vperm(void){
#ifdef Piccolo80
#ifdef VPERM
	CHECK(Piccolo, vperm, VPERM_P, 80);
#endif
#endif
}
void do_check_Piccolo80bitslice16(void){
#ifdef Piccolo80
#ifdef BITSLICE
	CHECK(Piccolo, bitslice16, BITSLICE16_P, 80);
#endif
#endif
}

void do_check_Piccolo128table(void){
#ifdef Piccolo128
#ifdef TABLE
	CHECK(Piccolo, table, TABLE_P, 128);
#endif
#endif
}
void do_check_Piccolo128vperm(void){
#ifdef Piccolo128
#ifdef VPERM
	CHECK(Piccolo, vperm, VPERM_P, 128);
#endif
#endif
}
void do_check_Piccolo128bitslice16(void){
#ifdef Piccolo128
#ifdef BITSLICE
	CHECK(Piccolo, bitslice16, BITSLICE16_P, 128);
#endif
#endif
}


#define WARNING_OUT(msg1, msg2) do {\
	custom_printf_warning("%s is not defined ('%s' might be missing at compile time!)\n", msg1, msg2);\
} while(0);


void warning_not_defined_led64(){
       WARNING_OUT("LED64", "-DLED64");
       return;
}
void warning_not_defined_led128(){
       WARNING_OUT("LED128", "-DLED128");
       return;
}

void warning_not_defined_present80(){
       WARNING_OUT("PRESENT80", "-DPRESENT80");
       return;
}
void warning_not_defined_present128(){
       WARNING_OUT("PRESENT128", "-DPRESENT128");
       return;
}

void warning_not_defined_piccolo80(){
       WARNING_OUT("Piccolo80", "-DPiccolo80");
       return;
}
void warning_not_defined_piccolo128(){
       WARNING_OUT("Piccolo128", "-DPiccolo128");
       return;
}

void warning_not_defined_table(){
       WARNING_OUT("table", "-DTABLE");
       return;
}
void warning_not_defined_vperm(){
       WARNING_OUT("vperm", "-DVPERM");
       return;
}
void warning_not_defined_bitslice8(){
	WARNING_OUT("bitslice8", "-DBITSLICE");
	return;
}
void warning_not_defined_bitslice16(){
	WARNING_OUT("bitslice16", "-DBITSLICE");
	return;
}
void warning_not_defined_bitslice32(){
	WARNING_OUT("bitslice32", "-DBITSLICE");
	return;
}

char* cipher_to_string(int cipher){
	switch (cipher) {
	case _LED64:
		return "LED64";
	case _LED128:
		return "LED128";
	case _PRESENT80:
		return "PRESENT80";
	case _PRESENT128:
		return "PRESENT128";
	case _Piccolo80:
		return "Piccolo80";
	case _Piccolo128:
		return "Piccolo128";
	default:
		return "unknown";
	}
}

int string_to_cipher(char* cipher){
	if(strcmp(cipher, "LED64") == 0)
		return _LED64;
	if(strcmp(cipher, "LED128") == 0)
		return _LED128;
	if(strcmp(cipher, "LED") == 0)
		return (_LED64|_LED128);
	if(strcmp(cipher, "PRESENT80") == 0)
		return _PRESENT80;
	if(strcmp(cipher, "PRESENT128") == 0)
		return _PRESENT128;
	if(strcmp(cipher, "PRESENT") == 0)
		return (_PRESENT80|_PRESENT128);
	if(strcmp(cipher, "Piccolo80") == 0)
		return _Piccolo80;
	if(strcmp(cipher, "Piccolo128") == 0)
		return _Piccolo128;
	if(strcmp(cipher, "Piccolo") == 0)
		return (_Piccolo80|_Piccolo128);

	return _NONE;

}

char* type_to_string(int type){
	switch (type) {
	case _TABLE:
		return "table";
	case _VPERM:
		return "vperm";
	case _BITSLICE8:
		return "bitslice8";
	case _BITSLICE16:
		return "bitslice16";
	case _BITSLICE32:
		return "bitslice32";
	default:
		return "unknown";
	}
}

int string_to_type(char* type){
	if(strcmp(type, "vperm") == 0)
		return _VPERM;
	if(strcmp(type, "table") == 0)
		return _TABLE;
	if(strcmp(type, "bitslice") == 0)
		return (_BITSLICE8|_BITSLICE16|_BITSLICE32);
	if(strcmp(type, "bitslice8") == 0)
		return _BITSLICE8;
	if(strcmp(type, "bitslice16") == 0)
		return _BITSLICE16;
	if(strcmp(type, "bitslice32") == 0)
		return _BITSLICE32;
	return _NONE;
}

int string_to_type_with_cipher(char* type, int cipher){
	if(strcmp(type, "vperm") == 0)
		return _VPERM;
	if(strcmp(type, "table") == 0)
		return _TABLE;
	if(strcmp(type, "bitslice") == 0){
		/* Get the proper bitslice implementations */
		return ((_BITSLICE8|_BITSLICE16|_BITSLICE32) & implementations[logtwo(cipher)].available_implementations);
	}
	if(strcmp(type, "bitslice8") == 0)
		return _BITSLICE8;
	if(strcmp(type, "bitslice16") == 0)
		return _BITSLICE16;
	if(strcmp(type, "bitslice32") == 0)
		return _BITSLICE32;
	return _NONE;
}

void execute_ciphers(u32 ciphers_to_test, u32 implem_types, u8 doreexecute){
	int i, j;
	for(i=0; i < CIPHER_TYPES_NUM; i++){
		if(ciphers_to_test & implementations[i].cipher){
			/* Execute the ciphers */
			for(j=0; j < CIPHER_TYPES_NUM; j++){
				/* Get the implementation type */
				if((get_bit(implem_types, j)) && (get_bit(implementations[i].available_implementations, j))){
					if(implementations[i].checking_functions[j] != (ExecuteCheck)-1){
						/* The implementation is asked and available */
						(implementations[i].checking_functions[j])();
					}
					/* Do we want possible reexecution or not? */
					if(doreexecute == NOREEXECUTE){
						implementations[i].checking_functions[j] = (ExecuteCheck)-1;
					}
				}
				else if (get_bit(implem_types, j)){
					/* The implementation is asked but it is not available */
					/* Print an error message                              */
					if(implementations[i].checking_functions[j] != (ExecuteCheck)-1){
						custom_printf_error("You asked for the implementation %s of %s, but it does not exist!\n", type_to_string(0x1 << j), cipher_to_string(0x1 << i));	
					}
					/* Do we want possible reexecution or not? */
					if(doreexecute == NOREEXECUTE){
						implementations[i].checking_functions[j] = (ExecuteCheck)-1;
					}
				}
			}
		}
	}
}

#define LIB_NAME "./liblightweight-ciphers.so"
/* Checking all the ciphers in all their implementation flavours */
int main(int argc, char* argv[]){
	int i, j;
        /* variable holding the ciphers to test */
	u32* ciphers_to_test = NULL;
	u32* implem_types = NULL;
	int counter = 0;
	void* handle;
	int cipher_options = 0;

	/* Sanity check on all the args */	
        for(i=1; i < argc; i++){
		if(strcmp(argv[i], "-no-colors") == 0){
			use_colors = 0;
		} else if(strcmp(argv[i], "-perf-only") == 0){
			check_perf = 1;
		}else if(strcmp(argv[i], "-vectors-only") == 0){
			check_vectors = 1;
		}
		else if(strncmp(argv[i], "-samples=", strlen("-samples=")) == 0){
			long long new_samples = atoll(argv[i]+strlen("-samples="));
			if(new_samples <= 0){
				samples = SAMPLES;
			}
			else{
				samples = (unsigned long long)new_samples;
			}
		}
		else{
			cipher_options++;
		}
		if((string_to_cipher(argv[i]) == _NONE) && (string_to_type(argv[i]) == _NONE) && (strcmp(argv[i], "-no-colors") != 0) && (strcmp(argv[i], "-perf-only") != 0) && (strcmp(argv[i], "-vectors-only") != 0) && (strncmp(argv[i], "-samples=", strlen("-samples=")) != 0)){
			if((strcmp(argv[i], "-h") != 0) && (strcmp(argv[i], "--help") != 0) && (strcmp(argv[i], "?") != 0)){
				custom_printf(red, nobg, nostyle, "%s", argv[i]);
				custom_printf(nocolor, nobg, nostyle, " is not a valid option ...\n");
			}
usage:
			custom_printf(green, nobg, nostyle, "Usage:");
			custom_printf(lgray, nobg, nostyle, " %s ", argv[0]);
			custom_printf(yellow, nobg, nostyle, "(LED|PRESENT|Piccolo|LED64|LED128|PRESENT80|PRESENT128|Piccolo80|Piccolo128)");
			custom_printf(lblue, nobg, nostyle, " (table|vperm|bitslice|bitslice8|bitslice16|bitslice32)\n");
			custom_printf(nocolor, nobg, nostyle, " Other options:\n");
			custom_printf(nocolor, nobg, nostyle, " -no-colors\n");
			custom_printf(nocolor, nobg, nostyle, " -perf-only\n");
			custom_printf(nocolor, nobg, nostyle, " -vectors-only\n");
			custom_printf(nocolor, nobg, nostyle, " -samples=[0-9]*\n");
    			exit(-1);
		}
  	}
	if((check_vectors == 0) && (check_perf == 0)){
		check_perf = check_vectors = 1;
	}
	/* Load the library */
	handle = dlopen(LIB_NAME, RTLD_NOW);
        if (!handle) {
		custom_printf(red, nobg, nostyle, "%s\n", dlerror());
		exit(-1);
	}
	load_ciphers_symbols(handle);

	/* If we do not have the args, check everything */
	if(cipher_options == 0){
		int j;
		ciphers_to_test = (u32*)realloc(ciphers_to_test, CIPHER_TYPES_NUM*sizeof(u32));
		implem_types = (u32*)realloc(implem_types, CIPHER_TYPES_NUM*sizeof(u32));
		for(j = 0; j < CIPHER_TYPES_NUM; j++){
			counter++;
			ciphers_to_test[j] = implementations[j].cipher;
			implem_types[j] = implementations[j].available_implementations;
		}
	}
	else{
		/* Else, parse the args */
		i = 1;
		while(i < argc){
			if(string_to_cipher(argv[i]) != _NONE){
				counter++;
				ciphers_to_test = (u32*)realloc(ciphers_to_test, counter*sizeof(u32));
				ciphers_to_test[counter-1] = string_to_cipher(argv[i]);
				implem_types = (u32*)realloc(implem_types, counter*sizeof(u32));
				implem_types[counter-1] = _NONE;
				i++;
				/* We have a cipher: get all the implementations */
				while(i < argc){
					if(string_to_type(argv[i]) != _NONE){
						implem_types[counter-1] |= string_to_type_with_cipher(argv[i], ciphers_to_test[counter-1]);
						i++;
					}
					else{
						break;
					}
				}
				if(implem_types[counter-1] == _NONE){
					/* If we have nothing, run the full implementation set on the ciphers */
					int j;
					for(j = 0; j < CIPHER_TYPES_NUM; j++){
						if(get_bit(ciphers_to_test[counter-1], j)){
							implem_types[counter-1] |= implementations[j].available_implementations;
						}
					}
				}
			}
			else{
                                if(string_to_type(argv[i]) != _NONE){
					int j;
					/* Check all the possible asked implementations for each cipher */
                                        for(j = 0; j < CIPHER_TYPES_NUM; j++){
						counter++;
						ciphers_to_test = (u32*)realloc(ciphers_to_test, counter*sizeof(u32));
						ciphers_to_test[counter-1] = implementations[j].cipher;
						implem_types = (u32*)realloc(implem_types, counter*sizeof(u32));
						implem_types[counter-1] = string_to_type_with_cipher(argv[i], ciphers_to_test[counter-1]);
					}
					i++;
				}
				else{
					/* Error when parsing the args */
					if((strcmp(argv[i], "-no-colors") == 0) || (strcmp(argv[i], "-perf-only") == 0) || (strcmp(argv[i], "-vectors-only") == 0) || (strncmp(argv[i], "-samples=", strlen("-samples=")) == 0)){
						i++;
					}
					else{
						goto usage;
					}
				}
			}
		}
	}
	/* Purge the arguments */
	for(i=0; i < counter; i++){
		if((ciphers_to_test[i] == (_LED64|_LED128|_PRESENT80|_PRESENT128|_Piccolo80|_Piccolo128)) && (ciphers_to_test[i] != _NONE)){
			for(j=0; j < counter; j++){
				if((i != j) && (hamming(ciphers_to_test[j]) <= 2) && (hamming(ciphers_to_test[j]) > 0)){
					/* Purge the found cipher */
					ciphers_to_test[i] ^= ciphers_to_test[j]; 
				}
			}	
		}		
	}	
	/* Execute the chosen ciphers */
	for(i=0; i < counter; i++){
		if(ciphers_to_test[i] != _NONE){
			execute_ciphers(ciphers_to_test[i], implem_types[i], NOREEXECUTE);
		}
	}
	if(ciphers_to_test != NULL){
		free(ciphers_to_test);
	}
	if(implem_types != NULL){
		free(implem_types);
	}

	return 1; 
}
