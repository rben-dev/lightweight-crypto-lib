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
    File:    src/common/log.h

-------------------------- CeCILL-B HEADER ----------------------------------*/
/* Logging facilities */

#ifdef BASHCOLORS
#define ANSI_COLOR_RED     		"\x1b[31m"
#define ANSI_COLOR_GREEN  	 	"\x1b[32m"
#define ANSI_COLOR_YELLOW  		"\x1b[33m"
#define ANSI_COLOR_BLUE    		"\x1b[34m"
#define ANSI_COLOR_MAGENTA 		"\x1b[35m"
#define ANSI_COLOR_CYAN    		"\x1b[36m"
#define ANSI_COLOR_LBLUE		"\x1b[94m"
#define ANSI_COLOR_LGRAY		"\x1b[37m"
#define ANSI_COLOR_NONE    		""

#define ANSI_STYLE_BOLD			"\x1b[1m"
#define ANSI_STYLE_UNDERLINED 		"\x1b[4m"
#define ANSI_STYLE_INVERTED 		"\x1b[7m"
#define ANSI_STYLE_DIM			"\x1b[2m"
#define ANSI_STYLE_BLINK		"\x1b[5m"
#define ANSI_STYLE_HIDDEN		"\x1b[8m"
#define ANSI_STYLE_BOLDUNDERLINED	"\x1b[1m\x1b[4m"
#define ANSI_STYLE_NONE			""

#define ANSI_BACKGROUND_RED     	"\x1b[41m"
#define ANSI_BACKGROUND_GREEN		"\x1b[42m"
#define ANSI_BACKGROUND_YELLOW 		"\x1b[43m"
#define ANSI_BACKGROUND_BLUE   		"\x1b[44m"
#define ANSI_BACKGROUND_MAGENTA 	"\x1b[45m"
#define ANSI_BACKGROUND_CYAN    	"\x1b[46m"
#define ANSI_BACKGROUND_NONE    	""

#define ANSI_RESET   			"\x1b[0m"

#else

#define ANSI_COLOR_RED     		""
#define ANSI_COLOR_GREEN  	 	""
#define ANSI_COLOR_YELLOW  		""
#define ANSI_COLOR_BLUE    		""
#define ANSI_COLOR_MAGENTA 		""
#define ANSI_COLOR_CYAN    		""
#define ANSI_COLOR_LBLUE		""
#define ANSI_COLOR_LGRAY		""
#define ANSI_COLOR_NONE    		""

#define ANSI_STYLE_BOLD			""
#define ANSI_STYLE_UNDERLINED 		""
#define ANSI_STYLE_INVERTED 		""
#define ANSI_STYLE_DIM			""
#define ANSI_STYLE_BLINK		""
#define ANSI_STYLE_HIDDEN		""
#define ANSI_STYLE_BOLDUNDERLINED	""
#define ANSI_STYLE_NONE			""

#define ANSI_BACKGROUND_RED     	""
#define ANSI_BACKGROUND_GREEN		""
#define ANSI_BACKGROUND_YELLOW 		""
#define ANSI_BACKGROUND_BLUE   		""
#define ANSI_BACKGROUND_MAGENTA 	""
#define ANSI_BACKGROUND_CYAN    	""
#define ANSI_BACKGROUND_NONE    	""

#define ANSI_RESET   			""

#endif

unsigned char use_colors = 1;

typedef enum {red = 0, green = 1, yellow = 2, blue = 3, magenta = 4, cyan = 5, lblue = 6, lgray = 7, nocolor = 8} color;
const char* bash_colors[] = {ANSI_COLOR_RED, ANSI_COLOR_GREEN, ANSI_COLOR_YELLOW, ANSI_COLOR_BLUE, ANSI_COLOR_MAGENTA, ANSI_COLOR_CYAN, ANSI_COLOR_LBLUE, ANSI_COLOR_LGRAY, ANSI_COLOR_NONE};

typedef enum {bold = 0, underlined = 1, inverted = 2, dim = 3, blink = 4, hidden = 5, boldunderlined = 6, nostyle = 7} style;
const char* bash_styles[] = {ANSI_STYLE_BOLD, ANSI_STYLE_UNDERLINED, ANSI_STYLE_INVERTED, ANSI_STYLE_DIM, ANSI_STYLE_BLINK, ANSI_STYLE_HIDDEN, ANSI_STYLE_BOLDUNDERLINED, ANSI_STYLE_NONE};

typedef enum {redbg = 0, greenbg = 1, yellowbg = 2, bluebg = 3, magentabg = 4, cyanbg = 5, nobg = 6} background;
const char* bash_backgrounds[] = {ANSI_BACKGROUND_RED, ANSI_BACKGROUND_GREEN, ANSI_BACKGROUND_YELLOW, ANSI_BACKGROUND_BLUE, ANSI_BACKGROUND_MAGENTA, ANSI_BACKGROUND_CYAN, ANSI_BACKGROUND_NONE};

#ifdef BASHCOLORS
#define custom_printf(col, bg, st, format, ...) do {\
	if(use_colors == 1){\
		printf("%s%s%s"format ANSI_RESET, bash_colors[col], bash_backgrounds[bg], bash_styles[st], ##__VA_ARGS__);\
	}\
	else{\
		printf(format, ##__VA_ARGS__);\
	}\
} while(0);
#else
#define custom_printf(col, bg, st, ...) do {\
	printf(__VA_ARGS__);\
} while(0);
#endif

#define custom_printf_warning(...) do {\
	custom_printf(yellow, nobg, boldunderlined, "Warning:");\
	custom_printf(nocolor, nobg, nostyle, " ");\
	custom_printf(nocolor, nobg, nostyle, ##__VA_ARGS__);\
} while(0);

#define custom_printf_error(...) do {\
	custom_printf(red, nobg, boldunderlined, "Error:");\
	custom_printf(nocolor, nobg, nostyle, " ");\
	custom_printf(nocolor, nobg, nostyle, ##__VA_ARGS__);\
} while(0);

