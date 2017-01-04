AC_INIT(myconfig, version-0.1)

main_dir="./"
table_dir="./src/table"
vperm_dir="./src/vperm"
bitslice_dir="./src/bitslice"

AC_CONFIG_FILES([$main_dir/Makefile])

AC_DEFUN(CHECK_OPTION,[
if test "$1" != "yes"; then
	if test "$1" != "no"; then
		if test "$1" != "default"; then
        		AC_MSG_ERROR([value $1 is not a proper value for option $2 (use "yes", "no" or "default")])
		fi
	fi
fi
])

## Default values
w_led="default"
w_present="default"
w_piccolo="default"
w_led64="default"
w_present80="default"
w_piccolo80="default"
w_led128="default"
w_present128="default"
w_piccolo128="default"

w_table="default"
w_vperm="default"
w_bitslice="default"

w_ssse="default"
w_avx="default"

w_threadsafe="default"

w_arch32="default"
w_arch64="default"

curr_arch=""

AC_ARG_WITH(led,         [  --with-led		LED cipher], w_led="$withval")
AC_ARG_WITH(led64,       [  --with-led64    	LED cipher/64-bit key variant], w_led64="$withval")
AC_ARG_WITH(led128,      [  --with-led128	LED cipher/128-bit key variant], w_led128="$withval")
AC_ARG_WITH(present,     [  --with-present	PRESENT cipher], w_present="$withval")
AC_ARG_WITH(present80,   [  --with-present80    PRESENT cipher/80-bit key variant], w_present80="$withval")
AC_ARG_WITH(present128,  [  --with-present128   PRESENT cipher/128-bit key variant], w_present128="$withval")
AC_ARG_WITH(piccolo,     [  --with-piccolo    	Piccolo cipher], w_piccolo="$withval")
AC_ARG_WITH(piccolo80,   [  --with-piccolo80    Piccolo cipher/80-bit key variant], w_piccolo80="$withval")
AC_ARG_WITH(piccolo128,  [  --with-piccolo128   Piccolo cipher/128-bit key variant], w_piccolo128="$withval")
AC_ARG_WITH(table,    	 [  --with-table   	Table implementations], w_table="$withval")
AC_ARG_WITH(vperm,  	 [  --with-vperm   	Vperm implementations], w_vperm="$withval")
AC_ARG_WITH(bitslice,    [  --with-bitslice   	Bitslice implementations], w_bitslice="$withval")
AC_ARG_WITH(ssse,    	 [  --with-ssse   	SSSE implementations], w_ssse="$withval")
AC_ARG_WITH(avx,    	 [  --with-avx   	AVX implementations], w_avx="$withval")
AC_ARG_WITH(threadsafe,  [  --with-threadsafe 	Thread safe library (link with pthread)], w_threadsafe="$withval")
AC_ARG_WITH(arch32,  	 [  --with-arch32 	Force 32-bit compilation], w_arch32="$withval")
AC_ARG_WITH(arch64,  	 [  --with-arch64 	Force 64-bit compilation], w_arch64="$withval")

CHECK_OPTION($w_led, "--with-led")
CHECK_OPTION($w_led64, "--with-led64")
CHECK_OPTION($w_led128, "--with-led128")
CHECK_OPTION($w_present, "--with-present")
CHECK_OPTION($w_present80, "--with-present80")
CHECK_OPTION($w_present128, "--with-present128")
CHECK_OPTION($w_piccolo, "--with-piccolo")
CHECK_OPTION($w_piccolo80, "--with-piccolo80")
CHECK_OPTION($w_piccolo128, "--with-piccolo128")
CHECK_OPTION($w_table, "--with-table")
CHECK_OPTION($w_vperm, "--with-vperm")
CHECK_OPTION($w_bitslice, "--with-bitslice")
CHECK_OPTION($w_ssse, "--with-ssse")
CHECK_OPTION($w_avx, "--with-avx")
CHECK_OPTION($w_threadsafe, "--with-threadsafe")
CHECK_OPTION($w_arch32, "--with-arch32")
CHECK_OPTION($w_arch64, "--with-arch64")
if test "$w_arch32" == "yes"; then
	if test "$w_arch64" == "yes"; then
        	AC_MSG_ERROR([--with-arch32 and --with-arch64 cannot be set to "yes" together!])
	fi
	if test "$w_vperm" == "yes"; then
        	AC_MSG_ERROR([--with-arch32 and --with-vperm cannot be set to "yes" together! (vperm code is in x86_64 assembly)])
	fi
fi
if test "$w_arch32" == "no"; then
	if test "$w_arch64" == "no"; then
        	AC_MSG_ERROR([--with-arch32 and --with-arch64 cannot be set to "no" together!])
	fi
fi


# Summary helpers
AC_DEFUN(WRITE_TO_FILE,[
printf "%-40s:   %s\n" $2 $3 >> $1
])
AC_DEFUN(SHOW_SUMMARY,[
cat $1 && rm -f $1
])

# Remove any existing summary file
rm -f ./summary
echo "###########################################" >> ./summary
echo "###               SUMMARY               ###" >> ./summary
echo "###########################################" >> ./summary

##########
# CHECK Make
case $host_type in
   *freebsd*)
	AC_CHECK_PROG(MAKEPROG,gmake,gmake,no)
	if test "$MAKEPROG" == "no"
	then
	  AC_MSG_ERROR(Cannot find GNU gmake.)
	fi
	AC_SUBST(MAKEPROG,$MAKEPROG)
	;;
   *)
	AC_CHECK_PROG(MAKEPROG,make,make,no)
	if test "$MAKEPROG" == "no"
	then
	  AC_MSG_ERROR(Cannot find GNU make.)
	fi
	AC_SUBST(MAKEPROG,$MAKEPROG)
	;;
esac

AC_PROG_CC(gcc cc)

######### INTERNAL OPTIONS ###########
#########
summary=""

####### CHECKING CPU CAPABILITIES
##################################################################
# Check for CPU arch
AC_DEFUN(CHECK_CPU_ARCH,[
C_FILE="./check_cpu_arch.c"
FILE="./check_cpu_arch"
rm -f $C_FILE $FILE
cat <<EOM >$C_FILE
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char* argv[]){
#ifdef __i386__
	return 1;
#endif
#ifdef __x86_64__ 
	return 2;
#endif
	return (sizeof(void*));
}
EOM
$CC $C_FILE -o $FILE &> /dev/null
OUT=$?
if [[ "$OUT" != "0" ]]; then
        AC_MSG_ERROR([problem when compiling $C_FILE])
fi 
# Check for output value
$FILE
OUT=$?
if [[ "$OUT" == "1" ]]; then
	echo "###     Detected CPU: x86 32-bit        ###" >> ./summary
        AC_MSG_NOTICE([---> Your CPU is in 32-bit mode])
	if test "$w_vperm" == "default"; then
		w_vperm="no"
	fi
	curr_arch="32-bit"
fi
if [[ "$OUT" == "2" ]]; then
	echo "###     Detected CPU: x86 64-bit        ###" >> ./summary
        AC_MSG_NOTICE([---> Your CPU is in 64-bit mode])
	curr_arch="64-bit"
fi
if [[ "$OUT" == "4" ]]; then
	echo "###     Detected CPU: no x86 (32-bit)   ###" >> ./summary
        AC_MSG_NOTICE([---> Your CPU has a non x86 architecture])
	if test "$w_vperm" == "default"; then
		w_vperm="no"
	fi
	if test "$w_bitslice" == "default"; then
		w_bitslice="no"
	fi
	curr_arch="32-bit"
fi
if [[ "$OUT" == "8" ]]; then
	echo "###     Detected CPU: no x86 (64-bit)   ###" >> ./summary
        AC_MSG_NOTICE([---> Your CPU has a non x86 architecture])
	if test "$w_vperm" == "default"; then
		w_vperm="no"
	fi
	if test "$w_bitslice" == "default"; then
		w_bitslice="no"
	fi
	curr_arch="64-bit"
fi
if [[ "$curr_arch" == "" ]]; then
        AC_MSG_ERROR([problem when detecting CPU architecture: unknown architecture!])
fi

# Job done: remove unnecessary files
rm -f $C_FILE $FILE
])

##################################################################
# Check for CPU features
AC_DEFUN(CHECK_CPU_FEATURES,[
C_FILE="./check_cpu_features.c"
FILE="./check_cpu_features"
rm -f $C_FILE $FILE
cat <<EOM >$C_FILE
#include <stdio.h>
#include <stdlib.h>
#include "common/helpers.h"
int main(int argc, char* argv[]){
	return 0;
}
EOM
$CC -DBITSLICE -DVPERM -DAVX $C_FILE -I $main_dir/src -o $FILE &> /dev/null
OUT=$?
if [[ "$OUT" != "0" ]]; then
        AC_MSG_ERROR([problem when compiling $C_FILE])
fi 
# Check for output value
$FILE
OUT=$?
if [[ "$OUT" == "2" ]]; then
	echo "###     Detected CPU: no SSSE3          ###" >> ./summary
	echo "###########################################" >> ./summary
        AC_MSG_NOTICE([---> Your CPU does not support SSSE3])
	w_avx="no"
	w_ssse="no"
	if test "$w_vperm" == "default"; then
		w_vperm="no"
	fi
	if test "$w_bitslice" == "default"; then
		w_bitslice="no"
	fi
fi
if [[ "$OUT" == "3" ]]; then
	echo "###     Detected CPU: SSSE3, no AVX     ###" >> ./summary
	echo "###########################################" >> ./summary
        AC_MSG_NOTICE([---> Your CPU supports SSSE3 but not AVX])
	w_avx="no"
fi
if [[ "$OUT" == "0" ]]; then
	echo "###     Detected CPU: SSSE3 and AVX     ###" >> ./summary
	echo "###########################################" >> ./summary
        AC_MSG_NOTICE([---> Your CPU supports both SSSE3 and AVX])
fi
# Job done: remove unnecessary files
rm -f $C_FILE $FILE
])

#### Check for CPU architecture and features (instruction set)
CHECK_CPU_ARCH()
CHECK_CPU_FEATURES()


# If we force arch32, we force vperm to be desactivated
if test "$w_arch32" == "yes"; then
	w_vperm="no"
	w_avx="no"
fi

# table handling
if test "$w_table" != "no"; then
        AC_MSG_NOTICE([Using table based functions])
        WRITE_TO_FILE(summary, "table", "YES")
	AC_SUBST(table_define, "-DTABLE")
else
        WRITE_TO_FILE(summary, "table", "NO")
	AC_SUBST(table_define, "")
fi

# vperm handling
if test "$w_vperm" != "no"; then
        AC_MSG_NOTICE([Using vperm functions])
        WRITE_TO_FILE(summary, "vperm", "YES")
	AC_SUBST(vperm_define, "-DVPERM")
else
        WRITE_TO_FILE(summary, "vperm", "NO")
	AC_SUBST(vperm_define, "")
fi

# bitslice handling
if test "$w_bitslice" != "no"; then
        AC_MSG_NOTICE([Using bitslice functions])
        WRITE_TO_FILE(summary, "bitslice", "YES")
	AC_SUBST(bitslice_define, "-DBITSLICE")
else
        WRITE_TO_FILE(summary, "bitslice", "NO")
fi

# led handling
led64_log=""
led128_log=""
if test "$w_led64" != "no"; then
	if test "$w_led" != "no"; then
		led64_log="1"
	    	WRITE_TO_FILE(summary, "LED64", "YES")
		AC_SUBST(led64_define, "-DLED64")
	else
		led64_log="1"
	       	WRITE_TO_FILE(summary, "LED64", "NO")
		AC_SUBST(led64_define, "")
	fi
else
	led64_log="1"
       	WRITE_TO_FILE(summary, "LED64", "NO")
	AC_SUBST(led64_define, "")
fi
if test "$w_led128" != "no"; then
	if test "$w_led" != "no"; then
		led128_log="1"
    		WRITE_TO_FILE(summary, "LED128", "YES")
		AC_SUBST(led128_define, "-DLED128")
	else
		led128_log="1"
	       	WRITE_TO_FILE(summary, "LED128", "NO")
		AC_SUBST(led128_define, "")
	fi
else
	led128_log="1"
       	WRITE_TO_FILE(summary, "LED128", "NO")
	AC_SUBST(led128_define, "")
fi
if test "$w_led" != "no"; then
	if test "$led64_log" == ""; then
	       	WRITE_TO_FILE(summary, "LED64", "YES")
		AC_SUBST(led64_define, "-DLED64")
	fi
	if test "$led128_log" == ""; then
    		WRITE_TO_FILE(summary, "LED128", "YES")
		AC_SUBST(led128_define, "-DLED128")
	fi
else
	if test "$led64_log" == ""; then
       		WRITE_TO_FILE(summary, "LED64", "NO")
		AC_SUBST(led64_define, "")
	fi
	if test "$led128_log" == ""; then
    		WRITE_TO_FILE(summary, "LED128", "NO")
		AC_SUBST(led128_define, "")
	fi
fi
# present handling
present80_log=""
present128_log=""
if test "$w_present80" != "no"; then
	if test "$w_present" != "no"; then
		present80_log="1"
	    	WRITE_TO_FILE(summary, "PRESENT80", "YES")
		AC_SUBST(present80_define, "-DPRESENT80")
	else
		present80_log="1"
	       	WRITE_TO_FILE(summary, "PRESENT80", "NO")
		AC_SUBST(present80_define, "")
	fi
else
	present80_log="1"
       	WRITE_TO_FILE(summary, "PRESENT80", "NO")
	AC_SUBST(present80_define, "")
fi
if test "$w_present128" != "no"; then
	if test "$w_present" != "no"; then
		present128_log="1"
    		WRITE_TO_FILE(summary, "PRESENT128", "YES")
		AC_SUBST(present128_define, "-DPRESENT128")
	else
		present128_log="1"
	       	WRITE_TO_FILE(summary, "PRESENT128", "NO")
		AC_SUBST(present128_define, "")
	fi
else
	present128_log="1"
       	WRITE_TO_FILE(summary, "PRESENT128", "NO")
	AC_SUBST(present128_define, "")
fi
if test "$w_present" != "no"; then
	if test "$present80_log" == ""; then
	       	WRITE_TO_FILE(summary, "PRESENT80", "YES")
		AC_SUBST(present80_define, "-DPRESENT80")
	fi
	if test "$present128_log" == ""; then
    		WRITE_TO_FILE(summary, "PRESENT128", "YES")
		AC_SUBST(present128_define, "-DPRESENT128")
	fi
else
	if test "$present80_log" == ""; then
       		WRITE_TO_FILE(summary, "PRESENT80", "NO")
		AC_SUBST(present80_define, "")
	fi
	if test "$present128_log" == ""; then
    		WRITE_TO_FILE(summary, "PRESENT128", "NO")
		AC_SUBST(present128_define, "")
	fi
fi

# piccolo handling
piccolo80_log=""
piccolo128_log=""
if test "$w_piccolo80" != "no"; then
	if test "$w_piccolo" != "no"; then
		piccolo80_log="1"
	    	WRITE_TO_FILE(summary, "Piccolo80", "YES")
		AC_SUBST(piccolo80_define, "-DPiccolo80")
	else
		piccolo80_log="1"
	       	WRITE_TO_FILE(summary, "Piccolo80", "NO")
		AC_SUBST(piccolo80_define, "")
	fi
else
	piccolo80_log="1"
       	WRITE_TO_FILE(summary, "Piccolo80", "NO")
	AC_SUBST(piccolo80_define, "")
fi
if test "$w_piccolo128" != "no"; then
	if test "$w_piccolo" != "no"; then
		piccolo128_log="1"
    		WRITE_TO_FILE(summary, "Piccolo128", "YES")
		AC_SUBST(piccolo128_define, "-DPiccolo128")
	else
		piccolo128_log="1"
	       	WRITE_TO_FILE(summary, "Piccolo128", "NO")
		AC_SUBST(piccolo128_define, "")
	fi
else
	piccolo128_log="1"
       	WRITE_TO_FILE(summary, "Piccolo128", "NO")
	AC_SUBST(piccolo128_define, "")
fi
if test "$w_piccolo" != "no"; then
	if test "$piccolo80_log" == ""; then
	       	WRITE_TO_FILE(summary, "Piccolo80", "YES")
		AC_SUBST(piccolo80_define, "-DPiccolo80")
	fi
	if test "$piccolo128_log" == ""; then
    		WRITE_TO_FILE(summary, "Piccolo128", "YES")
		AC_SUBST(piccolo128_define, "-DPiccolo128")
	fi
else
	if test "$piccolo80_log" == ""; then
       		WRITE_TO_FILE(summary, "Piccolo80", "NO")
		AC_SUBST(piccolo80_define, "")
	fi
	if test "$piccolo128_log" == ""; then
    		WRITE_TO_FILE(summary, "Piccolo128", "NO")
		AC_SUBST(piccolo128_define, "")
	fi
fi

# ssse handling
if test "$w_ssse" != "no"; then
       	WRITE_TO_FILE(summary, "Using SSSE", "YES")
	AC_SUBST(ssse_link, "-mssse3")
else
       	WRITE_TO_FILE(summary, "Using SSSE", "NO")
	AC_SUBST(ssse_link, "")
fi

# avx handling
if test "$w_avx" != "no"; then
       	WRITE_TO_FILE(summary, "Using AVX", "YES")
	AC_SUBST(avx_define, "-DAVX")
else
       	WRITE_TO_FILE(summary, "Using AVX", "NO")
	AC_SUBST(avx_define, "")
fi

# threadsafe handling
if test "$w_threadsafe" != "no"; then
       	WRITE_TO_FILE(summary, "Using thread-safe functions", "YES")
	AC_SUBST(threadsafe_define, "-DTHREAD_SAFE")
	AC_SUBST(threadsafe_link, "-lpthread")
else
       	WRITE_TO_FILE(summary, "Using thread-safe functions", "NO")
	AC_SUBST(threadsafe_define, "")
	AC_SUBST(threadsafe_link, "")
fi

# arch32 handling
if test "$w_arch32" == "yes"; then
       	WRITE_TO_FILE(summary, "Compiling for architecture (forced)", "32-bit")
	AC_SUBST(arch32_opt, "-m32")
else
	AC_SUBST(arch32_opt, "")
fi

# arch64 handling
if test "$w_arch64" == "yes"; then
       	WRITE_TO_FILE(summary, "Compiling for architecture (forced)", "64-bit")
	AC_SUBST(arch64_opt, "-m64")
else
	AC_SUBST(arch64_opt, "")
fi

# Default arch
if test "$w_arch32" == "default"; then
	if test "$w_arch64" == "default"; then
	        WRITE_TO_FILE(summary, "Compiling for architecture (detected)", "$curr_arch")
	fi
fi
AC_OUTPUT(Makefile)

SHOW_SUMMARY([summary])
