table_dir=src/table
vperm_dir=src/vperm
bitslice_dir=src/bitslice
common_dir=src/common
include_dir=src
LIB_COPTS=  -Wall -Wextra -Wpointer-arith -Wcast-align -Wredundant-decls -Wnested-externs -Winline -Wuninitialized -fPIC -O3 -shared -mssse3
LIB_LDOPTS=-lpthread
BIN_COPTS=  -Wall -Wextra -Wpointer-arith -Wcast-align -Wredundant-decls -Wnested-externs -Winline -Wuninitialized -O3
BIN_LDOPTS=-ldl
defines=-DTABLE -DVPERM -DBITSLICE -DAVX -DBASHCOLORS -DTEST_VECTORS -DMEASURE_PERF -DLED64 -DLED128 -DPRESENT80 -DPRESENT128 -DPiccolo80 -DPiccolo128 -DTHREAD_SAFE
outdir=bin
outlib=$(outdir)/liblightweight-ciphers.so
outbin=$(outdir)/check_all_ciphers

.PHONY: lib checks

all:	lib checks

lib:
	@mkdir -p $(outdir)
	$(CC) $(defines) $(LIB_COPTS) -I $(include_dir) $(table_dir)/LED/LED.c $(vperm_dir)/LED/LED.c $(bitslice_dir)/LED/LED.c $(table_dir)/PRESENT/PRESENT.c $(vperm_dir)/PRESENT/PRESENT.c $(bitslice_dir)/PRESENT/PRESENT.c $(table_dir)/Piccolo/Piccolo.c $(vperm_dir)/Piccolo/Piccolo.c $(bitslice_dir)/Piccolo/Piccolo.c $(common_dir)/lib_common.c -o $(outlib) $(LIB_LDOPTS)

checks:
	@mkdir -p $(outdir)
	$(CC) $(defines) $(BIN_COPTS) -I $(include_dir) $(common_dir)/check_all.c -o $(outbin) $(BIN_LDOPTS)

clean:
	@rm -f $(outlib) $(outbin)
	@rm -rf $(outdir) 
