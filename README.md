## Introduction

This software is a computer program whose purpose is to implement
lightweight block ciphers with different optimizations for the x86
platform. Three algorithms have been implemented: [PRESENT](http://homes.esat.kuleuven.be/.../papers/present_ches07.pdf), 
[LED](https://sites.google.com/site/ledblockcipher/) and [Piccolo](http://link.springer.com/chapter/10.1007%2F978-3-642-23951-9_23#page-1). 
Three techniques have been explored: table based 
implementations, vperm (for vector permutation) and bitslice 
implementations. For more details on these techniques and their 
adaptation to the algorithms, please refer to the 
[SAC 2013 paper](http://eprint.iacr.org/2013/445). The pdf 
of the extended paper is [here](doc/Implementing_Lightweight_Block_Ciphers_on_x86_Architectures.pdf).

Here is a big picture of how the code is divided:

  * `src/common` contains common headers, structures and functions.
  * `src/table` contains table based implementations, with the code 
    that generates the tables in src/table/gen_tables. The code here 
    is written in pure C so it should compile on any platform (x86 
    and other architectures), as well as any OS flavour (*nix, 
    Windows ...).
  * `src/vperm` contains vperm based implementations. They are written 
    in inline assembly for x86_64 and will only compile and work on 
    this platform. The code only compiles with gcc, but porting it to
    other assembly flavours should not be too complicated.
  * `src/bitslice` contains bitslice based implementations. They are 
    written in asm intrinsics. It should compile and run on i386 as 
    well as x86_64 platforms, and it should be portable to other OS 
    flavours since intrinsics are standard among many compilers.

**NOTE1**: vperm and bitslice implementations require a x86 CPU with at least 
**SSSE3 extensions**.

**NOTE2**: the code has been tested on Linux (Debian), but it should work 
on any environment with a decent gcc compiler (Mac OS, Windows with Cygwin ...).

## Authors

  * Ryad Benadjila (<mailto:ryad.benadjila@ssi.gouv.fr>)
  * Jian Guo (<mailto:ntu.guo@gmail.com]>)
  * Victor Lomné (<mailto:victor.lomne@ssi.gouv.fr>)
  * Thomas Peyrin (<mailto:thomas.peyrin@gmail.com>)

## Quick start

### Dependencies
The program only requires the [autotools](http://www.gnu.org/software/autoconf/) package, though it is not mandatory. 
If you don't want to use autotools, just copy the [Makefile.default](Makefile.default) 
as a Makefile and compile the code. Please note however that depending on your 
CPU type, you might need to adapt the Makefile.

**NOTE**: the autotools are used in the project to automatically detect the CPU 
and adapt the compilation options.

### Configure and build the project

    ./autogen.sh

    ./configure

    make

The produced files are in the `bin` directory. They consist of a `.so` dynamic 
library containing the ciphers as well as a standalone binary that tests the 
**reference vectors** of the ciphers and **their performance** for each implementation 
type. The standalone binary dynamically loads the library with _dlopen_.

The configure script takes some options to restrict the ciphers and the implementation flavours 
one wants to compile in the library. One can also force a given architecture (i386 or 
x86\_64) as well as other specific options described through the script help:
 
    ./configure --help

    --with-led          LED cipher
    --with-led64        LED  cipher/64-bit  key  variant
    --with-led128       LED  cipher/128-bit  key  variant
    --with-present      PRESENT  cipher
    --with-present80    PRESENT  cipher/80-bit  key  variant
    --with-present128   PRESENT  cipher/128-bit  key  variant
    --with-piccolo      Piccolo  cipher
    --with-piccolo80    Piccolo  cipher/80-bit  key  variant
    --with-piccolo128   Piccolo  cipher/128-bit  key  variant
    --with-table        Table  implementations
    --with-vperm        Vperm  implementations
    --with-bitslice     Bitslice  implementations
    --with-ssse         SSSE  implementations
    --with-avx          AVX  implementations
    --with-thread-safe  Thread  safe  library  (link  with  pthread)
    --with-arch32       Force  32-bit  compilation
    --with-arch64       Force  64-bit  compilation

### Running the program

Running the tests is as simple as:

    cd bin

    ./check_all_ciphers

The main binary takes options that restrict the execution to test vectors or performance 
benchmark only, or to some implemenations only. The number of samples used for benchmark can also 
be tuned here. The default is to use bash colors for a better readability, but one can turn this 
off (e.g. for logging the results in a file).

    ./check_all_ciphers -h
    Usage: ./check_all_ciphers (LED|PRESENT|Piccolo|LED64|LED128|PRESENT80|PRESENT128|Piccolo80|Piccolo128) 
    (table|vperm|bitslice|bitslice8|bitslice16|bitslice32)
    Other options:
    -no-colors
    -perf-only
    -vectors-only
    -samples=[0-9]*

### The lightweight block ciphers API

The **key schedule** as well as the **core encryption cipher** of the three lightweight block 
ciphers have been implemented in the different flavours (table, vperm and bitslice). We have 
tried to make it as easy to use as possible for users by chosing a common API that takes 
into account the **parallelism** offered by each technique (please refer to the 
[paper](doc/Implementing_Lightweight_Block_Ciphers_on_x86_Architectures.pdf) for details about 
how performances really depend on use cases of the cipher and how the chosen parallelism 
can impact them).

The common API naming convention is:

**Cipher ## key\_size ## implementation\_type ## implementation** (with **##** being the 
concatenation), where:

  * **Cipher** is one of `LED`, `PRESENT`, `Piccolo`
  * **key\_size** is one of `64` or `128` for LED, `80` or `128` for PRESENT and Piccolo
  * **implementation\_type** is one of `table` (for LED, PRESENT, Piccolo), `vperm` (for 
LED, PRESENT, Piccolo), `bitslice8` (for PRESENT), `bitslice16` (for LED, PRESENT and Piccolo) and 
`bitslice32` (for LED)
  * **implementation** is one of `key_schedule`, `core` (for encryption) and `cipher` (for combined 
key schedule and encryption)

For instance, **LED64bitslice16\_core** is the bitslice implementation of the encryption core of LED 
for a 64-bit key size and 16 parallel blocks as input. Similarly, **PRESENT80vperm\_key\_schedule** is 
the vperm key schedule of PRESENT for a 80-bit key size (vperm has a 2 blocks parallelism). 
Finally, **Piccolo128table\_cipher** is the table based implementation of the combined key schedule and 
encryption of Piccolo for a 128-bit key (table based implementations have a parallelism of 1 block).

### A note about performance measurements

We emphasize the fact that in order to get results consistent with the ones 
given in the [SAC 2013 paper](http://eprint.iacr.org/2013/445), one must 
**disable new Intel CPUs Turbo Boost technology**. This technology uses 
dynamic upscale of the processor to locally _overclock_ it. We use 
the *rdtsc* instruction to perform CPU cycles measurements: the cycle 
count obtained here can be desynchronized with the real CPU clock when 
Turbo Boost is active.

Turbo Boost can be disabled from the BIOS. A more user-friendly solution 
under Linux is to use MSR (model specific) register 0x1a0 to dynamically 
disable/enable it on chosen CPU cores. One must first insert the `msr` 
module:

 
    modprobe -i msr

Then, to disable Turbo Boost on the CPU number 'cpu':

    wrmsr -p cpu 0x1a0 0x4000850089

To enable it back:

    wrmsr -p cpu 0x1a0 0x850089
