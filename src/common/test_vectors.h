/* Test vectors for all the ciphers */
/**** LED ***/
/* LED64 test vectors */
u64 test_vectorsLED64[] = {0x0ULL, 0xefcdab8967452301ULL};
u16 keys64LED64[sizeof(test_vectorsLED64)/sizeof(u64)][KEY64] = {{0}, {0x2301, 0x6745, 0xab89, 0xefcd}};
u64 test_vectorsLED64results[sizeof(test_vectorsLED64)/sizeof(u64)] = {0x98c7a0031040c239ULL, 0x58fc93381e5503a0ULL};
/* LED128 test vectors */
u64 test_vectorsLED128[] = {0x0ULL, 0xefcdab8967452301ULL};
u16 keys128LED128[sizeof(test_vectorsLED128)/sizeof(u64)][KEY128] = {{0}, {0x2301, 0x6745, 0xab89, 0xefcd, 0x2301, 0x6745, 0xab89, 0xefcd}};
u64 test_vectorsLED128results[sizeof(test_vectorsLED128)/sizeof(u64)] = {0xa1db0c85a0b2ec3dULL, 0xc24f017f5824b8d6ULL};

/*** PRESENT ***/
/* PRESENT80 test vectors */
u64 test_vectorsPRESENT80[] = {0x0ULL, 0x0ULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL};
u16 keys80PRESENT80[sizeof(test_vectorsPRESENT80)/sizeof(u64)][KEY80] = {{0},  {0xffff, 0xffff, 0xffff, 0xffff, 0xffff}, {0}, {0xffff, 0xffff, 0xffff, 0xffff, 0xffff}};
u64 test_vectorsPRESENT80results[sizeof(test_vectorsPRESENT80)/sizeof(u64)] = {0x4584227b38c17955ULL, 0x495094f5c0462ce7ULL, 0x7b41682fc7ff12a1ULL, 0xd2103221d3dc3333ULL};
/* PRESENT128 test vectors */
u64 test_vectorsPRESENT128[] = {0x0ULL};
u16 keys128PRESENT128[sizeof(test_vectorsPRESENT128)/sizeof(u64)][KEY128] = {{0}};
u64 test_vectorsPRESENT128results[sizeof(test_vectorsPRESENT128)/sizeof(u64)] = {0xaf00692e2a70db96ULL};

/*** Piccolo ***/
/* Piccolo80 test vectors */
u64 test_vectorsPiccolo80[] = {0xefcdab8967452301ULL, 0x517fe322009f2f67};
u16 keys80Piccolo80[sizeof(test_vectorsPiccolo80)/sizeof(u64)][KEY80] = {{0x1100, 0x3322, 0x5544, 0x7766, 0x9988}, {0x0fbb, 0x83f6, 0x94d5, 0xa445, 0x9120}};
u64 test_vectorsPiccolo80results[sizeof(test_vectorsPiccolo80)/sizeof(u64)] = {0x5640f83599ff2b8dULL, 0xccbf57920c60a302ULL};
/* Piccolo128 test vectors */
u64 test_vectorsPiccolo128[] = {0xefcdab8967452301ULL, 0x517fe322009f2f67};
u16 keys128Piccolo128[sizeof(test_vectorsPiccolo128)/sizeof(u64)][KEY128] = {{0x1100, 0x3322, 0x5544, 0x7766, 0x9988, 0xbbaa, 0xddcc, 0xffee}, {0x0fbb, 0x83f6, 0x94d5, 0xa445, 0x9120, 0x5926, 0x74f7, 0x7d76}};
u64 test_vectorsPiccolo128results[sizeof(test_vectorsPiccolo128)/sizeof(u64)] = {0xff897b65ea2cc45eULL, 0x6b806ca361beee6cULL};
