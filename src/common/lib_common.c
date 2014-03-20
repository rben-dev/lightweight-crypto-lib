#include <stdint.h>

/*** Common stuff for all the algorithms ****/
/* For thread-safety */
/* This is only useful for bitslice based implementations */
#ifdef THREAD_SAFE
#ifdef BITSLICE
#include <pthread.h>
pthread_mutex_t bitslice_init_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif
#endif

#ifdef MEASURE_PERF
/* Global variables to keep track of */
/* performance measurements          */
uint64_t key_schedule_start = 0;
uint64_t key_schedule_end = 0;
uint64_t encrypt_start = 0;
uint64_t encrypt_end = 0;
#endif
