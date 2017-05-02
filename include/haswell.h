#ifndef __HASWELL__
#define __HASWELL__

#define TYPE_PTR volatile char **

typedef struct node {
  node *forward;
  node *backward;
  TYPE_PTR p;
} Node;


volatile char **B;
volatile char **C;
volatile char **D;
volatile char **E;

//volatile char **init_prime;
//volatile char **init_reprime;

int haswell_i7_4600m_cache_slice_from_virt(void* addr);
int haswell_i7_4600m_cache_slice_alg(uintptr_t addr);
int haswell_i7_4600m_setup(unsigned long int monline);
void haswell_i7_4600m_prime();
void haswell_i7_4600m_reprime();
unsigned long int haswell_i7_4600m_probe();

uint32_t cycles_low_start;
uint32_t cycles_high_start;
uint32_t cycles_low_stop;
uint32_t cycles_high_stop;


unsigned long int get_global_timestamp_start(void);
unsigned long int get_global_timestamp_stop(void);

inline bool checkElapsed(uint64_t start, uint64_t total) {
  uint32_t ch, cl;
  __asm volatile ("rdtscp\n\t" :  "=a"(cl), "=d"(ch));
  return ((((uint64_t)ch << 32) | cl) - start) > total;
}

inline uint64_t getTime() {
  uint32_t ch, cl;
  __asm volatile ("rdtscp\n\t" :  "=a"(cl), "=d"(ch));
  return (((uint64_t)ch << 32) | cl);
}

#define KB(x) x*1024
#define MB(x) x*1024*1024

#define TIMESTAMP_START asm volatile (".align 16\n\t" "CPUID\n\t" "CPUID\n\t" "CPUID\n\t" "RDTSC\n\t" "mov %%edx, %0\n\t" "mov %%eax, %1\n\t": "=r" (cycles_high_start), "=r" (cycles_low_start)::"%rax", "%rbx", "%rcx", "%rdx")
#define TIMESTAMP_STOP asm volatile ("RDTSCP\n\t" "mov %%edx, %0\n\t" "mov %%eax, %1\n\t" "CPUID\n\t": "=r" (cycles_high_stop), "=r" (cycles_low_stop)::"%rax", "%rbx", "%rcx", "%rdx")

#define REPEAT_FOR(cs) uint64_t __start = getTime(); while (!checkElapsed(__start, (cs)))

#endif
