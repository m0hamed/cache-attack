#include <stdio.h>
#include "unistd.h"
#include "inttypes.h"
#include "stdlib.h"
#include "assert.h"
#include <set>
#include <time.h>
#include <iostream>
#include <random>
#include <algorithm>
#include <vector>
#include <map>
#include <sys/mman.h>

#define SET_INDEX(x) ((((uintptr_t)x)>>6)&((1<<10)-1))
#define CYCLE_LIMIT 180
#define TYPE uint8_t
#define TYPE_PTR TYPE*

#define START_ADDR (void *)(0x0UL)
#define FLAGS (MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB)
#define PROTECTION (PROT_READ | PROT_WRITE)
#define MESSAGE_SIZE 1024
#define ADDRESS

using namespace std;

std::random_device rd{};
std::mt19937 engine{rd()};
int myrandom (int i) {
  return uniform_int_distribution<int>(0,i-1)(engine);
}

uintptr_t vtop(uintptr_t vaddr) {
    FILE *pagemap;
    intptr_t paddr = 0;
    uint64_t offset = (vaddr / sysconf(_SC_PAGESIZE)) * sizeof(uint64_t);
    uint64_t e;

    // https://www.kernel.org/doc/Documentation/vm/pagemap.txt
    if ((pagemap = fopen("/proc/self/pagemap", "r"))) {
        if (lseek(fileno(pagemap), offset, SEEK_SET) == offset) {
            if (fread(&e, sizeof(uint64_t), 1, pagemap)) {
                if (e & (1ULL << 63)) { // page present ?
                    paddr = e & ((1ULL << 54) - 1); // pfn mask
                    paddr = paddr * sysconf(_SC_PAGESIZE);
                    // add offset within page
                    paddr = paddr | (vaddr & (sysconf(_SC_PAGESIZE) - 1));
                }
            }
        }
        fclose(pagemap);
    }

    return paddr;
}

inline uint64_t atime(TYPE_PTR candidate) {
  uint64_t s, e;
  uint32_t sh, sl, eh, el;
  __asm volatile (".align 16\n\t"
      "lfence\n\t");
  __asm volatile ("rdtsc" : "=a"(sl), "=d"(sh));
  __asm volatile ("movb %0, %%bl" : :"m"(*candidate));
  __asm volatile ("lfence\n\t");
  __asm volatile ("rdtscp\n\t" :  "=a"(el), "=d"(eh));
  return (((uint64_t)eh << 32) | el) - (((uint64_t)sh << 32) | sl);
}

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

bool probe(vector<TYPE_PTR> s, TYPE_PTR candidate) {
  __asm volatile ("movb %0, %%bl" : :"m"(*candidate));
  for(auto l: s) {
    __asm volatile ("movb %0, %%cl" : :"m"(*l));
  }
  auto t = atime(candidate);
  //cout << t << " " << atime(candidate) << endl;
  return t > CYCLE_LIMIT;
  //return atime(candidate) > CYCLE_LIMIT;
}

bool probeExcept(vector<TYPE_PTR> s, TYPE_PTR candidate, TYPE_PTR except) {
  __asm volatile ("movb %0, %%bl" : :"m"(*candidate));
  for(auto l: s) {
    if (l == except) {
      continue;
    }
    __asm volatile ("movb %0, %%cl" : :"m"(*l));
  }
  auto t = atime(candidate);
  //cout << t << " " << atime(candidate) << endl;
  return t > CYCLE_LIMIT;
  //return atime(candidate) > CYCLE_LIMIT;
}

vector<TYPE_PTR> generatePotentialConflicting(uintptr_t start, int size, uint16_t setIndex) {
  vector<TYPE_PTR> v;
  cout << "Generating for set index " << setIndex << endl;
  for (uintptr_t i=start; i < start+size; i++) {
    if (SET_INDEX(i)==setIndex) {
      v.push_back((TYPE_PTR)i);
    }
  }
  return v;
}

inline void busyWait(uint64_t wait) {
  uint64_t start = getTime();
  while (!checkElapsed(start, wait)) {
    //do nothing
  }
}

void continousAccess(TYPE_PTR l1, TYPE_PTR l0, uint64_t tMark, uint64_t tPause,
    bool* D, int dLength) {
  for (int i=0; i<dLength; i++) {
    if(D[i]) {
      uint64_t start = getTime();
      while (!checkElapsed(start, tMark)) {
        __asm volatile ("movb %0, %%cl" : :"m"(*l1));
      }
      busyWait(tPause);
    } else {
      uint64_t start = getTime();
      while (!checkElapsed(start, tMark)) {
        __asm volatile ("movb %0, %%bl" : :"m"(*l0));
      }
      busyWait(tPause);
    }
  }
}

int BUFFER_SIZE = 3*1024*1024;

bool* getMessage(int size) {
  bool* message = (bool*) malloc(size*sizeof(bool));
  for (int i=0; i<size; i++) {
    message[i] = i%2==0;
    //message[i] = false;
  }
  return message;
}

void getLines(uint16_t s0, uint16_t s1, TYPE_PTR buffer, int size,
    TYPE_PTR* l0, TYPE_PTR* l1) {
  bool s0_set = false;
  bool s1_set = false;
  for (TYPE_PTR i=buffer; i < buffer+size; i++) {
    if (s0_set && s1_set) {
      return;
    }
    if (!s0_set && SET_INDEX(ADDRESS(i))==s0) {
      *l0 = i;
      continue;
    }
    if (!s1_set && SET_INDEX(ADDRESS(i))==s1) {
      *l1 = i;
      continue;
    }
  }
}

int main() {
  bool* D = getMessage(MESSAGE_SIZE);
  TYPE_PTR x = (TYPE_PTR) mmap(START_ADDR, BUFFER_SIZE*sizeof(TYPE), PROTECTION,
      FLAGS, 0, 0);
  for (int i=0; i<BUFFER_SIZE*sizeof(TYPE); i++) {
    *(x+i) = i%255;
  }
  TYPE_PTR l0;
  TYPE_PTR l1;
  uint16_t s0 = SET_INDEX(ADDRESS((uintptr_t)x+0x900));
  uint16_t s1 = SET_INDEX(ADDRESS((uintptr_t)x+0x1000));
  getLines(s0, s1, x, BUFFER_SIZE*sizeof(TYPE), &l0, &l1);
  printf("\n%016" PRIXPTR " : \n", vtop((uintptr_t)l0));
  printf("\n%016" PRIXPTR " : \n", vtop((uintptr_t)l1));
  while (true) {
    continousAccess(l0,l1, 100000, 100, D, MESSAGE_SIZE);
  }
  //auto es = getEvictionSet(pc);
  cout << "next set index" << endl;
}

