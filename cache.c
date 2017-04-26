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

#define SET_INDEX(x) ((((uintptr_t)x)>>6)&((1<<11)-1))
#define CYCLE_LIMIT 130
#define TYPE_PTR volatile uint64_t*
#define TYPE volatile uint64_t

#define ADDRESS

#define START_ADDR (void *)(0x0UL)
#define FLAGS (MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB)
#define PROTECTION (PROT_READ | PROT_WRITE)

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
//      "xor %eax, %eax\n\t"
//      "cpuid\n\t"
//      "xor %eax, %eax\n\t"
//      "cpuid\n\t"
//      "xor %eax, %eax\n\t"
//      "cpuid\n\t");
      "lfence\n\t");
  __asm volatile ("rdtsc" : "=a"(sl), "=d"(sh));
  __asm volatile ("movq %0, %%rbx" : :"m"(*candidate));
  //__asm volatile ("xor %eax, %eax\n\tcpuid\n\t");
  __asm volatile ("lfence\n\t");
  __asm volatile ("rdtscp\n\t" :  "=a"(el), "=d"(eh));
  return (((uint64_t)eh << 32) | el) - (((uint64_t)sh << 32) | sl);
}

bool probe(vector<TYPE_PTR> s, TYPE_PTR candidate) {
  __asm volatile ("movq %0, %%rbx" : :"m"(*candidate));
  for(auto l: s) {
    __asm volatile ("movq %0, %%rcx" : :"m"(*l));
  }
  auto t = atime(candidate);
  //cout << t << " " << atime(candidate) << endl;
  return t > CYCLE_LIMIT;
  //return atime(candidate) > CYCLE_LIMIT;
}

bool probeExcept(vector<TYPE_PTR> s, TYPE_PTR candidate, TYPE_PTR except) {
  __asm volatile ("movq %0, %%rbx" : :"m"(*candidate));
  for(auto l: s) {
    if (l == except) {
      continue;
    }
    __asm volatile ("movq %0, %%rcx" : :"m"(*l));
  }
  auto t = atime(candidate);
  //cout << t << " " << atime(candidate) << endl;
  return t > CYCLE_LIMIT;
  //return atime(candidate) > CYCLE_LIMIT;
}

template <typename T>
void remove_at(std::vector<T>& v, typename std::vector<T>::size_type n)
{
    std::swap(v[n], v.back());
    v.pop_back();
}

template <typename T>
vector<T> difference(vector<T> ao, vector<T> bo)
{
  vector<T> a(ao.size());
  copy(ao.begin(), ao.end(), a.begin());

  vector<T> b(bo.size());
  copy(bo.begin(), bo.end(), b.begin());

  std::sort (a.begin(),a.end());
  std::sort (b.begin(),b.end());
  //cout << "a.size " << a.size() << " b.size " << b.size() << endl;
  vector<T> vDifference;
  set_difference(
    a.begin(),
    a.end(),
    b.begin(),
    b.end(),
    back_inserter(vDifference));
  //cout << "diff.size " << vDifference.size() << endl;
  return vDifference;
}
template <typename T>
vector<T> clone(vector<T> a) {
  vector<T> b(a.size());
  copy(a.begin(), a.end(), b.begin());
  return b;
}

vector<vector<TYPE_PTR> > getEvictionSet(vector<TYPE_PTR> lines) {
  vector<TYPE_PTR> cs, conflictSet, badConflict, goodConflict;
  random_shuffle(lines.begin(), lines.end(), myrandom);
  vector<vector<TYPE_PTR> > eviction_sets;
  int i;
  for (auto candidate : lines) {
    if (! (probe(conflictSet, candidate) && probe(conflictSet, candidate))) {
      conflictSet.push_back(candidate);
    }
    //if (i++ > 120) {
    //  return NULL;
    //}
  }

  for (auto candidate: conflictSet) {
    bool flag = false;
    for (auto candidate2: conflictSet) {
      if (!(probeExcept(conflictSet, candidate, candidate2) && probeExcept(conflictSet, candidate, candidate2))) {
        flag = true;
        break;
      }
    }
    if (!flag) {
      badConflict.push_back(candidate);
      //cout << (uintptr_t) candidate << " is a bad conflict" << endl;
    } else {
      //cout << (uintptr_t) candidate << " is a good conflict" << endl;
    }
  }
  goodConflict = difference(conflictSet, badConflict);
  cout << "conflictSet size " << conflictSet.size() << endl;
  cout << "lines size " << lines.size() << endl;
  cout << "cs size " << cs.size() << endl;
  cout << "goodConflict size " << goodConflict.size() << endl;
  //auto diff = difference(lines, conflictSet);
  auto diff = difference(lines, goodConflict);
  cout << "diff set size " << diff.size() << endl;
  random_shuffle(diff.begin(), diff.end(), myrandom);
  vector<TYPE_PTR> currentConflict = goodConflict;
  cout << endl;
  int j = 0;
  for (auto candidate: diff) {
    if (currentConflict.size() == 0) {
      cout << "We are out of conflictSet" << endl;
      break;
    }
    if (probe(currentConflict, candidate) && probe(currentConflict, candidate)) {
      vector<TYPE_PTR> evictionSet;
      for(auto l : currentConflict) {
        if (!(probeExcept(currentConflict, candidate, l) && probeExcept(currentConflict, candidate, l))) {
          evictionSet.push_back(l);
        } else {
          //cout << "removing " << (uintptr_t) l << " does not make " << (uintptr_t) candidate << " not conflicting" << endl;
        }
      }
      if (evictionSet.size() > 0) {
        eviction_sets.push_back(evictionSet);
        cout << "eviction set size " << evictionSet.size() << endl;
        //cout << j << endl;
        //printf("%x\n", candidate);
        currentConflict = difference(currentConflict, evictionSet);
      } else {
        cout << "No eviction set found" << endl;
      }
    } else {
      //cout << (uintptr_t) candidate << " is not conflicting" << endl;
    }
    j++;
  }
  cout << "We are out of diff" << endl;
  return eviction_sets;
}

uint8_t getHaswelSlice(uintptr_t p) {
  uint8_t slice = 0;
  slice ^= (p>>17)&1;
  slice ^= (p>>18)&1;
  slice ^= (p>>20)&1;
  slice ^= (p>>22)&1;
  slice ^= (p>>24)&1;
  slice ^= (p>>25)&1;
  slice ^= (p>>26)&1;
  slice ^= (p>>27)&1;
  slice ^= (p>>28)&1;
  slice ^= (p>>30)&1;
  slice ^= (p>>32)&1;
  slice ^= (p>>33)&1; // Alexdros code cattack 1570
  return slice;
}

vector<vector<TYPE_PTR>> getHaswelEvictionSets(vector<TYPE_PTR> pc) {
  vector<vector<TYPE_PTR>> evictionSets(2);
  vector<TYPE_PTR> a,b;
  for (auto l: pc) {
    if (getHaswelSlice(vtop((uintptr_t)l))) {
      a.push_back(l);
    } else {
      b.push_back(l);
    }
  }
  evictionSets[0] = a;
  evictionSets[1] = b;
  return evictionSets;
}

TYPE_PTR createProbingList(int length) {
}

vector<TYPE_PTR> generatePotentialConflicting(TYPE_PTR start, int size, uint16_t setIndex) {
  vector<TYPE_PTR> v;
  cout << "Generating for set index " << setIndex << endl;
  for (TYPE_PTR i=start; i < start+size; i++) {
    if (SET_INDEX(ADDRESS(i))==setIndex) {
      v.push_back((TYPE_PTR)i);
    }
  }
  return v;
}

bool continousPrime(vector<TYPE_PTR> pc) {
  bool flag = false;
  TYPE x = 5;
  for (int j = 0; j < 10000; j++) {
    if (probe(pc, &x)) {
      flag=true;
    }
  }
  return flag;
}

int BUFFER_SIZE = 3*3*1024*1024;

int main() {
  //TYPE_PTR x = (TYPE_PTR) malloc(BUFFER_SIZE*sizeof(uint8_t));
  TYPE_PTR x = (TYPE_PTR) mmap(START_ADDR, BUFFER_SIZE*sizeof(TYPE), PROTECTION, FLAGS, 0, 0);
  for (int i=0; i<BUFFER_SIZE; i++) {
    x[i] = i%255;
  }
  auto pc = generatePotentialConflicting(x, BUFFER_SIZE, SET_INDEX(ADDRESS((uintptr_t)x+0x900)));
  auto eviction_sets = getEvictionSet(pc);
  cout << "test starting" << endl;
  while (true) {
    int i=0;
    for (auto es: eviction_sets) {
      cout << ".";
      if (continousPrime(es)) {
        //cout << "Thrashing detected @ index " << i << endl;
        cout << i << flush;
      }
      i++;
    }
  }
  cout << endl;
  cout << "================= second try" << endl;
  cout << endl;
  pc = generatePotentialConflicting(x, BUFFER_SIZE, SET_INDEX(ADDRESS((uintptr_t)x+0x900)));
  getEvictionSet(pc);
  //cout << "next set index" << endl;
  //pc = generatePotentialConflicting((uintptr_t)x, BUFFER_SIZE, SET_INDEX(ADDRESS((uintptr_t)x+1279)));
  //es = getEvictionSet(pc);
  //if (es) {
  //  cout << "eviction set size " << es->size() << endl;
  //}
  //for (auto addr: es) {
  //  printf("%x\n", addr);
  //}
  //int count = 0;
  //cout << BUFFER_SIZE*1.0/count << endl;
  //for (int i=0; i<BUFFER_SIZE; i+=BUFFER_SIZE/32) {
  //  uintptr_t a = vtop((uintptr_t)&(x[i]));
  //  //printf("%#015x \t %#015x\n", a, &(x[i]));
  //}
}

