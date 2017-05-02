#include <stdio.h>
#include "unistd.h"
#include "inttypes.h"
#include "stdlib.h"
#include "haswell.h"
#include <sys/mman.h>
#include <vector>
#include <iostream>
#include <fstream>

using namespace std;

void ptr2bin(void* ptr, char bin[65]) {
	unsigned long int ptr_int = (unsigned long int)ptr;
	for (int i = 0; i < 64; ++i) {
		if (ptr_int & 0x1) bin[i] = '1'; else bin[i] = '0';
		ptr_int = ptr_int >> 1;
	}
	bin[64] = '\0';
}

void printPtr2bin(void* ptr) {
	char bin[65];
	ptr2bin((void *)ptr, bin);
	for (int i = 0; i < 8; ++i) {
		for (int j = 0; j < 8; ++j) {
			printf("%c", bin[63-(i*8+j)]);
		}
		printf(" ");
	}
	printf("\n");
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


int haswell_i7_4600m_cache_slice_alg(uintptr_t i_addr) {
    //printf("haswell_i7_4600m_cache_slice\n");
    //unsigned long int x = ((unsigned long int*)addr)[0];
    //unsigned long int i_addr = (unsigned long int) get_pfn(addr);

    //printf("\n%016" PRIXPTR " : \n", i_addr);


    // According to Reverse Engineering Intel Last-Level Cache Complex Addressing Using Performace Counters
    // Xeon & Core (4 core - from bit 17 and above)
    int bit0 = ((i_addr & 0x000020000) >> 17) ^ ((i_addr & 0x000040000) >> 18)
             ^ ((i_addr & 0x000100000) >> 20) ^ ((i_addr & 0x000400000) >> 22)
             ^ ((i_addr & 0x001000000) >> 24) ^ ((i_addr & 0x002000000) >> 25)
             ^ ((i_addr & 0x004000000) >> 26) ^ ((i_addr & 0x008000000) >> 27)
             ^ ((i_addr & 0x010000000) >> 28) ^ ((i_addr & 0x040000000) >> 30)
             ^ ((i_addr & 0x100000000) >> 32) ^ ((i_addr & 0x200000000) >> 33);

    return bit0;
}


int haswell_i7_4600m_cache_slice_from_virt(void* addr) {
    return haswell_i7_4600m_cache_slice_alg(vtop((uintptr_t)addr));
}
// Ivy Bridge i7-3770 FUNCTIONS

int haswell_i7_4600m_setup(unsigned long int monline, Node** start) {
    //printf("haswell_i7_4600m_setup\n");
    uint64_t cache_line_check_offset = monline & 0x00001FFFF;  // 0001 1111 1111 1111 1111
    //printf("cache line offset");
    //printPtr2bin((void *)cache_line_check_offset);
    size_t mem_length = (size_t)MB(2);
    int i = 0;
    //int mem_length_char = ((int)mem_length/sizeof(char));
    //int mem_length_ptr = (int)mem_length/sizeof(void *);

// Cache slice selection algorithm needs verification
// p17 ⊕ p18 ⊕ p20 ⊕ p22 ⊕ p24 ⊕ p25 ⊕ p26 ⊕ p27 ⊕ p28 ⊕ p30 ⊕ p32
// p18 ⊕ p19 ⊕ p21 ⊕ p23 ⊕ p25 ⊕ p27 ⊕ p29 ⊕ p30 ⊕ p31 ⊕ p32

    int monline_cache_slice = haswell_i7_4600m_cache_slice_alg( monline);
    //printf("monline_cache_slice\t:\t%d\n", monline_cache_slice);

    void *tmp[128];
    int B_idx = -1;
    int C_idx = -1;
    int D_idx = -1;
    int E_idx = -1;

    int cache_slice_pattern[4][4];

    cache_slice_pattern[0][0] = 0x0;
    cache_slice_pattern[0][1] = 0x7;
    cache_slice_pattern[0][2] = 0x9;
    cache_slice_pattern[0][3] = 0xe;

    cache_slice_pattern[1][0] = 0x1;
    cache_slice_pattern[1][1] = 0x6;
    cache_slice_pattern[1][2] = 0x8;
    cache_slice_pattern[1][3] = 0xf;

    cache_slice_pattern[2][0] = 0x2;
    cache_slice_pattern[2][1] = 0x5;
    cache_slice_pattern[2][2] = 0xb;
    cache_slice_pattern[2][3] = 0xc;

    cache_slice_pattern[3][0] = 0x3;
    cache_slice_pattern[3][1] = 0x4;
    cache_slice_pattern[3][2] = 0xa;
    cache_slice_pattern[3][3] = 0xd;


    for (i = 0; i < 128; ++i) tmp[i] = NULL;

    for (i = 0; i < 128; ++i) {
        tmp[i] = mmap(NULL, mem_length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
        if (tmp[i] == MAP_FAILED) {
          return 0;
        }
        if (haswell_i7_4600m_cache_slice_from_virt(tmp[i]) == monline_cache_slice) {     //monline_cache_slice
            if (B_idx == -1) {
                B = (volatile char **)tmp[i];
                B_idx = i;
                continue;
            }
            if (C_idx == -1) {
                C = (volatile char **)tmp[i];
                C_idx = i;
                continue;
            }
            if (D_idx == -1) {
                D = (volatile char **)tmp[i];
                D_idx = i;
                continue;
            }
            if (E_idx == -1) {
                E = (volatile char **)tmp[i];
                E_idx = i;
                break;
            }
        }
    }

    //printf("B_idx\t:\t%d\n", B_idx);
    //printf("C_idx\t:\t%d\n", C_idx);
    //printf("D_idx\t:\t%d\n", D_idx);
    //printf("E_idx\t:\t%d\n", E_idx);

    if (B_idx == -1 || C_idx == -1 || D_idx == -1 || E_idx == -1) return 0;

    // THIS FOR LOOP NEEDS REVISION (is munmap((void *) addr, size_t length) relieasing the hugepage as expected?)
    for (i = 0; i < 128; ++i) {
        //printf("i\t:\t%d\n", i);
        if (i != B_idx && i != C_idx && i != D_idx && i != E_idx && tmp[i] != NULL) {
            munmap(tmp[i], MB(2));
        }
    }



    //B = mmap(NULL, mem_length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
    //C = mmap(NULL, mem_length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);

    *start = (Node*) malloc(sizeof(Node));
    (**start).p = B + (cache_slice_pattern[monline_cache_slice][0] << 17)/8 + cache_line_check_offset/8;
    Node *next = (Node*) malloc(sizeof(Node));
    (**start).forward = next;
    next->backward = *start;
    next->p = (volatile char **)(B + (cache_slice_pattern[monline_cache_slice][1] << 17)/8 + cache_line_check_offset/8);
    next->forward = (Node*) malloc(sizeof(Node));
    next->forward->backward = next;
    next = next->forward;
    next->p = (volatile char **)(B + (cache_slice_pattern[monline_cache_slice][2] << 17)/8 + cache_line_check_offset/8);
    next->forward = (Node*) malloc(sizeof(Node));
    next->forward->backward = next;
    next = next->forward;
    next->p = (volatile char **)(B + (cache_slice_pattern[monline_cache_slice][3] << 17)/8 + cache_line_check_offset/8);
    next->forward = (Node*) malloc(sizeof(Node));
    next->forward->backward = next;
    next = next->forward;
    next->p = (volatile char **)(C + (cache_slice_pattern[monline_cache_slice][0] << 17)/8 + cache_line_check_offset/8);
    next->forward = (Node*) malloc(sizeof(Node));
    next->forward->backward = next;
    next = next->forward;
    next->p = (volatile char **)(C + (cache_slice_pattern[monline_cache_slice][1] << 17)/8 + cache_line_check_offset/8);
    next->forward = (Node*) malloc(sizeof(Node));
    next->forward->backward = next;
    next = next->forward;
    next->p = (volatile char **)(C + (cache_slice_pattern[monline_cache_slice][2] << 17)/8 + cache_line_check_offset/8);
    next->forward = (Node*) malloc(sizeof(Node));
    next->forward->backward = next;
    next = next->forward;
    next->p = (volatile char **)(C + (cache_slice_pattern[monline_cache_slice][3] << 17)/8 + cache_line_check_offset/8);
    next->forward = (Node*) malloc(sizeof(Node));
    next->forward->backward = next;
    next = next->forward;
    next->p = (volatile char **)(D + (cache_slice_pattern[monline_cache_slice][0] << 17)/8 + cache_line_check_offset/8);
    next->forward = (Node*) malloc(sizeof(Node));
    next->forward->backward = next;
    next = next->forward;
    next->p = (volatile char **)(D + (cache_slice_pattern[monline_cache_slice][1] << 17)/8 + cache_line_check_offset/8);
    next->forward = (Node*) malloc(sizeof(Node));
    next->forward->backward = next;
    next = next->forward;
    next->p = (volatile char **)(D + (cache_slice_pattern[monline_cache_slice][2] << 17)/8 + cache_line_check_offset/8);
    next->forward = (Node*) malloc(sizeof(Node));
    next->forward->backward = next;
    next = next->forward;
    next->p = (volatile char **)(D + (cache_slice_pattern[monline_cache_slice][3] << 17)/8 + cache_line_check_offset/8);
    next->forward = (Node*) malloc(sizeof(Node));
    next->forward->backward = next;
    next = next->forward;
    next->p = (volatile char **)(E + (cache_slice_pattern[monline_cache_slice][0] << 17)/8 + cache_line_check_offset/8);
    next->forward = (Node*) malloc(sizeof(Node));
    next->forward->backward = next;
    next = next->forward;
    next->p = (volatile char **)(E + (cache_slice_pattern[monline_cache_slice][1] << 17)/8 + cache_line_check_offset/8);
    next->forward = (Node*) malloc(sizeof(Node));
    next->forward->backward = next;
    next = next->forward;
    next->p = (volatile char **)(E + (cache_slice_pattern[monline_cache_slice][2] << 17)/8 + cache_line_check_offset/8);
    next->forward = (Node*) malloc(sizeof(Node));
    next->forward->backward = next;
    next = next->forward;
    next->p = (volatile char **)(E + (cache_slice_pattern[monline_cache_slice][3] << 17)/8 + cache_line_check_offset/8);
    next->forward = *start;
    (**start).backward = next;

    B[(cache_slice_pattern[monline_cache_slice][0] << 17)/8 + cache_line_check_offset/8] = (volatile char *)(B + (cache_slice_pattern[monline_cache_slice][1] << 17)/8 + cache_line_check_offset/8);
    B[(cache_slice_pattern[monline_cache_slice][1] << 17)/8 + cache_line_check_offset/8] = (volatile char *)(B + (cache_slice_pattern[monline_cache_slice][2] << 17)/8 + cache_line_check_offset/8);
    B[(cache_slice_pattern[monline_cache_slice][2] << 17)/8 + cache_line_check_offset/8] = (volatile char *)(B + (cache_slice_pattern[monline_cache_slice][3] << 17)/8 + cache_line_check_offset/8);
    B[(cache_slice_pattern[monline_cache_slice][3] << 17)/8 + cache_line_check_offset/8] = (volatile char *)(C + (cache_slice_pattern[monline_cache_slice][0] << 17)/8 + cache_line_check_offset/8);

    C[(cache_slice_pattern[monline_cache_slice][0] << 17)/8 + cache_line_check_offset/8] = (volatile char *)(C + (cache_slice_pattern[monline_cache_slice][1] << 17)/8 + cache_line_check_offset/8);
    C[(cache_slice_pattern[monline_cache_slice][1] << 17)/8 + cache_line_check_offset/8] = (volatile char *)(C + (cache_slice_pattern[monline_cache_slice][2] << 17)/8 + cache_line_check_offset/8);
    C[(cache_slice_pattern[monline_cache_slice][2] << 17)/8 + cache_line_check_offset/8] = (volatile char *)(C + (cache_slice_pattern[monline_cache_slice][3] << 17)/8 + cache_line_check_offset/8);
    C[(cache_slice_pattern[monline_cache_slice][3] << 17)/8 + cache_line_check_offset/8] = (volatile char *)(D + (cache_slice_pattern[monline_cache_slice][0] << 17)/8 + cache_line_check_offset/8);

    D[(cache_slice_pattern[monline_cache_slice][0] << 17)/8 + cache_line_check_offset/8] = (volatile char *)(D + (cache_slice_pattern[monline_cache_slice][1] << 17)/8 + cache_line_check_offset/8);
    D[(cache_slice_pattern[monline_cache_slice][1] << 17)/8 + cache_line_check_offset/8] = (volatile char *)(D + (cache_slice_pattern[monline_cache_slice][2] << 17)/8 + cache_line_check_offset/8);
    D[(cache_slice_pattern[monline_cache_slice][2] << 17)/8 + cache_line_check_offset/8] = (volatile char *)(D + (cache_slice_pattern[monline_cache_slice][3] << 17)/8 + cache_line_check_offset/8);
    D[(cache_slice_pattern[monline_cache_slice][3] << 17)/8 + cache_line_check_offset/8] = (volatile char *)(E + (cache_slice_pattern[monline_cache_slice][0] << 17)/8 + cache_line_check_offset/8);

    E[(cache_slice_pattern[monline_cache_slice][0] << 17)/8 + cache_line_check_offset/8] = (volatile char *)(E + (cache_slice_pattern[monline_cache_slice][1] << 17)/8 + cache_line_check_offset/8);
    E[(cache_slice_pattern[monline_cache_slice][1] << 17)/8 + cache_line_check_offset/8] = (volatile char *)(E + (cache_slice_pattern[monline_cache_slice][2] << 17)/8 + cache_line_check_offset/8);
    E[(cache_slice_pattern[monline_cache_slice][2] << 17)/8 + cache_line_check_offset/8] = (volatile char *)(E + (cache_slice_pattern[monline_cache_slice][3] << 17)/8 + cache_line_check_offset/8);
    E[(cache_slice_pattern[monline_cache_slice][3] << 17)/8 + cache_line_check_offset/8] = (volatile char *)(B + (cache_slice_pattern[monline_cache_slice][0] << 17)/8 + cache_line_check_offset/8);


    //if ( ((cache_slice_pattern[monline_cache_slice][3] << 17) + cache_line_check_offset + KB(32)) < MB(2) ) {
    //    B[(cache_slice_pattern[monline_cache_slice][0] << 17)/8 + cache_line_check_offset/8 + KB(32)/8] = (volatile char *)(B + (cache_slice_pattern[monline_cache_slice][1] << 17)/8 + cache_line_check_offset/8 + KB(32)/8);
    //    B[(cache_slice_pattern[monline_cache_slice][1] << 17)/8 + cache_line_check_offset/8 + KB(32)/8] = (volatile char *)(B + (cache_slice_pattern[monline_cache_slice][2] << 17)/8 + cache_line_check_offset/8 + KB(32)/8);
    //    B[(cache_slice_pattern[monline_cache_slice][2] << 17)/8 + cache_line_check_offset/8 + KB(32)/8] = (volatile char *)(B + (cache_slice_pattern[monline_cache_slice][3] << 17)/8 + cache_line_check_offset/8 + KB(32)/8);
    //    B[(cache_slice_pattern[monline_cache_slice][3] << 17)/8 + cache_line_check_offset/8 + KB(32)/8] = (volatile char *)(C + (cache_slice_pattern[monline_cache_slice][0] << 17)/8 + cache_line_check_offset/8 + KB(32)/8);

    //    C[(cache_slice_pattern[monline_cache_slice][0] << 17)/8 + cache_line_check_offset/8 + KB(32)/8] = (volatile char *)(C + (cache_slice_pattern[monline_cache_slice][1] << 17)/8 + cache_line_check_offset/8 + KB(32)/8);
    //    C[(cache_slice_pattern[monline_cache_slice][1] << 17)/8 + cache_line_check_offset/8 + KB(32)/8] = (volatile char *)(C + (cache_slice_pattern[monline_cache_slice][2] << 17)/8 + cache_line_check_offset/8 + KB(32)/8);
    //    C[(cache_slice_pattern[monline_cache_slice][2] << 17)/8 + cache_line_check_offset/8 + KB(32)/8] = (volatile char *)(C + (cache_slice_pattern[monline_cache_slice][3] << 17)/8 + cache_line_check_offset/8 + KB(32)/8);
    //    C[(cache_slice_pattern[monline_cache_slice][3] << 17)/8 + cache_line_check_offset/8 + KB(32)/8] = (volatile char *)(D + (cache_slice_pattern[monline_cache_slice][0] << 17)/8 + cache_line_check_offset/8 + KB(32)/8);

    //    D[(cache_slice_pattern[monline_cache_slice][0] << 17)/8 + cache_line_check_offset/8 + KB(32)/8] = (volatile char *)(D + (cache_slice_pattern[monline_cache_slice][1] << 17)/8 + cache_line_check_offset/8 + KB(32)/8);
    //    D[(cache_slice_pattern[monline_cache_slice][1] << 17)/8 + cache_line_check_offset/8 + KB(32)/8] = (volatile char *)(D + (cache_slice_pattern[monline_cache_slice][2] << 17)/8 + cache_line_check_offset/8 + KB(32)/8);
    //    D[(cache_slice_pattern[monline_cache_slice][2] << 17)/8 + cache_line_check_offset/8 + KB(32)/8] = (volatile char *)(D + (cache_slice_pattern[monline_cache_slice][3] << 17)/8 + cache_line_check_offset/8 + KB(32)/8);
    //    D[(cache_slice_pattern[monline_cache_slice][3] << 17)/8 + cache_line_check_offset/8 + KB(32)/8] = (volatile char *)(E + (cache_slice_pattern[monline_cache_slice][0] << 17)/8 + cache_line_check_offset/8 + KB(32)/8);

    //    E[(cache_slice_pattern[monline_cache_slice][0] << 17)/8 + cache_line_check_offset/8 + KB(32)/8] = (volatile char *)(E + (cache_slice_pattern[monline_cache_slice][1] << 17)/8 + cache_line_check_offset/8 + KB(32)/8);
    //    E[(cache_slice_pattern[monline_cache_slice][1] << 17)/8 + cache_line_check_offset/8 + KB(32)/8] = (volatile char *)(E + (cache_slice_pattern[monline_cache_slice][2] << 17)/8 + cache_line_check_offset/8 + KB(32)/8);
    //    E[(cache_slice_pattern[monline_cache_slice][2] << 17)/8 + cache_line_check_offset/8 + KB(32)/8] = (volatile char *)(E + (cache_slice_pattern[monline_cache_slice][3] << 17)/8 + cache_line_check_offset/8 + KB(32)/8);
    //    E[(cache_slice_pattern[monline_cache_slice][3] << 17)/8 + cache_line_check_offset/8 + KB(32)/8] = (volatile char *)(B + (cache_slice_pattern[monline_cache_slice][0] << 17)/8 + cache_line_check_offset/8 + KB(32)/8);


    //    init_reprime = B + (cache_slice_pattern[monline_cache_slice][0] << 17)/8 + cache_line_check_offset/8 + KB(32)/8;
    //} else {
    //    B[(cache_slice_pattern[monline_cache_slice][0] << 17)/8 + cache_line_check_offset/8 - KB(32)/8] = (volatile char *)(B + (cache_slice_pattern[monline_cache_slice][1] << 17)/8 + cache_line_check_offset/8 - KB(32)/8);
    //    B[(cache_slice_pattern[monline_cache_slice][1] << 17)/8 + cache_line_check_offset/8 - KB(32)/8] = (volatile char *)(B + (cache_slice_pattern[monline_cache_slice][2] << 17)/8 + cache_line_check_offset/8 - KB(32)/8);
    //    B[(cache_slice_pattern[monline_cache_slice][2] << 17)/8 + cache_line_check_offset/8 - KB(32)/8] = (volatile char *)(B + (cache_slice_pattern[monline_cache_slice][3] << 17)/8 + cache_line_check_offset/8 - KB(32)/8);
    //    B[(cache_slice_pattern[monline_cache_slice][3] << 17)/8 + cache_line_check_offset/8 - KB(32)/8] = (volatile char *)(C + (cache_slice_pattern[monline_cache_slice][0] << 17)/8 + cache_line_check_offset/8 - KB(32)/8);

    //    C[(cache_slice_pattern[monline_cache_slice][0] << 17)/8 + cache_line_check_offset/8 - KB(32)/8] = (volatile char *)(C + (cache_slice_pattern[monline_cache_slice][1] << 17)/8 + cache_line_check_offset/8 - KB(32)/8);
    //    C[(cache_slice_pattern[monline_cache_slice][1] << 17)/8 + cache_line_check_offset/8 - KB(32)/8] = (volatile char *)(C + (cache_slice_pattern[monline_cache_slice][2] << 17)/8 + cache_line_check_offset/8 - KB(32)/8);
    //    C[(cache_slice_pattern[monline_cache_slice][2] << 17)/8 + cache_line_check_offset/8 - KB(32)/8] = (volatile char *)(C + (cache_slice_pattern[monline_cache_slice][3] << 17)/8 + cache_line_check_offset/8 - KB(32)/8);
    //    C[(cache_slice_pattern[monline_cache_slice][3] << 17)/8 + cache_line_check_offset/8 - KB(32)/8] = (volatile char *)(D + (cache_slice_pattern[monline_cache_slice][0] << 17)/8 + cache_line_check_offset/8 - KB(32)/8);

    //    D[(cache_slice_pattern[monline_cache_slice][0] << 17)/8 + cache_line_check_offset/8 - KB(32)/8] = (volatile char *)(D + (cache_slice_pattern[monline_cache_slice][1] << 17)/8 + cache_line_check_offset/8 - KB(32)/8);
    //    D[(cache_slice_pattern[monline_cache_slice][1] << 17)/8 + cache_line_check_offset/8 - KB(32)/8] = (volatile char *)(D + (cache_slice_pattern[monline_cache_slice][2] << 17)/8 + cache_line_check_offset/8 - KB(32)/8);
    //    D[(cache_slice_pattern[monline_cache_slice][2] << 17)/8 + cache_line_check_offset/8 - KB(32)/8] = (volatile char *)(D + (cache_slice_pattern[monline_cache_slice][3] << 17)/8 + cache_line_check_offset/8 - KB(32)/8);
    //    D[(cache_slice_pattern[monline_cache_slice][3] << 17)/8 + cache_line_check_offset/8 - KB(32)/8] = (volatile char *)(E + (cache_slice_pattern[monline_cache_slice][0] << 17)/8 + cache_line_check_offset/8 - KB(32)/8);

    //    E[(cache_slice_pattern[monline_cache_slice][0] << 17)/8 + cache_line_check_offset/8 - KB(32)/8] = (volatile char *)(E + (cache_slice_pattern[monline_cache_slice][1] << 17)/8 + cache_line_check_offset/8 - KB(32)/8);
    //    E[(cache_slice_pattern[monline_cache_slice][1] << 17)/8 + cache_line_check_offset/8 - KB(32)/8] = (volatile char *)(E + (cache_slice_pattern[monline_cache_slice][2] << 17)/8 + cache_line_check_offset/8 - KB(32)/8);
    //    E[(cache_slice_pattern[monline_cache_slice][2] << 17)/8 + cache_line_check_offset/8 - KB(32)/8] = (volatile char *)(E + (cache_slice_pattern[monline_cache_slice][3] << 17)/8 + cache_line_check_offset/8 - KB(32)/8);
    //    E[(cache_slice_pattern[monline_cache_slice][3] << 17)/8 + cache_line_check_offset/8 - KB(32)/8] = (volatile char *)(B + (cache_slice_pattern[monline_cache_slice][0] << 17)/8 + cache_line_check_offset/8 - KB(32)/8);

    //    init_reprime = B + (cache_slice_pattern[monline_cache_slice][0] << 17)/8 + cache_line_check_offset/8 - KB(32)/8;
    //}
    printf("Address B: %lx\n", vtop((uintptr_t)B));
    printf("Address C: %lx\n", vtop((uintptr_t)C));
    printf("Address D: %lx\n", vtop((uintptr_t)D));
    printf("Address E: %lx\n", vtop((uintptr_t)E));
    printf("START: %lx\n", vtop((uintptr_t)(**start).p));
    printf("Cache slice %i\n", monline_cache_slice);


    //*init_prime = B + (cache_slice_pattern[monline_cache_slice][0] << 17)/8 + cache_line_check_offset/8;

    return 1;
}

void haswell_i7_4600m_prime(volatile char **tmp1) {
    //printf("ivybridge_i7_3770_prime\n");
    TIMESTAMP_START;
    TIMESTAMP_STOP;
    TIMESTAMP_START;
    TIMESTAMP_STOP;
    //volatile char **tmp1 = init_prime;
    tmp1 = (volatile char **)*tmp1;
    tmp1 = (volatile char **)*tmp1;
    tmp1 = (volatile char **)*tmp1;
    tmp1 = (volatile char **)*tmp1;
    tmp1 = (volatile char **)*tmp1;
    tmp1 = (volatile char **)*tmp1;
    tmp1 = (volatile char **)*tmp1;
    tmp1 = (volatile char **)*tmp1;
    tmp1 = (volatile char **)*tmp1;
    tmp1 = (volatile char **)*tmp1;
    tmp1 = (volatile char **)*tmp1;
    tmp1 = (volatile char **)*tmp1;
    tmp1 = (volatile char **)*tmp1;
    tmp1 = (volatile char **)*tmp1;
    tmp1 = (volatile char **)*tmp1;
    tmp1 = (volatile char **)*tmp1;
}

void haswell_i7_4600m_reprime() {
    //printf("haswell_i7_4600m_reprime\n");
    volatile char **tmp1 = init_reprime;
    tmp1 = (volatile char **)*tmp1;
    tmp1 = (volatile char **)*tmp1;
    tmp1 = (volatile char **)*tmp1;
    tmp1 = (volatile char **)*tmp1;
    tmp1 = (volatile char **)*tmp1;
    tmp1 = (volatile char **)*tmp1;
    tmp1 = (volatile char **)*tmp1;
    tmp1 = (volatile char **)*tmp1;
    tmp1 = (volatile char **)*tmp1;
    tmp1 = (volatile char **)*tmp1;
    tmp1 = (volatile char **)*tmp1;
    tmp1 = (volatile char **)*tmp1;
    tmp1 = (volatile char **)*tmp1;
    tmp1 = (volatile char **)*tmp1;
    tmp1 = (volatile char **)*tmp1;
    tmp1 = (volatile char **)*tmp1;
}

uint64_t haswell_i7_4600m_probe(Node* start) {
    //printf("haswell_i7_4600m_probe\n");
    // PROBE & MEASURE
    uint64_t begin, end;
    //unsigned long int begin2, end2;
    //volatile char **tmp1 = init_prime;
    TIMESTAMP_START;
    __asm volatile ("addq %0, %%rcx" : :"m"(*(start->p)));
    start = start->forward;
    __asm volatile ("addq %0, %%rcx" : :"m"(*(start->p)));
    start = start->forward;
    __asm volatile ("addq %0, %%rcx" : :"m"(*(start->p)));
    start = start->forward;
    __asm volatile ("addq %0, %%rcx" : :"m"(*(start->p)));
    start = start->forward;
    __asm volatile ("addq %0, %%rcx" : :"m"(*(start->p)));
    start = start->forward;
    __asm volatile ("addq %0, %%rcx" : :"m"(*(start->p)));
    start = start->forward;
    __asm volatile ("addq %0, %%rcx" : :"m"(*(start->p)));
    start = start->forward;
    __asm volatile ("addq %0, %%rcx" : :"m"(*(start->p)));
    start = start->forward;
    __asm volatile ("addq %0, %%rcx" : :"m"(*(start->p)));
    start = start->forward;
    __asm volatile ("addq %0, %%rcx" : :"m"(*(start->p)));
    start = start->forward;
    __asm volatile ("addq %0, %%rcx" : :"m"(*(start->p)));
    start = start->forward;
    __asm volatile ("addq %0, %%rcx" : :"m"(*(start->p)));
    start = start->forward;
    __asm volatile ("addq %0, %%rcx" : :"m"(*(start->p)));
    start = start->forward;
    __asm volatile ("addq %0, %%rcx" : :"m"(*(start->p)));
    start = start->forward;
    __asm volatile ("addq %0, %%rcx" : :"m"(*(start->p)));
    start = start->forward;
    __asm volatile ("addq %0, %%rcx" : :"m"(*(start->p)));
    //tmp1 = (volatile char **)*tmp1;
    //tmp1 = (volatile char **)*tmp1;
    //tmp1 = (volatile char **)*tmp1;
    //tmp1 = (volatile char **)*tmp1;
    //tmp1 = (volatile char **)*tmp1;
    //tmp1 = (volatile char **)*tmp1;
    //tmp1 = (volatile char **)*tmp1;
    //tmp1 = (volatile char **)*tmp1;
    //tmp1 = (volatile char **)*tmp1;
    //tmp1 = (volatile char **)*tmp1;
    //tmp1 = (volatile char **)*tmp1;
    //tmp1 = (volatile char **)*tmp1;
    //tmp1 = (volatile char **)*tmp1;
    //tmp1 = (volatile char **)*tmp1;
    //tmp1 = (volatile char **)*tmp1;
    //tmp1 = (volatile char **)*tmp1;
    TIMESTAMP_STOP;
    begin = get_global_timestamp_start();
    end = get_global_timestamp_stop();
/*
    TIMESTAMP_START;
    TIMESTAMP_STOP;
    begin2 = get_global_timestamp_start();
    end2 = get_global_timestamp_stop();
*/
    return (end-begin);//-(end2-begin2);
}

uint64_t haswell_i7_4600m_reverse_probe(Node* start) {
    //printf("haswell_i7_4600m_probe\n");
    // PROBE & MEASURE
    uint64_t begin, end;
    //unsigned long int begin2, end2;
    //volatile char **tmp1 = init_prime_reverse;
    TIMESTAMP_START;
    __asm volatile ("addq %0, %%rcx" : :"m"(*(start->p)));
    start = start->forward;
    __asm volatile ("addq %0, %%rcx" : :"m"(*(start->p)));
    start = start->forward;
    __asm volatile ("addq %0, %%rcx" : :"m"(*(start->p)));
    start = start->forward;
    __asm volatile ("addq %0, %%rcx" : :"m"(*(start->p)));
    start = start->forward;
    __asm volatile ("addq %0, %%rcx" : :"m"(*(start->p)));
    start = start->forward;
    __asm volatile ("addq %0, %%rcx" : :"m"(*(start->p)));
    start = start->forward;
    __asm volatile ("addq %0, %%rcx" : :"m"(*(start->p)));
    start = start->forward;
    __asm volatile ("addq %0, %%rcx" : :"m"(*(start->p)));
    start = start->forward;
    __asm volatile ("addq %0, %%rcx" : :"m"(*(start->p)));
    start = start->forward;
    __asm volatile ("addq %0, %%rcx" : :"m"(*(start->p)));
    start = start->forward;
    __asm volatile ("addq %0, %%rcx" : :"m"(*(start->p)));
    start = start->forward;
    __asm volatile ("addq %0, %%rcx" : :"m"(*(start->p)));
    start = start->forward;
    __asm volatile ("addq %0, %%rcx" : :"m"(*(start->p)));
    start = start->forward;
    __asm volatile ("addq %0, %%rcx" : :"m"(*(start->p)));
    start = start->forward;
    __asm volatile ("addq %0, %%rcx" : :"m"(*(start->p)));
    start = start->forward;
    __asm volatile ("addq %0, %%rcx" : :"m"(*(start->p)));
    TIMESTAMP_STOP;
    begin = get_global_timestamp_start();
    end = get_global_timestamp_stop();
    return (end-begin);//-(end2-begin2);
}

uint64_t get_global_timestamp_start(void) {
	return ((uint64_t)cycles_high_start << 32) | cycles_low_start;
}

uint64_t get_global_timestamp_stop(void) {
	return ((uint64_t)cycles_high_stop << 32) | cycles_low_stop;
}

template<typename T>
void outputCSVLine(const char* label, vector<T> v, const char* filename,
    ios_base::openmode mode) {
  ofstream file;
  file.open(filename, mode);
  file << label;
  for(auto e:v) {
    file << "," << e;
  }
  file << endl;
  file.close();
}

int main(int argc, char* argv[]) {
  uintptr_t m1, m2;
  printf("Please enter the first line to monitor:\n");
  scanf("%lx", &m1);
  printf("Monitoring %lx:\n", m1);
  printf("Please enter the second line to monitor:\n");
  scanf("%lx", &m2);
  printf("Monitoring %lx:\n", m2);
  //m1 = (uintptr_t) malloc(sizeof(uint32_t));
  //m2 = (uintptr_t) malloc(sizeof(uint32_t));
  Node *s1, *s2;
  if (!haswell_i7_4600m_setup(m2, &s2)) {
      printf("[x] Not enough memory could be allocated on required cache-slice, please try again and/or increase hugepages available memory");
      return 0;
  }
  if (!haswell_i7_4600m_setup(m1, &s1)) {
      printf("[x] Not enough memory could be allocated on required cache-slice, please try again and/or increase hugepages available memory");
      return 0;
  }
  vector<uint64_t> t1,t2;
  uint64_t p1_time, p2_time, p1_time_reverse, p2_time_reverse;
  REPEAT_FOR(1000ULL*1000*1000) {
    //p2_time = haswell_i7_4600m_probe(s2);
    //t2.push_back(p2_time);

    //p1_time = haswell_i7_4600m_probe(s1);
    //t1.push_back(p1_time);

    haswell_i7_4600m_prime(s1->p); //return 0;
    haswell_i7_4600m_prime(s2->p); //return 0;
    //haswell_i7_4600m_reprime(); //return 0;

    p1_time_reverse = haswell_i7_4600m_reverse_probe(s1);
    t1.push_back(p1_time_reverse);

    p2_time_reverse = haswell_i7_4600m_reverse_probe(s2);
    t2.push_back(p2_time_reverse);
  }
  outputCSVLine("t1", t1, argv[1], ios::trunc);
  outputCSVLine("t2", t2, argv[1], ios::app);
}
