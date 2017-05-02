# the compiler: gcc for C program, define as g++ for C++
CC = g++ -std=c++11 -O0

# compiler flags:
#  -g    adds debugging information to the executable file
#  -Wall turns on most, but not all, compiler warnings
CFLAGS  = -Wall -g -m64
CLIBDIR = -L /usr/lib

CHEADER_DIR = -I include/ -I /usr/include/
CLIBS   = -lm

all: cache

cache: cache.c
	$(CC) $(CFLAGS) -B /usr/share/libhugetlbfs -Wl,--hugetlbfs-align cache.c -o cache $(CHEADER_DIR) $(CLIBDIR) $(CLIBS)

asm: cache.c
	$(CC) $(CFLAGS) -B /usr/share/libhugetlbfs -Wl,--hugetlbfs-align cache.c -S $(CHEADER_DIR) $(CLIBDIR) $(CLIBS)

run: cache
	sudo HUGETLB_MORECORE=thp HUGETLB_ELFMAP=RW ./cache

cache_normal: cache.c
	$(CC) $(CFLAGS) -m64 cache.c -o cache $(CHEADER_DIR) $(CLIBDIR) $(CLIBS)

run_normal: cache_normal
	./cache

haswell.s: haswell.c
	$(CC) $(CFLAGS) haswell.c -S $(CHEADER_DIR) $(CLIBDIR) $(CLIBS)

haswell: haswell.c
	$(CC) $(CFLAGS) haswell.c -o haswell $(CHEADER_DIR) $(CLIBDIR) $(CLIBS)

victim.s: victim.c
	$(CC) $(CFLAGS) victim.c -S $(CHEADER_DIR) $(CLIBDIR) $(CLIBS)

victim: victim.c
	$(CC) $(CFLAGS) victim.c -o victim $(CHEADER_DIR) $(CLIBDIR) $(CLIBS)


.PHONY: clean

clean:
	rm cache haswell victim *.s
