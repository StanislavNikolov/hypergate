CC=gcc
CFLAGS=-Wall -O2

all: main.o minecraft.o
	$(CC) $(CFLAGS) main.o minecraft.o -o hypegate

main.o: main.c
	$(CC) $(CFLAGS) -c main.c -o main.o

minecraft.o: minecraft.c
	$(CC) $(CFLAGS) -c minecraft.c -o minecraft.o
