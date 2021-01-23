CC=gcc
CFLAGS=-Wall -Og -g -pthread

all: main.o
	$(CC) $(CFLAGS) main.o -o main

main.o: main.c
	$(CC) $(CFLAGS) -c main.c -o main.o
