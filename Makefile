CC=gcc
CFLAGS=-Wall -O2

all: main.o minecraft.o log.o
	$(CC) $(CFLAGS) main.o minecraft.o log.o -o hypegate

main.o: main.c
	$(CC) $(CFLAGS) -c main.c -o main.o

minecraft.o: minecraft.c
	$(CC) $(CFLAGS) -c minecraft.c -o minecraft.o

log.o: log/src/log.c
	$(CC) $(CFLAGS) -c log/src/log.c -o log.o -DLOG_USE_COLOR
