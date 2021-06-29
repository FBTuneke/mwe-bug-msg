# LIBS = -lmrloop -luring -lzstd
LIBS = -luring -lbpf
CC = gcc
CFLAGS = -O2

client:
	$(CC) $(CFLAGS) client.c -o client

bpf:
	clang -O2 -Wall -target bpf -g -c -o bpf.o bpf.c

server:
	$(CC) $(CFLAGS) -o server server.c $(LIBS)


clean:
	-rm -f *.o
	-rm -f server
	-rm -f client

