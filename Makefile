CC=gcc 
CFLAGS=-Wall
main: fesa_if.o main.o 

clean:
	rm -f main main.o
