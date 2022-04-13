CC=g++
CFLAGS= -std=c++17 -c -Wall

all: example_linux

example_linux: main.o memory.o
	$(CC) main.o memory.o -o example_linux

main.o: ../main.cpp
	$(CC) $(CFLAGS) ../main.cpp

memory.o: ../../memory.cpp
	$(CC) $(CFLAGS) ../../memory.cpp

clean:
	rm -rf *.o example_linux
