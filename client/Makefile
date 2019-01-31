IDIR =../include
CC=gcc
CFLAGS=-I$(IDIR)

ODIR=obj
LDIR =../lib

LIBS=-lm

_DEPS = simple_tcp.h outstream.h routing_table.h
DEPS = $(patsubst %,%,$(_DEPS))

_OBJ = simple_tcp.c main.cpp routing_table.c
OBJ = $(patsubst %,%,$(_OBJ))


%.o: %.c $(DEPS)
	$(CC) -g -c -o $@ $< $(CFLAGS)

all: $(OBJ)
	$(CC) -g -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f *.o 
