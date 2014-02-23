FILES=main.c
OBJ=${FILES:.c=.o}
FLAGS=-Wall -W -Werror -Wshadow -std=c99 -g -pipe -O3 -pedantic -D_GNU_SOURCE

BIN=../bin/
EXE=$(BIN)flow

CC=gcc
RM=rm -rf
MKDIR=mkdir -p

.PHONY: all clean run exe

all: $(OBJ) exe
	$(MKDIR) ../bin
	$(CC) $(FLAGS) $(OBJ) -o $(EXE)

exe: $(EXE)

run:
	./$(EXE) -h

clean:
	$(RM) *.o

.c.o:
	$(CC) $(FLAGS) $< -c -o $@

$(EXE): $(FILES) $(DEPS)

#deps
main.o: main.h main.c
