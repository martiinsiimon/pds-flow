FILES=main.c
OBJ=${FILES:.c=.o}
FLAGS=-Wall -W -Werror -ansi -Wshadow -g -O0 -pipe -pedantic

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

%: %.c
	$(CC) -o $@ $^ $(FLAGS)

#zavislosti
main.o: main.c main.h

$(EXE): $(FILES) $(DEPS)
