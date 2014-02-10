FILES=main.c
OBJ=${FILES:.c=.o}
FLAGS=-Wall -g -O0 -pipe -pedantic

EXE=flow

CC=gcc
RM=rm -rf

.PHONY: all clean run exe

all: $(OBJ) exe
	$(CC) $(FLAGS) $(OBJ) -o $(EXE)

exe: $(EXE)

run:
	./$(EXE)

clean:
	$(RM) *.o

%: %.c
	$(CC) -o $@ $^ $(FLAGS)

#zavislosti
main.o: main.c main.h

$(EXE): $(FILES) $(DEPS)
