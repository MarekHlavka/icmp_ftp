CC=gcc
CFLAGS=-std=c99 -Wall -Wextra -pedantic -g
SRC=*.c
HDR=*.h
PROJ=secret

## make
.PHONY:$(PROJ)
$(PROJ): clean
	$(CC) $(CFLAGS) $(SRC) -o $(PROJ)

## odstraneni
clean:
	rm -f *.o $(PROJ)