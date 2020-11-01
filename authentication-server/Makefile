# AS Makefile, versao 1
# Redes de Computadores, DEI/IST/ULisboa 2020-21

LD   = gcc
CFLAGS = -g -Wall -Wextra
LDFLAGS= -lm

all:
	@echo Compiling Authentication System...
	$(LD) $(CFLAGS) $(LDFLAGS) -o as as.c ../functions.c

run:
	./as

clean:
	@echo Cleaning...
	rm -f *.o as
