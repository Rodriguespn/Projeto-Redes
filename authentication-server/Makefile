# AS Makefile, versao 1
# Redes de Computadores, DEI/IST/ULisboa 2020-21

LD   = gcc
CFLAGS = -g -Wall -Wextra -std=gnu99 -I../
LDFLAGS= -lm

all:
	@echo Compiling Authentication System...
	$(LD) $(CFLAGS) $(LDFLAGS) -o as as.c ../functions.c

clean:
	@echo Cleaning...
	rm -f *.o as
