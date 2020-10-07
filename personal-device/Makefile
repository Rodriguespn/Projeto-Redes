# PD Makefile, versao 1
# Redes de Computadores, DEI/IST/ULisboa 2020-21

LD   = gcc
CFLAGS = -g -Wall -Wextra -std=gnu99 -I../
LDFLAGS= -lm

all:
	@echo Compiling Personal Device...
	$(LD) $(CFLAGS) $(LDFLAGS) -o pd pd.c

clean:
	@echo Cleaning...
	rm -f *.o pd
