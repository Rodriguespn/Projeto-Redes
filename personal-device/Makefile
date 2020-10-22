# PD Makefile, versao 1
# Redes de Computadores, DEI/IST/ULisboa 2020-21

LD   = gcc
CFLAGS = -g -Wall -Wextra -std=gnu99 -I../
LDFLAGS= -lm

all:
	@echo Compiling Personal Device...
	$(LD) $(CFLAGS) $(LDFLAGS) -o pd pd.c ../functions.c

run:
	./pd 10.0.2.15

run_as_tejo:
	./pd 193.136.128.109 -n tejo.tecnico.ulisboa.pt -p 58011

clean:
	@echo Cleaning...
	rm -f *.o pd
