# UA Makefile, versao 1
# Redes de Computadores, DEI/IST/ULisboa 2020-21

LD   = gcc
CFLAGS = -g -Wall -Wextra -std=gnu99 -I../
LDFLAGS= -lm

all:
	@echo Compiling User...
	$(LD) $(CFLAGS) $(LDFLAGS) -o user user.c ../functions.c

run:
	./user -n tejo.tecnico.ulisboa.pt -p 58011

clean:
	@echo Cleaning...
	rm -f *.o user
