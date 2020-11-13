# UA Makefile, versao 1
# Redes de Computadores, DEI/IST/ULisboa 2020-21

LD   = gcc
CFLAGS = -g -Wall -Wextra -std=gnu99 -I../
LDFLAGS= -lm

all:
	@echo Compiling User...
	$(LD) $(CFLAGS) $(LDFLAGS) -o user user.c ../functions.c

run:
	./user -n 193.136.128.109 -p 58038 -m 193.136.138.142 -q 59000

clean:
	@echo Cleaning...
	rm -f *.o user
