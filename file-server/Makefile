# FS Makefile, versao 1
# Redes de Computadores, DEI/IST/ULisboa 2020-21

LD   = gcc
CFLAGS = -g -Wall -Wextra -std=gnu99 -I../
LDFLAGS= -lm

all:
	@echo Compiling File System...
	$(LD) $(CFLAGS) $(LDFLAGS) -o fs fs.c ../functions.c

run:
	./fs -v

clean:
	@echo Cleaning...
	rm -rf *.o fs USERS/
