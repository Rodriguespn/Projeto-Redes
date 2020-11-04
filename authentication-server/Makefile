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

user:
	@echo Compiling User Dummy...
	$(LD) $(CFLAGS) $(LDFLAGS) -o user user-pedro.c ../functions.c

fs_dummy:
	@echo Compiling FS Dummy...
	$(LD) $(CFLAGS) $(LDFLAGS) -o fs fs-dummy.c ../functions.c

clean:
	@echo Cleaning...
	rm -f *.o as
