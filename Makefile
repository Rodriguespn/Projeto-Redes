# Makefile, versao 1
# Redes de Computadores, DEI/IST/ULisboa 2020-21

LD   = gcc
CFLAGS = -g -Wall -Wextra -std=gnu99 -I../
LDFLAGS= -lm

all:
	@echo Calling all makefiles...
	cd authentication-server && make
	cd file-server && make
	cd personal-device && make
	cd user-app && make
	@echo Compilation Succeeded.

clean:
	@echo Cleaning...
	cd authentication-server && make clean
	cd file-server && make clean
	cd personal-device && make clean
	cd user-app && make clean
