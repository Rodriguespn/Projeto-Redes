# Makefile, versao 1
# Redes de Computadores, DEI/IST/ULisboa 2020-21

LD   = gcc
CFLAGS = -g -Wall -Wextra -std=gnu99 -I../
LDFLAGS= -lm

# A phony target is one that is not really the name of a file
# https://www.gnu.org/software/make/manual/html_node/Phony-Targets.html
.PHONY: all clean

all: clean AS PD User FS

AS:
	@echo Compiling Authentication System...
	$(LD) $(CFLAGS) $(LDFLAGS) -o as as.c

PD: 
	@echo Compiling Personal Device...
	$(LD) $(CFLAGS) $(LDFLAGS) -o pd pd.c

User:
	@echo Compiling User...
	$(LD) $(CFLAGS) $(LDFLAGS) -o user user.c

FS:
	@echo Compiling File System...
	$(LD) $(CFLAGS) $(LDFLAGS) -o fs fs.c

clean:
	@echo Cleaning...
	rm -f *.o as fs user pd
