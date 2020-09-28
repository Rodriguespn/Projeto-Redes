# Makefile, versao 1
# Redes de Computadores, DEI/IST/ULisboa 2020-21

LD   = gcc
CFLAGS = -g -Wall -std=gnu99 -I../
LDFLAGS= -lm

# A phony target is one that is not really the name of a file
# https://www.gnu.org/software/make/manual/html_node/Phony-Targets.html
.PHONY: all clean

all: clean AS PD User FS

AS: AS.o
	$(LD) $(CFLAGS) $(LDFLAGS) -o AS AS.c

PD: PD.o
	$(LD) $(CFLAGS) $(LDFLAGS) -o PD PD.c

User: User.o
	$(LD) $(CFLAGS) $(LDFLAGS) -o User User.c

FS: FS.o
	$(LD) $(CFLAGS) $(LDFLAGS) -o FS FS.c

clean:
	@echo Cleaning...
	rm -f *.o AS FS User PD

