#ifndef AS_H
#define AS_H

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h> 
#include "../constants.h"
#include "../functions.h"

void usage();
int wrong_arguments(int argc);
void parse_arguments(const char* argv[], int size);

#endif /* AS_H */