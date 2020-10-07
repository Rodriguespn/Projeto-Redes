#ifndef PD_H
#define PD_H

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "project_constants.h"

void usage();
int wrong_arguments(int argc);
void parse_pd_port(const char* argv[], int size);
void parse_as_ip(const char* argv[], int size);
void parse_as_port(const char* argv[], int size);
void parse_arguments(const char* argv[], int size);

#endif /* PD_H */