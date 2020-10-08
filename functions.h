#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "constants.h" 

void read_stdin(char* buffer);
void parse_pd_port(const char* argv[], int size, char* pdport);
void parse_as_ip(const char* argv[], int size, char* asip, char* pdip);
void parse_as_port(const char* argv[], int size, char* asport);
void parse_fs_port(const char* argv[], int size, char* fsport);
void parse_fs_ip(const char* argv[], int size, char* fsip, char* pdip);

#endif /* FUNCTIONS_H */