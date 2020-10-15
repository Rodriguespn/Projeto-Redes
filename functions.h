#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "constants.h" 

#define max(A,B) ((A)>=(B)?(A):(B))

void handler_sigint();
void read_stdin(char* buffer);
char* parse_pd_port(const char* argv[], int size);
char* parse_as_ip(const char* argv[], int size, char* defaultip);
char* parse_as_port(const char* argv[], int size);
char* parse_fs_port(const char* argv[], int size);
char* parse_fs_ip(const char* argv[], int size, char* pdip);

#endif /* FUNCTIONS_H */