#ifndef FUNCTIONS_H
#define FUNCTIONS_H

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
#include <stdarg.h>
#include "constants.h" 

#define max(A,B) ((A)>=(B)?(A):(B))

void handler_sigint();
void read_stdin(char* buffer);
void parse_pd_port(const char* argv[], int size, char** pdport);
void parse_as_ip(const char* argv[], int size, char* defaultip, char** asip);
void parse_as_port(const char* argv[], int size, char** asport);
void parse_fs_port(const char* argv[], int size, char** fsport);
void parse_fs_ip(const char* argv[], int size, char* defaultip, char** fsip);
Boolean parse_verbose_flag(const char* argv[], int size);
void verbose_message(Boolean verbose_flag, const char* message, ... );

int tcp_write(int sockfd, char* buffer);
int tcp_read(int sockfd, char* buffer, int size);
int udp_write(int sockfd, char* buffer, struct sockaddr *addr, socklen_t addrlen);
int udp_read(int sockfd, char* buffer, int size, struct sockaddr* addr);

#endif /* FUNCTIONS_H */