#ifndef USER_H
#define USER_H

#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#define PORT "58001"

#include "../constants.h"
#include "../functions.h"

void usage();
int wrong_arguments(int argc);
void parse_arguments(const char* argv[], int size);
int tcp_write(int sockfd, char* buffer, int size);
int tcp_read(int sockfd, char* buffer, int size);

#endif /* USER_H */