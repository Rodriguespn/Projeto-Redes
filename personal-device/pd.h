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
#include "../constants.h"

void usage();
int wrong_arguments(int argc);
void read_stdin(char* buffer);
void parse_register_message(char* buffer, char* command, char* uid, char* password);
void parse_exit_message(char* buffer, char* command);
enum boolean all_numbers(char* uid);
enum boolean valid_uid(char* uid);
enum boolean only_numbers_or_letters(char* password);
enum boolean valid_password(char* password);
void prepare_request(char* request, char* command, char* uid, char* password);
void parse_pd_port(const char* argv[], int size);
void parse_as_ip(const char* argv[], int size);
void parse_as_port(const char* argv[], int size);
void parse_arguments(const char* argv[], int size);

#endif /* PD_H */