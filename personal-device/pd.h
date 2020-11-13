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
#include <signal.h> 
#include "../constants.h"
#include "../functions.h"

#define LOGIN_SUCCESS_MESSAGE   "Registration successful."
#define LOGIN_FAILURE_MESSAGE   "Registration unsuccessful."
#define SERVER_DOWN_MESSAGE     "Server disconnected."

void handler_sigint();
int wrong_arguments(int argc);
void usage();
Boolean parse_register_message(char* buffer, char* command, char* uid, char* password);
void parse_exit_message(char* buffer, char* command);
Boolean parse_validation_code(char* buffer);
Boolean get_fop_from_fop_code(char* fop, char* fop_long_name);
Boolean fop_has_file(char* fop);
Boolean prepare_register_request(char* request, char* command, char* uid, char* password);
Boolean verify_register_response(char* buffer, int size);
void parse_arguments(const char* argv[], int size);

#endif /* PD_H */