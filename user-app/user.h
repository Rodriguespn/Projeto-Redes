#ifndef USER_H
#define USER_H

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "../constants.h"
#include "../functions.h"

#define SUCCESS_MESSAGE   "Command successful."
#define FAILURE_MESSAGE   "Command unsuccessful."
#define SERVER_DOWN_MESSAGE     "Server disconnected."

void usage();
int wrong_arguments(int argc);
void parse_arguments(const char* argv[], int size);
/*PARSERS*/
Boolean parse_login_message(char* buffer, char* command, char* uid, char* password);
Boolean parse_req(char* buffer, char* command, char* fop, char* fname);
Boolean parse_val(char* buffer, char* command, char* vc);
Boolean parse_list(char* buffer, char* command);
Boolean parse_retrieve(char* buffer, char* command, char* filename);
Boolean parse_upload(char* buffer, char* command, char* filename);
Boolean parse_delete(char* buffer, char* command, char* filename);
Boolean parse_remove(char* buffer, char* command);
Boolean prepare_login_request(char* request, char* command, char* uid, char* password);
Boolean verify_login_response(char* buffer, int size);
void verify_command_response(char* buffer, int size);

#endif /* USER_H */