#ifndef USER_H
#define USER_H

#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "../constants.h"
#include "../functions.h"

#define LOGIN_SUCCESS_MESSAGE   "You are now logged in."
#define LOGIN_FAILURE_MESSAGE   "Login unsuccessful."
#define SERVER_DOWN_MESSAGE     "Server disconnected."

void usage();
int wrong_arguments(int argc);
void parse_arguments(const char* argv[], int size);
Boolean parse_login_message(char* buffer, char* command, char* uid, char* password);
Boolean prepare_login_request(char* request, char* command, char* uid, char* password);
Boolean verify_login_response(char* buffer, int size);

#endif /* USER_H */