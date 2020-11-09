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

#define RAND_MAX 9
#define SUCCESS_MESSAGE   "Command successful."
#define FAILURE_MESSAGE   "Command unsuccessful."
#define SERVER_DOWN_MESSAGE     "Server disconnected."

void usage();
int wrong_arguments(int argc);
void parse_arguments(const char* argv[], int size);

//TODO: alterar os prepares

Boolean parse_login_message(char* buffer, char* command, char* uid, char* password);
Boolean prepare_login_request(char* request, char* command, char* uid, char* password);
Boolean verify_login_response(char* buffer, int size);

Boolean parse_req(char* buffer, char* command, char* fop, char* fname);
void prepare_req_request(char* request, char* uid, char* fop, char* fname);

Boolean parse_val(char* buffer, char* command, char* vc);
void prepare_val_request(char* request, char* uid, char* password);

Boolean parse_list(char* buffer, char* command);
void prepare_list_request(char* request, char* uid, char* password);

Boolean parse_retrieve(char* buffer, char* command, char* filename);
void prepare_retrieve_request(char* request, char* uid, char* password);

Boolean parse_upload(char* buffer, char* command, char* filename);
void prepare_upload_request(char* request, char* uid, char* password);

Boolean parse_delete(char* buffer, char* command, char* filename);
void prepare_delete_request(char* request, char* uid, char* password);

Boolean parse_remove(char* buffer, char* command);
Boolean prepare_remove_request(char* request, char* uid, char* password);

void verify_command_response(char* buffer, int size);

void  socket_to_fs();

#endif /* USER_H */