#ifndef AS_H
#define AS_H

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h> 
#include "../constants.h"
#include "../functions.h"

#define USERS_FOLDER_NAME           "USERS/"

#define PASSWORD_FILE_PREFIX        "_pass"
#define REGISTRATION_FILE_PREFIX    "_reg"
#define LOGIN_FILE_PREFIX           "_login"
#define TID_FILE_PREFIX             "_tid"

#define FILE_EXTENSION              ".txt"


void usage();
int wrong_arguments(int argc);
void process_registration_request(char* buffer, char* uid, char* password, char* pdip, char* pdport);
void process_unregistration_request(char* buffer, char* uid, char* password);
void process_login_request(char* buffer, char* uid, char* password);
void process_request_request(char* buffer, char* uid, char* rid, char* fop);
void prepare_error_message(char* buffer);
void prepare_ok_message(char* buffer, const char* command);
void prepare_nok_message(char* buffer, const char* command);
void prepare_not_logged_in_message(char* buffer);
void parse_arguments(const char* argv[], int size);
Boolean parse_command(char* buffer, char* command);
Boolean parse_register_message(char* uid, char* password, char* pdip, char* pdport);
Boolean parse_unregister_message(char* uid, char* password);
Boolean parse_login_message(char* uid, char* password);
Boolean parse_request_message(char* uid, char* rid, char* fop);
Boolean all_numbers(char* uid);
Boolean valid_uid(char* uid);
Boolean only_numbers_or_letters(char* password);
Boolean valid_password(char* password);
void get_user_directory(char* buffer, char *uid);
void get_filename(char* buffer, char* uid, const char* filename, const char* file_ext);
Boolean register_user(char* uid, char* password, char* ip, char* port);
Boolean unregister_user(char *uid, char *password);
Boolean login_user(char* uid, char* password);

#endif /* AS_H */