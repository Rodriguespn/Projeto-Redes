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
void prepare_error_message(char* buffer);
void prepare_registration_ok_message(char* buffer);
void prepare_registration_nok_message(char* buffer);
void parse_arguments(const char* argv[], int size);
enum boolean parse_command(char* buffer, char* command);
enum boolean parse_register_message(char* buffer, char* uid, char* password, char* pdip, char* pdport);
enum boolean all_numbers(char* uid);
enum boolean valid_uid(char* uid);
enum boolean only_numbers_or_letters(char* password);
enum boolean valid_password(char* password);
enum boolean register_user(char* uid, char* password, char* ip, char* port);

#endif /* AS_H */