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
#include <time.h>
#include "../constants.h"
#include "../functions.h"

#define USERS_FOLDER_NAME           "USERS/"

#define PASSWORD_FILE_PREFIX        "_pass"
#define REGISTRATION_FILE_PREFIX    "_reg"
#define LOGIN_FILE_PREFIX           "_login"

#define FILE_EXTENSION              ".txt"

// Request error codes
#define OK_CODE                     0
#define INVALID_UID_ERR_CODE        1
#define INVALID_PASSWORD_ERR_CODE   2
#define INVALID_FOP_ERR_CODE        3
#define PD_NOT_CONNECTED_ERR_CODE   4
#define UID_NOT_FOUND_ERROR         5
#define INCORRECT_PASSWORD_ERR_CODE 6
#define UNKNOWN_ERROR               7

void usage();
int wrong_arguments(int argc);
void process_registration_request(char* buffer, char* uid, char* password, char* pdip, char* pdport);
void process_unregistration_request(char* buffer, char* uid, char* password);
void process_login_request(char* buffer, char* uid, char* password);
void process_request_request(char* buffer, char* uid, char* rid, char* fop, char** vc, char* operation);
void process_authentication_request(char* buffer, char* uid, char* rid, char* vc, char* operation);
void prepare_error_message(char* buffer);
void prepare_ok_message(char* buffer, const char* command);
void prepare_nok_message(char* buffer, const char* command);
void prepare_not_logged_in_message(char* buffer);
void prepare_invalid_user_message(char* buffer);
void prepare_invalid_fop_message(char* buffer);
void prepare_pd_error_message(char* buffer);
void prepare_request_message(char* buffer, int code);
void prepare_validation_pd_request(char* buffer, char* uid, char* vc, char* fop, char* filename);
void prepare_authentication_message(char* buffer, char* tid);
void parse_arguments(const char* argv[], int size);
Boolean parse_command(char* buffer, char* command);
Boolean parse_register_message(char* uid, char* password, char* pdip, char* pdport);
Boolean parse_unregister_message(char* uid, char* password);
Boolean parse_login_message(char* uid, char* password);
Boolean parse_request_message(char* uid, char* rid, char* fop, char*filename);
Boolean parse_authentication_message(char* uid, char* rid, char* vc);
Boolean all_numbers(char* uid);
Boolean valid_uid(char* uid);
Boolean only_numbers_or_letters(char* password);
Boolean valid_password(char* password);
Boolean fop_has_file(char* fop);
Boolean send_vc_to_pd(char* uid, char* fop, char* filename, char** vc);
void get_user_directory(char* buffer, char *uid);
void get_filename(char* buffer, char* uid, const char* filename, const char* file_ext);
void generate_random_vc(char** vc);
int register_user(char* uid, char* password, char* ip, char* port);
int unregister_user(char *uid, char *password);
int login_user(char* uid, char* password);
int request_user(char* uid, char* fop, char* filename, char** vc, char* operation);
Boolean authenticate_user(char* uid, char* rid, char* vc, char* request_uid, char* request_rid, char* request_vc, char* tid, char* request);
Boolean get_user_file_path(char** path, char* uid, const char* file_name, const char* file_extension);

#endif /* AS_H */