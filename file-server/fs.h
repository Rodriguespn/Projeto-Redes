#ifndef FS_H
#define FS_H

#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h> 
#include <errno.h>
#include "../constants.h"
#include "../functions.h"
#include <dirent.h>
#include <unistd.h>

#define MAIN_DIR_NAME       "USERS/"    // Main directory name
#define MAIN_DIR_NAME_SIZE  6

#define FILENAME_SIZE       25          // Max. filename size
#define USERS_DIR_SIZE      15          // Max. files per user
#define FILE_SIZE_DIG       11          // Max. digits a file size can have

// Argument Functions
void usage();
Boolean wrong_arguments(int argc);
void parse_argument_string(int argc, char const* argv[], char* flag, char* default_buffer, char* argument_buffer);
int parse_argument_int(int argc, char const* argv[], char* flag, int default_int);
Boolean parse_argument_flag(int argc, char const* argv[], char* flag);

// Directory functions
Boolean make_main_directory();
Boolean find_user_directory(char* uid);
Boolean make_user_directory(char* uid);
Boolean find_user_filename(char* uid, char* filename);
int count_user_filenames(char* uid);
void list_user_filenames(char* uid, char* res, int res_size);
Boolean reached_user_file_limit(char* uid, int max);
Boolean create_user_file(char* uid, char* filename, char* data);
Boolean delete_user_file(char* uid, char* filename);
Boolean remove_user_dir(char* uid);


// Internet Functions
void get_localhost_info(char* hostname_buffer, char* ip_buffer);
Boolean read_user_request_arg(int sockfd, char* dest, int dest_size, Boolean skip_len,  char* delimiter);
Boolean read_as_val_response(int sockfd, struct sockaddr* addr, int user_sockfd, char* dest, int dest_size, Boolean skip_len, char* delimiter, char* dest_default, char* special_res_err);
Boolean send_as_val_request(int sockfd, struct sockaddr* addr, int user_sockfd, char* uid, char* tid);
Boolean send_user_response(int sockfd, char* protocol, char* status);

// Signal Threatment Functions
void sigint_handler();

#endif /* FS_H */