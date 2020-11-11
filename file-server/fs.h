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
#include <errno.h>
#include "../constants.h"
#include "../functions.h"
#include <dirent.h>

#define MAIN_DIR_NAME       "USERS/"    // Main directory name
#define MAIN_DIR_NAME_SIZE  6

#define FILENAME_SIZE       24          // Max. filename size
#define USERS_DIR_SIZE      15          // Max. files per user
#define FILE_SIZE_DIG       10          // Max. digits a file size can have

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
Boolean reached_user_file_limit(char* uid, int max);
Boolean create_user_file(char* uid, char* filename, char* data);
Boolean delete_user_file(char* uid, char* filename);
Boolean remove_user_dir(char* uid);


// Internet Functions
void get_localhost_info(char* hostname_buffer, char* ip_buffer);

// Signal Threatment Functions
void sigint_handler();

#endif /* FS_H */