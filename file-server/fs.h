#ifndef FS_H
#define FS_H

#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include "../constants.h"
#include "../functions.h"

#define MAIN_DIR_NAME       "USERS/"    // Main directory name
#define USER_DIR_NAME       "UID"       // User directory name (inside main directory name)

#define FILENAME_SIZE       24          // Max. filename size
#define USERS_DIR_SIZE      15          // Max. files per user
#define FILE_SIZE_DIG       10          // Max. digits a file size can have

// Argument Functions
void usage();
Boolean wrong_arguments(int argc);
void parse_argument_string(int argc, char const* argv[], char* flag, char* default_buffer, char* argument_buffer);
int parse_argument_int(int argc, char const* argv[], char* flag, int default_int);
Boolean parse_argument_flag(int argc, char const* argv[], char* flag);

// Internet Functions
void get_localhost_info(char* hostname_buffer, char* ip_buffer);

// Signal Threatment Functions
void sigint_handler();

#endif /* FS_H */