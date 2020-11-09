#ifndef FS_H
#define FS_H

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
#include <dirent.h>
#include "../constants.h"
#include "../functions.h"

#define USERS_FOLDER_NAME           "USERS/"
#define FILE_EXTENSION              ".txt"


#define TIMEOUT                     0
#define SELECT_TIMEOUT_SECS         10
#define SELECT_TIMEOUT_USECS        0
#define PD_TIMEOUT_SECS             2
#define PD_TIMEOUT_USECS            0

void usage();
int wrong_arguments(int argc);
void parse_arguments(const char* argv[], int size);
Boolean parse_command(char* buffer, char* command);


#endif /* FS_H */