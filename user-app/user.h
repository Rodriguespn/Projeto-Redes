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
#include <time.h>
#include "../constants.h"
#include "../functions.h"

#define SUCCESS_MESSAGE "Success!"
#define FAILURE_MESSAGE "Action unsuccessful."
#define SERVER_DOWN_MESSAGE "Server disconnected."
#define RND 42

void usage();
int wrong_arguments(int argc);
void parse_arguments(const char *argv[], int size);

/*login*/
Boolean parse_login_message(char *buffer, char *command, char *uid, char *password);
Boolean prepare_login_request(char *request, char *command, char *uid, char *password);
Boolean verify_login_response(char *buffer, int size);

/*req*/
Boolean parse_req(char *fop, char *fname);
void prepare_req_request(char *request, char *uid, char *fop, char *fname, char *rid);

/*val*/
Boolean parse_val(char *vc);
void prepare_val_request(char *request, char *uid, char *rid, char *vc);

/*list*/
void prepare_list_request(char *request, char *uid, char *tid);
void treat_rls(char* buffer);

/*retrieve*/
Boolean parse_retrieve_upload_delete(char *fname);
void prepare_retrieve_request(char *request, char *uid, char *tid, char *fname);
void treat_rrt(char* buffer);

/*upload*/
void prepare_upload_request(char *request, char *uid, char *tid, char *fname,
                            char *fsize, char *data);
void treat_rup(char* buffer);

/*delete*/
void prepare_delete_request(char *request, char *uid, char *tid, char *fname);
void treat_rdl(char* buffer);

/*remove*/
void prepare_remove_request(char *request, char *uid, char *tid);
void treat_rrm(char* buffer);

void verify_command_response(char *buffer, int size);

void init_socket_to_fs(int fs_fd, int errcode_fs, ssize_t m, struct addrinfo hints_fs, 
                       struct addrinfo *res_fs);

void generate_random_rid(char rid[], int size);

#endif /* USER_H */