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
#define RND 42

void usage();
int wrong_arguments(int argc);
void parse_arguments(const char *argv[], int size);

//login
Boolean parse_login_message(char *buffer, char *command, char *uid, char *password);
Boolean prepare_login_request(char *request, char *command, char *uid, char *password);
Boolean verify_login_response(char *buffer);

//req
void req(char* fop, char* fname, char* buffer, char* uid, char* rid, int as_fd, ssize_t n);
Boolean parse_req(char *fop, char *fname);
void prepare_req_request(char *request, char *uid, char *fop, char *fname, char *rid);
void treat_rrq(char* buffer);

//val
void val(char* vc, char* tid, char* buffer, char* uid, char* rid, int as_fd, ssize_t n);
Boolean parse_val(char *vc);
void prepare_val_request(char *request, char *uid, char *rid, char *vc);
void treat_rau(char* buffer, char *tid);

//list
void list(char* tid, char* buffer, char* uid);
void prepare_list_request(char *request, char *uid, char *tid);
void treat_rls(char* buffer);

//retrieve
void retrieve(char* fname, char* tid, char* buffer, char* uid);
void prepare_retrieve_request(char *request, char *uid, char *tid, char *fname);
void treat_rrt(char* buffer);

//upload
void upload(char* fname, char* fsize, char* data, char* tid, char* buffer, char* uid);
void prepare_upload_request(char *request, char *uid, char *tid, char *fname,
                            char *fsize, char *data, int fs_fd);
void treat_rup(char* buffer);

//delete
void delete(char* fname, char* tid, char* buffer, char* uid);
void prepare_delete_request(char *request, char *uid, char *tid, char *fname);
void treat_rdl(char* buffer);

//remove
void rem(char* tid, char* buffer, char* uid, int as_fd);
void prepare_remove_request(char *request, char *uid, char *tid);
void treat_rrm(char* buffer);

//exit
void ex(int as_fd);

//global
Boolean parse_retrieve_upload_delete(char *fname);

//Initializes TCP connection to FS
int init_socket_to_fs();

//RID generator
void generate_random_rid(char rid[], int size);

#endif /* USER_H */