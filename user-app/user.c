#include "user.h"

char *asip, *asport, *fsip, *fsport;
char login_success[SIZE];
char req_success[SIZE];

int main(int argc, char const *argv[])
{
    int as_fd, errcode;
    ssize_t n;
    //socklen_t addrlen;
    struct addrinfo hints_as, *res_as;
    //struct sockaddr_in addr;
    char buffer[SIZE];

    //array for used RIDs and its length
    int rid_list[MAX_RID];
    int j = 0;

    // checks if the number of arguments is correct
    if (wrong_arguments(argc))
    {
        usage();
        exit(EXIT_FAILURE);
    }

    // treats the SIGINT signal
    signal(SIGINT, handler_sigint);

    // parses the argv arguments
    parse_arguments(argv, argc);

    printf("ASIP=%s\n", asip);
    printf("ASport=%s\n", asport);
    printf("FSIP=%s\n", fsip);
    printf("FSport=%s\n\n", fsport);

    //connection to AS
    as_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (as_fd == ERROR)
        exit(EXIT_FAILURE); //error

    memset(&hints_as, 0, sizeof hints_as);
    hints_as.ai_family = AF_INET;
    hints_as.ai_socktype = SOCK_STREAM;

    errcode = getaddrinfo(asip, asport, &hints_as, &res_as);
    if (errcode != 0)
    {
        //error
        fprintf(stderr, "Error: could not get address info\n");
        exit(EXIT_FAILURE);
    }
    //TCP socket
    //IPv4
    //TCP socket
    n = connect(as_fd, res_as->ai_addr, res_as->ai_addrlen);
    if (n == ERROR)
    {
        //error
        fprintf(stderr, "Error: could not connect\n");
        exit(EXIT_FAILURE);
    }

    char command[SIZE], uid[SIZE], password[SIZE], rid[SIZE], fop[1], fname[SIZE],
        vc[SIZE], tid[SIZE], fsize[SIZE], data[SIZE];

    memset(buffer, EOS, SIZE);
    memset(command, EOS, SIZE);
    memset(uid, EOS, SIZE);
    memset(password, EOS, SIZE);
    memset(fname, EOS, SIZE);
    memset(vc, EOS, SIZE);
    memset(tid, EOS, SIZE);
    memset(fsize, EOS, SIZE);
    memset(data, EOS, SIZE);

    // writes the "registration success" message
    memset(login_success, EOS, SIZE);
    strcpy(login_success, LOG_RESPONSE);
    strcat(login_success, " ");
    strcat(login_success, OK);
    strcat(login_success, "\n");

    do
    {
        // reads the stdin and checks for login command
        read_stdin(buffer);
        if (!parse_login_message(buffer, command, uid, password))
        {
            continue;
        }

        // if there is a login command prepares the login message to be sent
        memset(buffer, EOS, SIZE);
        if (!prepare_login_request(buffer, command, uid, password))
        {
            continue;
        }

        printf("request: %s\n", buffer);

        // sends the login message to AS via tcp connection
        n = tcp_write(as_fd, buffer);

        // receives the AS response message
        memset(buffer, EOS, SIZE);
        n = tcp_read(as_fd, buffer, SIZE);

        // checks if the response is OK. If so the loop ends
    } while (!verify_login_response(buffer, n));

    while (1)
    {
        read_stdin(buffer);
        strcpy(command, strtok(buffer, " "));

        if (strcmp(command, "req") == 0)
        {
            if (parse_req(buffer, fop, fname))
            {
                prepare_req_request(buffer, uid, fop, fname, rid_list[], j);

                // sends the login message to AS via tcp connection
                n = tcp_write(as_fd, buffer);

                // receives the AS response message
                memset(buffer, EOS, SIZE);
                n = tcp_read(as_fd, buffer, SIZE);
            };
        }
        if (strcmp(command, "val") == 0)
        {
            if (parse_val(buffer, vc))
            {
                prepare_val_request(buffer, uid, rid, vc);
                
                // sends the login message to AS via tcp connection
                n = tcp_write(as_fd, buffer);

                // receives the AS response message
                memset(buffer, EOS, SIZE);
                n = tcp_read(as_fd, buffer, SIZE);
            }
        }
        if (strcmp(command, "list") == 0 || strcmp(command, "l") == 0)
        {
            prepare_list_request(buffer, uid, tid);
            //socket FS
        }
        if (strcmp(command, "retrieve") == 0 || strcmp(command, "r") == 0)
        {
            if (parse_retrieve_upload_delete(buffer, fname))
            {
                prepare_retrieve_request(buffer, uid, tid, fname);
                //socket FS
            }
        }
        if (strcmp(command, "upload") == 0 || strcmp(command, "u") == 0)
        {
            if (parse_retrieve_upload_delete(buffer, fname))
            {
                prepare_upload_request(buffer, uid, tid, fname, fsize, data);
                //socket FS
            }
        }
        if (strcmp(command, "delete") == 0 || strcmp(command, "d") == 0)
        {
            if (parse_retrieve_upload_delete(buffer, fname))
            {
                prepare_delete_request(buffer, uid, tid, fname);
                //socket FS
            }
        }
        if (strcmp(command, "remove") == 0 || strcmp(command, "x") == 0)
        {
            printf("Programa fechado.\n");
            prepare_remove_request(buffer, uid, tid);
            //socket FS
        }
        if(strcmp(command, "exit") == 0){
            exit(EXIT_SUCCESS);
        }
    }
}

void usage()
{
    printf("usage: ./user [-n ASIP] [-p ASport] [-m FSIP] [-q FSport]\n");
    printf("example: ./user -n 193.136.138.142 -p 58011 -m 193.136.138.142 -q 59000\n");
    //alterar exemplo flag -m
}

int wrong_arguments(int argc)
{
    return !(argc > 0 && argc % 2 == 1 && argc <= 9);
}

// parses the arguments given on the command line
void parse_arguments(const char *argv[], int size)
{
    parse_as_ip(argv, size, LOCALHOST, &asip);
    parse_as_port(argv, size, &asport);
    parse_fs_ip(argv, size, LOCALHOST, &fsip);
    parse_fs_port(argv, size, &fsport);
}

/*login*/
Boolean parse_login_message(char *buffer, char *command, char *uid, char *password)
{
    char *token = strtok(buffer, " ");

    if (!token)
    {
        fprintf(stderr, "Command missing!\nMust give a command\n");
        return false;
    }
    else if (strcmp(token, USER_LOGIN) != 0)
    {
        fprintf(stderr, "You did not login.\nDid you mean to use command '%s'?\n", USER_LOGIN);
        return false;
    }
    strcpy(command, token);

    token = strtok(NULL, " ");
    if (!token)
    {
        fprintf(stderr, "UID missing!\nMust give a UID\n");
        return false;
    }
    strcpy(uid, token);

    token = strtok(NULL, " ");
    if (!token)
    {
        fprintf(stderr, "Password missing!\nMust give a password\n");
        return false;
    }
    strcpy(password, token);

    return true;
}

Boolean prepare_login_request(char *request, char *command, char *uid, char *password)
{

    if (strcmp(command, USER_LOGIN))
    {
        return false;
    }

    strcpy(request, LOGIN);
    strcat(request, " ");
    strcat(request, uid);
    strcat(request, " ");
    strcat(request, password);
    strcat(request, "\n");

    return true;
}

Boolean verify_login_response(char *buffer, int size)
{
    printf("response: %s\n", buffer);
    if (!size)
    {
        printf("%s\n\n", SERVER_DOWN_MESSAGE);
        return false;
    }

    if (!strcmp(buffer, login_success))
    {
        printf("%s\n\n", SUCCESS_MESSAGE);
        return true;
    }

    printf("%s\n\n", FAILURE_MESSAGE);
    //printf("response: %s\n", buffer);
    return false;
}

/*req*/
Boolean parse_req(char *buffer, char *fop, char *fname)
{
    char *token;

    token = strtok(NULL, " ");
    if (!token)
    {
        fprintf(stderr, "Fop missing!\nMust give a Fop\n");
        return false;
    }
    strcpy(fop, token);

    token = strtok(NULL, " ");

    if (strcmp(fop, USER_LIST_SHORT) == 0 || strcmp(fop, USER_REMOVE_SHORT) == 0)
    {
        if (token)
        {
            fprintf(stderr, "File operation given does not need file.\n");
            return false;
        }
        else
        {
            strcpy(fname, token);
        }
    }
    else
    {
        if (!token)
        {
            fprintf(stderr, "File operation give needs a file.\n");
            return false;
        }
    }

    return true;
}

void prepare_req_request(char *request, char *uid, char *fop, char *fname
                         int rid_list[], int j)
{
    char rid[4];
    int rid_used = 0, random;

    for (int i = 0; i < 4; i++)
    {
        random = rand();

        rid[i] = random + '0';
        rid_used += random * (1000 / (i + 1));
    }
    rid_list[j] = rid_used;

    strcpy(request, REQUEST);
    strcat(request, " ");
    strcat(request, uid);
    strcat(request, " ");
    strcat(request, rid);
    strcat(request, " ");
    strcat(request, fop);
    strcat(request, " ");
    strcat(request, fname);
    strcat(request, "\n");
}

/*val*/
Boolean parse_val(char *buffer, char *vc)
{
    char *token;

    token = strtok(NULL, " ");
    if (!token)
    {
        fprintf(stderr, "VC missing!\nMust give a VC\n");
        return false;
    }
    strcpy(vc, token);

    return true;
}

void prepare_val_request(char *request, char *uid, char *rid, char *vc)
{
    strcpy(request, AUTHENTICATION);
    strcat(request, " ");
    strcat(request, uid);
    strcat(request, " ");
    strcat(request, rid);
    strcat(request, " ");
    strcat(request, vc);
    strcat(request, "\n");
}

/*list*/
//nao precisa de parser

void prepare_list_request(char *request, char *uid, char *tid)
{
    strcpy(request, LIST);
    strcat(request, " ");
    strcat(request, uid);
    strcat(request, " ");
    strcat(request, tid);
    strcat(request, "\n");
}

/*retrieve*/
Boolean parse_retrieve_upload_delete(char *buffer, char *fname)
{
    char *token;

    token = strtok(NULL, " ");
    if (!token)
    {
        fprintf(stderr, "UID missing!\nMust give a UID\n");
        return false;
    }
    strcpy(fname, token);

    return true;
}

void prepare_retrieve_request(char *request, char *uid, char *tid, char *fname)
{
    strcpy(request, RETRIEVE);
    strcat(request, " ");
    strcat(request, uid);
    strcat(request, " ");
    strcat(request, tid);
    strcat(request, " ");
    strcat(request, fname);
    strcat(request, "\n");
}

/*upload*/
//usa parser do retrieve
void prepare_upload_request(char *request, char *uid, char *tid, char *fname,
                            char *fsize, char *data)
{
    strcpy(request, UPLOAD);
    strcat(request, " ");
    strcat(request, uid);
    strcat(request, " ");
    strcat(request, tid);
    strcat(request, " ");
    strcat(request, fname);
    strcat(request, " ");
    strcat(request, fsize);
    strcat(request, " ");
    strcat(request, data);
    strcat(request, "\n");
}

/*delete*/
//usa parser do retrieve
void prepare_delete_request(char *request, char *uid, char *tid, char *fname)
{
    strcpy(request, DELETE);
    strcat(request, " ");
    strcat(request, uid);
    strcat(request, " ");
    strcat(request, tid);
    strcat(request, " ");
    strcat(request, fname);
    strcat(request, "\n");
}

/*remove*/
//nao precisa de parser
void prepare_remove_request(char *request, char *uid, char *tid)
{
    strcpy(request, REMOVE);
    strcat(request, " ");
    strcat(request, uid);
    strcat(request, " ");
    strcat(request, tid);
    strcat(request, "\n");
}

/*exit*/
//nao precisa de nada

void verify_command_response(char *buffer, int size)
{
    printf("response: %s\n", buffer);
    if (!size)
    {
        printf("%s\n", SERVER_DOWN_MESSAGE);
    }

    if (!strcmp(buffer, req_success))
    {
        printf("%s\n", SUCCESS_MESSAGE);
    }

    printf("%s\n", FAILURE_MESSAGE);
    //printf("response: %s\n", buffer);
}

void socket_to_fs()
{
    ssize_t m;
    struct addrinfo hints_fs, *res_fs;
    int errcode, fs_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fs_fd == ERROR)
        exit(EXIT_FAILURE); //error

    memset(&hints_fs, 0, sizeof hints_fs);
    hints_fs.ai_family = AF_INET;
    hints_fs.ai_socktype = SOCK_STREAM;

    errcode = getaddrinfo(fsip, fsport, &hints_fs, &res_fs);
    if (errcode != 0)
    {
        //error
        fprintf(stderr, "Error: could not get address info\n");
        exit(EXIT_FAILURE);
    }
    //TCP socket
    //IPv4
    //TCP socket
    m = connect(fs_fd, res_fs->ai_addr, res_fs->ai_addrlen);
    if (m == ERROR)
    {
        //error
        fprintf(stderr, "Error: could not connect\n");
        exit(EXIT_FAILURE);
    }
}
