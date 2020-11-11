#include "user.h"

char *asip, *asport, *fsip, *fsport;
char login_success[SIZE];
char req_success[SIZE];

int main(int argc, char const *argv[])
{
    //User-AS variables
    int as_fd, errcode_as;
    ssize_t n;
    struct addrinfo hints_as, *res_as;

    //User-FS variables
    int fs_fd, errcode_fs;
    ssize_t m;
    struct addrinfo hints_fs, *res_fs;

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

    errcode_as = getaddrinfo(asip, asport, &hints_as, &res_as);
    if (errcode_as != 0)
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

    char buffer[SIZE], command[SIZE], uid[SIZE], password[SIZE], rid[SIZE],
        fop[FOP_SIZE], fname[SIZE], vc[SIZE], tid[SIZE], fsize[SIZE], data[SIZE];

    memset(buffer, EOS, SIZE);
    memset(command, EOS, SIZE);
    memset(uid, EOS, SIZE);
    memset(password, EOS, SIZE);
    memset(rid, EOS, SIZE);
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
        printf("message sent to AS = %s", buffer);

        // receives the AS response message
        memset(buffer, EOS, SIZE);
        n = tcp_read(as_fd, buffer, SIZE);
        printf("message received from AS = %s", buffer);

        // checks if the response is OK. If so the loop ends
    } while (!verify_login_response(buffer, n));

    while (1)
    {
        read_stdin(buffer);
        strcpy(command, strtok(buffer, " "));

        if (strcmp(command, USER_REQUEST) == 0)
        {
            if (parse_req(fop, fname))
            {
                prepare_req_request(buffer, uid, fop, fname, rid);

                // sends the login message to AS via tcp connection
                n = tcp_write(as_fd, buffer);
                printf("message sent to AS = %s", buffer);

                // receives the AS response message
                memset(buffer, EOS, SIZE);
                n = tcp_read(as_fd, buffer, SIZE);
                printf("message received from AS = %s", buffer);
            };
        }
        if (strcmp(command, USER_VAL) == 0)
        {
            if (parse_val(vc))
            {
                prepare_val_request(buffer, uid, rid, vc);

                // sends the login message to AS via tcp connection
                n = tcp_write(as_fd, buffer);
                printf("message sent to AS = %s", buffer);

                // receives the AS response message
                memset(buffer, EOS, SIZE);
                n = tcp_read(as_fd, buffer, SIZE);
                printf("message received from AS = %s", buffer);

                //sets TID
                char *token = strtok(buffer, " ");
                token = strtok(NULL, " ");
                strcpy(tid, token);
                printf("TID is now: %s\n", tid);

                if (strcmp(tid, "0") == 0)
                {
                    printf("Authentication failed.\n");
                }
            }
        }
        if (strcmp(command, USER_LIST) == 0 || strcmp(command, USER_LIST_SHORT) == 0)
        {
            init_socket_to_fs(fs_fd, errcode_fs, m, hints_fs, res_fs);

            prepare_list_request(buffer, uid, tid);

            // sends the login message to FS via tcp connection
            n = tcp_write(fs_fd, buffer);
            printf("message sent to AS = %s", buffer);

            // receives the FS response message
            memset(buffer, EOS, SIZE);
            n = tcp_read(fs_fd, buffer, SIZE);
            printf("message received from AS = %s", buffer);

            //treat received message
            treat_rls(buffer);
        }
        if (strcmp(command, USER_RETRIEVE) == 0 || strcmp(command, USER_RETRIEVE_SHORT) == 0)
        {
            if (parse_retrieve_upload_delete(fname))
            {
                init_socket_to_fs(fs_fd, errcode_fs, m, hints_fs, res_fs);

                prepare_retrieve_request(buffer, uid, tid, fname);

                // sends the login message to FS via tcp connection
                n = tcp_write(fs_fd, buffer);
                printf("message sent to AS = %s", buffer);

                // receives the FS response message
                memset(buffer, EOS, SIZE);
                n = tcp_read(fs_fd, buffer, SIZE);
                printf("message received from AS = %s", buffer);

                //TODO: display name and path of file
                //treat received message
                treat_rrt(buffer);

                close(fs_fd);
            }
        }
        if (strcmp(command, USER_UPLOAD) == 0 || strcmp(command, USER_UPLOAD_SHORT) == 0)
        {
            if (parse_retrieve_upload_delete(fname))
            {
                init_socket_to_fs(fs_fd, errcode_fs, m, hints_fs, res_fs);

                prepare_upload_request(buffer, uid, tid, fname, fsize, data);

                // sends the login message to FS via tcp connection
                n = tcp_write(fs_fd, buffer);
                printf("message sent to AS = %s", buffer);

                // receives the FS response message
                memset(buffer, EOS, SIZE);
                n = tcp_read(fs_fd, buffer, SIZE);
                printf("message received from AS = %s", buffer);

                //TODO: display succes/failure
                //treat received message
                treat_rup(buffer);

                close(fs_fd);
            }
        }
        if (strcmp(command, USER_DELETE) == 0 || strcmp(command, USER_DELETE_SHORT) == 0)
        {
            if (parse_retrieve_upload_delete(fname))
            {
                init_socket_to_fs(fs_fd, errcode_fs, m, hints_fs, res_fs);

                prepare_delete_request(buffer, uid, tid, fname);

                // sends the login message to FS via tcp connection
                n = tcp_write(fs_fd, buffer);
                printf("message sent to AS = %s", buffer);

                // receives the FS response message
                memset(buffer, EOS, SIZE);
                n = tcp_read(fs_fd, buffer, SIZE);
                printf("message received from AS = %s", buffer);

                //TODO: display succes/failure
                //treat received message
                treat_rdl(buffer);

                close(fs_fd);
            }
        }
        if (strcmp(command, USER_REMOVE) == 0 || strcmp(command, USER_REMOVE_SHORT) == 0)
        {
            init_socket_to_fs(fs_fd, errcode_fs, m, hints_fs, res_fs);

            prepare_remove_request(buffer, uid, tid);

            // sends the login message to FS via tcp connection
            n = tcp_write(fs_fd, buffer);
            printf("message sent to AS = %s", buffer);

            // receives the FS response message
            memset(buffer, EOS, SIZE);
            n = tcp_read(fs_fd, buffer, SIZE);
            printf("message received from AS = %s", buffer);

            //display succes/failure
            //treat received message
            treat_rrm(buffer);

            close(fs_fd);
        }
        if (strcmp(command, USER_EXIT) == 0)
        {
            exit(EXIT_SUCCESS);
        }

        memset(buffer, EOS, SIZE);
        memset(command, EOS, SIZE);
        memset(fname, EOS, SIZE);
        memset(vc, EOS, SIZE);
        memset(fsize, EOS, SIZE);
        memset(data, EOS, SIZE);
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

    token = strtok(NULL, " ");
    if (token)
    {
        fprintf(stderr, "Too many arguments!\n");
        return false;
    }

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
        printf("%s\n", SERVER_DOWN_MESSAGE);
        return false;
    }

    if (!strcmp(buffer, login_success))
    {
        printf("%s\n", SUCCESS_MESSAGE);
        return true;
    }

    printf("%s\n", FAILURE_MESSAGE);
    //printf("response: %s\n", buffer);
    return false;
}

/*req*/
Boolean parse_req(char *fop, char *fname)
{
    char *token = strtok(NULL, " ");

    if (!token)
    {
        fprintf(stderr, "Fop missing!\nMust give a Fop\n");
        return false;
    }
    strcpy(fop, token);

    token = strtok(NULL, " ");
    if (strcmp(fop, "L") == 0 || strcmp(fop, "X") == 0)
    {
        if (token)
        {
            fprintf(stderr, "File operation given does not need file.\n");
            return false;
        }
    }
    else
    {
        if (!token)
        {
            fprintf(stderr, "File operation give needs a file.\n");
            return false;
        }
        else
        {
            strcpy(fname, token);
        }
    }

    token = strtok(NULL, " ");
    if (token)
    {
        fprintf(stderr, "Too many arguments!\n");
        return false;
    }

    printf("fop = %s\nfname = %s\n", fop, fname);

    return true;
}

void prepare_req_request(char *request, char *uid, char *fop, char *fname, char *rid)
{
    generate_random_rid(rid, RID_SIZE);

    memset(request, EOS, SIZE);
    strcpy(request, REQUEST);
    strcat(request, " ");
    strcat(request, uid);
    strcat(request, " ");
    strcat(request, rid);
    strcat(request, " ");
    strcat(request, fop);
    if (strlen(fname) > 0)
    {
        strcat(request, " ");
        strcat(request, fname);
    }
    strcat(request, "\n");

    printf("uid = %s\n", uid);
    printf("rid = %s\n", rid);
    printf("fop = %s\n", fop);
    printf("fname = %s\n", fname);
    printf("request = %s\n", request);
}

/*val*/
Boolean parse_val(char *vc)
{
    char *token = strtok(NULL, " ");

    if (!token)
    {
        fprintf(stderr, "VC missing!\nMust give a VC\n");
        return false;
    }
    strcpy(vc, token);

    token = strtok(NULL, " ");
    if (token)
    {
        fprintf(stderr, "Too many arguments!\n");
        return false;
    }

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

void treat_rls(char *buffer)
{
    char *token = strtok(buffer, " ");

    if (strcmp(token, LIS_RESPONSE) != 0)
    {
        fprintf(stderr, "Did not receive RLS!\n");
        return;
    }

    token = strtok(NULL, " ");
    if (!token)
    {
        fprintf(stderr, "Did not receive number of files!\n");
        return;
    }
    int i = atoi(token);

    token = strtok(NULL, " ");

    for (int j = 0; j < i; i++)
    {
        printf("%d - filename: %s\t", j + 1, token);
        token = strtok(NULL, " ");
        printf("filesize: %s\n", token);
        token = strtok(NULL, " ");
    }
}

/*retrieve*/
Boolean parse_retrieve_upload_delete(char *fname)
{
    char *token = strtok(NULL, " ");
    if (!token)
    {
        fprintf(stderr, "UID missing!\nMust give a UID\n");
        return false;
    }
    strcpy(fname, token);

    token = strtok(NULL, " ");
    if (token)
    {
        fprintf(stderr, "Too many arguments!\n");
        return false;
    }

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

void treat_rrt(char *buffer)
{
    char *token = strtok(buffer, " ");

    if (strcmp(token, RET_RESPONSE) != 0)
    {
        fprintf(stderr, "Did not receive UPL!\n");
        return;
    }
    token = strtok(NULL, " ");

    //OK
    if(strcmp(token, OK)){
        token = strtok((NULL), " ");
        printf("filename: %s\t", token);
        token = strtok(NULL, " ");
        printf("filesize: %s\n", token);
    }
    //EOF
    else if(strcmp(token, FILE_UNAVAILABLE)){
        fprintf(stderr, "File is not available.\n");
    }
    //NOK
    else if(strcmp(token, NOT_OK)){
        fprintf(stderr, "No content available for current UID.\n");
    }
    //INV
    else if(strcmp(token, AS_VALIDATION_ERROR)){
        fprintf(stderr, "Validation error.\n");
    }
    //ERR
    else if(strcmp(token, PROTOCOL_ERROR)){
        fprintf(stderr, "Request is not correctly formulated.\n");
    }
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

void treat_rup(char* buffer)
{
    char *token = strtok(buffer, " ");

    if (strcmp(token, UPL_RESPONSE) != 0)
    {
        fprintf(stderr, "Did not receive UPL!\n");
        return;
    }
    token = strtok(NULL, " ");

    //OK
    if(strcmp(token, OK)){
        printf(SUCCESS_MESSAGE);
        printf("\n");
    }
    //DUP
    else if(strcmp(token, FILE_UNAVAILABLE)){
        printf(FAILURE_MESSAGE);
        fprintf(stderr, " File already exists.\n");
    }
    //FULL
    else if(strcmp(token, NOT_OK)){
        printf(FAILURE_MESSAGE);
        fprintf(stderr, " FS is full, user already uploaded 15 files.\n");
    }
    //INV
    else if(strcmp(token, AS_VALIDATION_ERROR)){
        printf(FAILURE_MESSAGE);
        fprintf(stderr, " Validation error.\n");
    }
    //ERR
    else if(strcmp(token, PROTOCOL_ERROR)){
        printf(FAILURE_MESSAGE);
        fprintf(stderr, " Request is not correctly formulated.\n");
    }
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

void treat_rdl(char* buffer)
{
    char *token = strtok(buffer, " ");

    if (strcmp(token, DEL_RESPONSE) != 0)
    {
        fprintf(stderr, "Did not receive DEL!\n");
        return;
    }
    token = strtok(NULL, " ");

    //OK
    if(strcmp(token, OK)){
        printf(SUCCESS_MESSAGE);
        printf("\n");
    }
    //NOK
    else if(strcmp(token, NOT_OK)){
        printf(FAILURE_MESSAGE);
        fprintf(stderr, " UID does not exist.\n");
    }
    //INV
    else if(strcmp(token, AS_VALIDATION_ERROR)){
        printf(FAILURE_MESSAGE);
        fprintf(stderr, " Validation error.\n");
    }
    //ERR
    else if(strcmp(token, PROTOCOL_ERROR)){
        printf(FAILURE_MESSAGE);
        fprintf(stderr, " Request is not correctly formulated.\n");
    }
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

void treat_rrm(char* buffer)
{
    char *token = strtok(buffer, " ");

    if (strcmp(token, REM_RESPONSE) != 0)
    {
        fprintf(stderr, "Did not receive REM!\n");
        return;
    }
    token = strtok(NULL, " ");

    //OK
    if(strcmp(token, OK)){
        printf(SUCCESS_MESSAGE);
        printf("\n");
    }
    //NOK
    else if(strcmp(token, NOT_OK)){
        printf(FAILURE_MESSAGE);
        fprintf(stderr, " UID does not exist.\n");
    }
    //INV
    else if(strcmp(token, AS_VALIDATION_ERROR)){
        printf(FAILURE_MESSAGE);
        fprintf(stderr, " Validation error.\n");
    }
    //ERR
    else if(strcmp(token, PROTOCOL_ERROR)){
        printf(FAILURE_MESSAGE);
        fprintf(stderr, " Request is not correctly formulated.\n");
    }
}

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

void init_socket_to_fs(int fs_fd, int errcode_fs, ssize_t m, struct addrinfo hints_fs,
                       struct addrinfo *res_fs)
{
    //connection to FS
    fs_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fs_fd == ERROR)
        exit(EXIT_FAILURE); //error

    memset(&hints_fs, 0, sizeof hints_fs);
    hints_fs.ai_family = AF_INET;
    hints_fs.ai_socktype = SOCK_STREAM;

    errcode_fs = getaddrinfo(asip, asport, &hints_fs, &res_fs);
    if (errcode_fs != 0)
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

void generate_random_rid(char rid[], int size)
{
    int rid_alg, rid_number = 0;

    // uses the current time as seed for random generator
    srand(time(NULL) % RND);
    memset(rid, EOS, size);
    for (int i = 0; i < (size - 1); i++)
    {
        rid_alg = rand() % 10;
        rid_number = rid_number * 10 + rid_alg;
        printf("rid_alg=%d\trid_number=%d\n", rid_alg, rid_number);
    }

    // converts the random number into a string with 4 digits
    sprintf(rid, "%04d", rid_number);
}
