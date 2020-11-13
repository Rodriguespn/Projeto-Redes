#include "user.h"

char *asip, *asport, *fsip, *fsport;
char login_success[SIZE];

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
        exit(EXIT_FAILURE);

    memset(&hints_as, 0, sizeof hints_as);
    hints_as.ai_family = AF_INET;
    hints_as.ai_socktype = SOCK_STREAM;

    errcode_as = getaddrinfo(asip, asport, &hints_as, &res_as);
    if (errcode_as != 0)
    {
        fprintf(stderr, "Error: could not get address info\n");
        exit(EXIT_FAILURE);
    }

    n = connect(as_fd, res_as->ai_addr, res_as->ai_addrlen);
    if (n == ERROR)
    {
        fprintf(stderr, "Error: could not connect\n");
        exit(EXIT_FAILURE);
    }

    //connection to FS
    fs_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fs_fd == ERROR)
        exit(EXIT_FAILURE);

    memset(&hints_fs, 0, sizeof hints_fs);
    hints_fs.ai_family = AF_INET;
    hints_fs.ai_socktype = SOCK_STREAM;

    errcode_fs = getaddrinfo(asip, asport, &hints_fs, &res_fs);
    if (errcode_fs != 0)
    {
        fprintf(stderr, "Error: could not get address info\n");
        exit(EXIT_FAILURE);
    }

    m = connect(fs_fd, res_fs->ai_addr, res_fs->ai_addrlen);
    if (m == ERROR)
    {
        fprintf(stderr, "Error: could not connect\n");
        exit(EXIT_FAILURE);
    }

    //variables
    char buffer[SIZE], command[SIZE], last_command[SIZE], uid[SIZE], password[SIZE], rid[SIZE],
        fop[FOP_SIZE], fname[SIZE], vc[SIZE], tid[SIZE], fsize[SIZE], data[SIZE];

    memset(buffer, EOS, SIZE);
    memset(command, EOS, SIZE);
    memset(last_command, EOS, SIZE);
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

    /*Sequence of actions: 
        - exit may be executed whenever;
        - first action must be login;
        - after req action must be either req or val;
        - after val action can be anyone but val or login;
        - after an user-fs command or login action must be req;
    */
    do
    {
        // reads the stdin and checks for login command
        read_stdin(buffer);
        // reads the stdin and checks for exit command
        if (strcmp(buffer, USER_EXIT) == 0)
        {
            close(as_fd);
            exit(EXIT_SUCCESS);
        }
        else if (!parse_login_message(buffer, command, uid, password))
        {
            continue;
        }
        memset(buffer, EOS, SIZE);
        // if there is a login command prepares the login message to be sent
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
    } while (!verify_login_response(buffer));

    while (1)
    {
        read_stdin(buffer);
        strcpy(command, strtok(buffer, " "));

        //if the last action was req, it will check for req, val or exit
        if (strcmp(last_command, USER_REQUEST) == 0)
        {
            //req
            if (strcmp(command, USER_REQUEST) == 0)
                req(fop, fname, buffer, uid, rid, as_fd, n);

            //val
            else if (strcmp(command, USER_VAL) == 0)
                val(vc, tid, buffer, uid, rid, as_fd, n);

            //exit
            else if (strcmp(command, USER_EXIT) == 0)
            {
                ex(as_fd);
            }

            //others
            else
            {
                printf("Not accepted. Possible actions: 'req', 'val' or 'exit'.\n");
                continue;
            }
        }

        //if the last action was val, it will check for anyone but val or login
        else if (strcmp(last_command, USER_VAL) == 0)
        {
            //req
            if (strcmp(command, USER_REQUEST) == 0)
                req(fop, fname, buffer, uid, rid, as_fd, n);

            //list
            else if (strcmp(command, USER_LIST) == 0 || strcmp(command, USER_LIST_SHORT) == 0)
                list(tid, buffer, uid);

            //retrieve
            else if (strcmp(command, USER_RETRIEVE) == 0 || strcmp(command, USER_RETRIEVE_SHORT) == 0)
                retrieve(fname, tid, buffer, uid);

            //upload
            else if (strcmp(command, USER_UPLOAD) == 0 || strcmp(command, USER_UPLOAD_SHORT) == 0)
                upload(fname, fsize, data, tid, buffer, uid);

            //delete
            else if (strcmp(command, USER_DELETE) == 0 || strcmp(command, USER_DELETE_SHORT) == 0)
                delete (fname, tid, buffer, uid);

            //remove
            else if (strcmp(command, USER_REMOVE) == 0 || strcmp(command, USER_REMOVE_SHORT) == 0)
                rem(tid, buffer, uid, as_fd);

            //exit
            else if (strcmp(command, USER_EXIT) == 0)
                ex(as_fd);

            //other
            else
            {
                printf("Not accepted. Impossible actions: 'val' and 'login'.\n");
                continue;
            }
        }

        //if the last action was an User_FS command(else) or login, action must
        //be either req or exit
        else
        {
            //req
            if (strcmp(command, USER_REQUEST) == 0)
                req(fop, fname, buffer, uid, rid, as_fd, n);

            //exit
            else if (strcmp(command, USER_EXIT) == 0)
                ex(as_fd);

            //other
            else
            {
                printf("Not accepted. Possible actions: 'req' and 'exit'.\n");
                continue;
            }
        }

        strcpy(last_command, command);

        //clean variables
        memset(command, EOS, SIZE);
        memset(buffer, EOS, SIZE);
        memset(fname, EOS, SIZE);
        memset(vc, EOS, SIZE);
        memset(fsize, EOS, SIZE);
        memset(data, EOS, SIZE);
    }
}

//shows the correct way to run user.c
void usage()
{
    printf("usage: ./user [-n ASIP] [-p ASport] [-m FSIP] [-q FSport]\n");
    printf("example: ./user -n 193.136.138.142 -p 58011 -m 193.136.138.142 -q 59000\n");
}

//ensures the number of arguments given when running is correct
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

//login action functions
Boolean parse_login_message(char *buffer, char *command, char *uid, char *password)
{
    char *token = strtok(buffer, " ");

    if (!token)
    {
        fprintf(stderr, "Command missing! Must give a command\n");
        return false;
    }
    else if (strcmp(token, USER_LOGIN) != 0)
    {
        fprintf(stderr, "You did not login. Did you mean to use command '%s'?\n", USER_LOGIN);
        return false;
    }
    strcpy(command, token);

    token = strtok(NULL, " ");
    if (!token)
    {
        fprintf(stderr, "UID missing! Must give a UID\n");
        return false;
    }
    strcpy(uid, token);

    token = strtok(NULL, " ");
    if (!token)
    {
        fprintf(stderr, "Password missing! Must give a password\n");
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

Boolean verify_login_response(char *buffer)
{
    printf("response: %s\n", buffer);

    if (!strcmp(buffer, login_success))
    {
        printf("%s\n", SUCCESS_MESSAGE);
        return true;
    }
    else
    {
        printf("%s\n", FAILURE_MESSAGE);
        return false;
    }
}

//req action functions
void req(char *fop, char *fname, char *buffer, char *uid, char *rid, int as_fd, ssize_t n)
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

        //treat the received message
        treat_rrq(buffer);

        //tirar isto
        printf("(ignore this (%ld))\n", n);
    }
}

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

void treat_rrq(char *buffer)
{
    char *token = strtok(buffer, " ");

    if (strcmp(token, REQ_RESPONSE) != 0)
    {
        fprintf(stderr, "Did not receive %s!\n", REQ_RESPONSE);
        return;
    }
    token = strtok(NULL, " ");

    //OK
    if (strcmp(token, OK))
    {
        printf(SUCCESS_MESSAGE);
        printf("\n");
    }
    //ELOG
    else if (strcmp(token, NOT_LOGGED_IN))
    {
        printf(FAILURE_MESSAGE);
        printf(" There was not a successful login.\n");
    }
    //EPD
    else if (strcmp(token, PD_NOT_AVAILABLE))
    {
        printf(FAILURE_MESSAGE);
        printf(" Message was not sent by AS to PD.\n");
    }
    //EUSER
    else if (strcmp(token, INVALID_UID))
    {
        printf(FAILURE_MESSAGE);
        printf(" UID is incorrect.\n");
    }
}

//val action functions
void val(char *vc, char *tid, char *buffer, char *uid, char *rid, int as_fd, ssize_t n)
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

        //treat the received message
        treat_rau(buffer, tid);

        //tirar isto
        printf("(ignore this (%ld))\n", n);
    }
}

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

void treat_rau(char *buffer, char *tid)
{
    char *token = strtok(buffer, " ");
    if (strcmp(token, AUT_RESPONSE) != 0)
    {
        fprintf(stderr, "Did not receive %s!\n", AUT_RESPONSE);
        return;
    }
    token = strtok(NULL, " ");

    if (strcmp(token, TID_ERROR) == 0)
    {
        printf(FAILURE_MESSAGE);
        printf(" Authentication failed.\n");
        return;
    }
    else
    {
        strcpy(tid, token);
        printf("%s TID is now: %s\n", SUCCESS_MESSAGE, tid);
    }
}

//list action functions
void list(char *tid, char *buffer, char *uid)
{
    int fs_fd = init_socket_to_fs();

    prepare_list_request(buffer, uid, tid);

    // sends the login message to FS via tcp connection
    tcp_write(fs_fd, buffer);
    printf("message sent to FS = %s", buffer);

    // receives the FS response message
    memset(buffer, EOS, SIZE);
    tcp_read(fs_fd, buffer, SIZE);
    printf("message received from FS = %s", buffer);

    //treat received message
    treat_rls(buffer);

    close(fs_fd);
}

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

//retrieve action functions
void retrieve(char *fname, char *tid, char *buffer, char *uid)
{
    if (parse_retrieve_upload_delete(fname))
    {
        int fs_fd = init_socket_to_fs();

        prepare_retrieve_request(buffer, uid, tid, fname);

        // sends the login message to FS via tcp connection
        tcp_write(fs_fd, buffer);
        printf("message sent to FS = %s", buffer);

        // receives the FS response message
        memset(buffer, EOS, SIZE);
        tcp_read(fs_fd, buffer, SIZE);
        printf("message received from FS = %s", buffer);

        //treat received message
        treat_rrt(buffer);

        close(fs_fd);
    }
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
    int fsize_value;
    char fsize[SIZE];
    char data[SIZE];
    char *token = strtok(buffer, " ");

    if (strcmp(token, RET_RESPONSE) != 0)
    {
        fprintf(stderr, "Did not receive RRT!\n");
        return;
    }
    token = strtok(NULL, " ");

    //OK
    if (strcmp(token, OK) == 0)
    {
        token = strtok(NULL, " ");
        if (!token)
        {
            fprintf(stderr, "Did not receive number of file size!\n");
            return;
        }
        strcpy(fsize, token);
        fsize_value = atoi(fsize);

        token = strtok(NULL, " ");
        if (!token)
        {
            fprintf(stderr, "Did not receive data!\n");
            return;
        }
    }

    //EOF
    else if (strcmp(token, EOF_FILE) == 0)
    {
        fprintf(stderr, "%s File is not available.\n", FAILURE_MESSAGE);
        return;
    }

    //NOK
    else if (strcmp(token, NOT_OK) == 0)
    {
        fprintf(stderr, "%s No content available for this UID.\n", FAILURE_MESSAGE);
        return;
    }

    //INV
    else if (strcmp(token, AS_VALIDATION_ERROR) == 0)
    {
        fprintf(stderr, "%s AS validation error.\n", FAILURE_MESSAGE);
        return;
    }

    //ERR
    else if (strcmp(token, PROTOCOL_ERROR) == 0)
    {
        fprintf(stderr, "%s Request is not correctly formulated.\n", FAILURE_MESSAGE);
        return;
    }
}

//upload action functions
void upload(char *fname, char *fsize, char *data, char *tid, char *buffer, char *uid)
{
    if (parse_retrieve_upload_delete(fname))
    {

        int fs_fd = init_socket_to_fs();

        prepare_upload_request(buffer, uid, tid, fname, fsize, data, fs_fd);

        // sends the login message to FS via tcp connection
        tcp_write(fs_fd, buffer);
        printf("message sent to FS = %s", buffer);

        // receives the FS response message
        memset(buffer, EOS, SIZE);
        tcp_read(fs_fd, buffer, SIZE);
        printf("message received from FS = %s", buffer);

        //treat received message
        treat_rup(buffer);

        close(fs_fd);
    }
}

void prepare_upload_request(char *request, char *uid, char *tid, char *fname,
                            char *fsize, char *data, int fs_fd)
{
    int fsize_value = atoi(fsize);
    int i = 0;
    ssize_t n;

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

    while(i < fsize_value && (n = tcp_read(fs_fd, data, SIZE)) != 0)
    {
        printf("%s", data);
        i+=n;
    }

    strcat(request, "\n");
}

void treat_rup(char *buffer)
{
    char *token = strtok(buffer, " ");

    if (strcmp(token, UPL_RESPONSE) != 0)
    {
        fprintf(stderr, "Did not receive UPL!\n");
        return;
    }
    token = strtok(NULL, " ");

    //OK
    if (strcmp(token, OK))
    {
        printf(SUCCESS_MESSAGE);
        printf("\n");
    }
    //DUP
    else if (strcmp(token, FILE_UNAVAILABLE))
    {
        printf(FAILURE_MESSAGE);
        fprintf(stderr, " File already exists.\n");
    }
    //FULL
    else if (strcmp(token, NOT_OK))
    {
        printf(FAILURE_MESSAGE);
        fprintf(stderr, " FS is full, user already uploaded 15 files.\n");
    }
    //INV
    else if (strcmp(token, AS_VALIDATION_ERROR))
    {
        printf(FAILURE_MESSAGE);
        fprintf(stderr, " Validation error.\n");
    }
    //ERR
    else if (strcmp(token, PROTOCOL_ERROR))
    {
        printf(FAILURE_MESSAGE);
        fprintf(stderr, " Request is not correctly formulated.\n");
    }
}

//delete action functions
void delete (char *fname, char *tid, char *buffer, char *uid)
{
    if (parse_retrieve_upload_delete(fname))
    {
        int fs_fd = init_socket_to_fs();

        prepare_delete_request(buffer, uid, tid, fname);

        // sends the login message to FS via tcp connection
        tcp_write(fs_fd, buffer);
        printf("message sent to FS = %s", buffer);

        // receives the FS response message
        memset(buffer, EOS, SIZE);
        tcp_read(fs_fd, buffer, SIZE);
        printf("message received from FS = %s", buffer);

        //treat received message
        treat_rdl(buffer);

        close(fs_fd);
    }
}

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

void treat_rdl(char *buffer)
{
    char *token = strtok(buffer, " ");

    if (strcmp(token, DEL_RESPONSE) != 0)
    {
        fprintf(stderr, "Did not receive DEL!\n");
        return;
    }
    token = strtok(NULL, " ");

    //OK
    if (strcmp(token, OK))
    {
        printf(SUCCESS_MESSAGE);
        printf("\n");
    }
    //NOK
    else if (strcmp(token, NOT_OK))
    {
        printf(FAILURE_MESSAGE);
        fprintf(stderr, " UID does not exist.\n");
    }
    //INV
    else if (strcmp(token, AS_VALIDATION_ERROR))
    {
        printf(FAILURE_MESSAGE);
        fprintf(stderr, " Validation error.\n");
    }
    //ERR
    else if (strcmp(token, PROTOCOL_ERROR))
    {
        printf(FAILURE_MESSAGE);
        fprintf(stderr, " Request is not correctly formulated.\n");
    }
}

//remove action functions
void rem(char *tid, char *buffer, char *uid, int as_fd)
{
    int fs_fd = init_socket_to_fs();

    prepare_remove_request(buffer, uid, tid);

    // sends the login message to FS via tcp connection
    tcp_write(fs_fd, buffer);
    printf("message sent to FS = %s", buffer);

    // receives the FS response message
    memset(buffer, EOS, SIZE);
    tcp_read(fs_fd, buffer, SIZE);
    printf("message received from FS = %s", buffer);

    //treat received message
    treat_rrm(buffer);

    close(as_fd);
    close(fs_fd);
    exit(EXIT_SUCCESS);
}

void prepare_remove_request(char *request, char *uid, char *tid)
{
    strcpy(request, REMOVE);
    strcat(request, " ");
    strcat(request, uid);
    strcat(request, " ");
    strcat(request, tid);
    strcat(request, "\n");
}

void treat_rrm(char *buffer)
{
    char *token = strtok(buffer, " ");

    if (strcmp(token, REM_RESPONSE) != 0)
    {
        fprintf(stderr, "Did not receive REM!\n");
        return;
    }
    token = strtok(NULL, " ");

    //OK
    if (strcmp(token, OK))
    {
        printf(SUCCESS_MESSAGE);
        printf("\n");
    }
    //NOK
    else if (strcmp(token, NOT_OK))
    {
        printf(FAILURE_MESSAGE);
        fprintf(stderr, " UID does not exist.\n");
    }
    //INV
    else if (strcmp(token, AS_VALIDATION_ERROR))
    {
        printf(FAILURE_MESSAGE);
        fprintf(stderr, " Validation error.\n");
    }
    //ERR
    else if (strcmp(token, PROTOCOL_ERROR))
    {
        printf(FAILURE_MESSAGE);
        fprintf(stderr, " Request is not correctly formulated.\n");
    }
}

//exit action functions
void ex(int as_fd)
{
    close(as_fd);
    exit(EXIT_SUCCESS);
}

//general functions
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

//Initializes TCP connection to FS
int init_socket_to_fs()
{
    struct addrinfo hints_fs, *res_fs;
    int errcode_fs;
    ssize_t m;

    //connection to FS
    int fs_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fs_fd == ERROR) {
        printf("Error: could not create\n");
        exit(EXIT_FAILURE);
    }

    memset(&hints_fs, 0, sizeof hints_fs);
    hints_fs.ai_family = AF_INET;
    hints_fs.ai_socktype = SOCK_STREAM;

    errcode_fs = getaddrinfo(fsip, fsport, &hints_fs, &res_fs);
    if (errcode_fs != 0)
    {
        fprintf(stderr, "Error: could not get address info\n");
        exit(EXIT_FAILURE);
    }

    m = connect(fs_fd, res_fs->ai_addr, res_fs->ai_addrlen);
    if (m == ERROR)
    {
        fprintf(stderr, "Error: could not connect\n");
        exit(EXIT_FAILURE);
    }
    return fs_fd;
}

//RID generator
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
