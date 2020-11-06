#include "user.h"

char *asip, *asport, *fsip, *fsport;
char login_success[SIZE];
char req_success[SIZE]

int main(int argc, char const *argv[]) {
    int as_fd, fs_fd, errcode;
    ssize_t n, m;
    socklen_t addrlen;
    struct addrinfo hints_as, *res_as, hints_fs, *res_fs;
    struct sockaddr_in addr;
    char buffer[SIZE];

    // checks if the number of arguments is correct
    if (wrong_arguments(argc)) {
        usage();
        exit(EXIT_FAILURE);
    }

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
    if (errcode != 0) {
        //error
        fprintf(stderr, "Error: could not get address info\n");
        exit(EXIT_FAILURE);
    }
    //TCP socket
    //IPv4
    //TCP socket
    n = connect(as_fd, res_as->ai_addr, res_as->ai_addrlen);
    if (n == ERROR) {
        //error
        fprintf(stderr, "Error: could not connect\n");
        exit(EXIT_FAILURE);
    }


    //connection to FS
    fs_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fs_fd == ERROR)
        exit(EXIT_FAILURE); //error

    memset(&hints_fs, 0, sizeof hints_fs);
    hints_fs.ai_family = AF_INET;
    hints_fs.ai_socktype = SOCK_STREAM;

    errcode = getaddrinfo(fsip, fsport, &hints_fs, &res_fs);
    if (errcode != 0) {
        //error
        fprintf(stderr, "Error: could not get address info\n");
        exit(EXIT_FAILURE);
    }
    //TCP socket
    //IPv4
    //TCP socket
    m = connect(fs_fd, res_fs->ai_addr, res_fs->ai_addrlen);
    if (m == ERROR) {
        //error
        fprintf(stderr, "Error: could not connect\n");
        exit(EXIT_FAILURE);
    }

    char command[SIZE], uid[SIZE], password[SIZE], fop[SIZE], fname[SIZE], filename[SIZE],
        vc[SIZE];
    memset(buffer, EOS, SIZE);
    memset(command, EOS, SIZE);
    memset(uid, EOS, SIZE);
    memset(password, EOS, SIZE);
    memset(fop, EOS, SIZE);
    memset(fname, EOS, SIZE);
    memset(filename, EOS, SIZE);
    memset(vc, EOS, SIZE);
    
    // writes the "registration success" message
    memset(login_success, EOS, SIZE);
    strcpy(login_success, LOG_RESPONSE);
    strcat(login_success, " ");
    strcat(login_success, OK);
    strcat(login_success, "\n");

    do {
        // reads the stdin and checks for login command
        read_stdin(buffer);
        if (!parse_login_message(buffer, command, uid, password)) {
            continue;
        }

        // if there is a login command prepares the login message to be sent
        memset(buffer, EOS, SIZE);
        if (!prepare_login_request(buffer, command, uid, password)) {
            continue;
        }

        printf("request: %s\n", buffer);
        
        // sends the login message to AS via tcp connection
        n = tcp_write(as_fd, buffer);
        
        // receives the AS response message
        memset(buffer, EOS, SIZE);
        n = tcp_read(as_fd, buffer, SIZE);

        // checks if the response is OK. If so the loop ends
    } while(!verify_login_response(buffer, n));

    while(1){
        read_stdin(buffer);
        command = strtok(buffer, " ");

        if (strcmp(command, "exit") == 0){
            break;
        }
        if (strcmp(command, "req") == 0){
            parse_req(buffer, command, fop, fname);
        }
        if (strcmp(command, "val") == 0){
            parse_val(buffer, command, vc);
        }
        if (strcmp(command, "list") == 0 || strcmp(command, "l") == 0){
            parse_list(buffer, command);
        }
        if (strcmp(command, "retrieve") == 0 || strcmp(command, "r") == 0){
            parse_retrieve(buffer, command, filename);
        }
        if(strcmp(command, "upload") == 0 || strcmp(command, "u") == 0){
            parse_upload(buffer, command, filename);
        }
        if(strcmp(command, "delete") == 0 || strcmp(command, "d") == 0){
            parse_delete(buffer, command, filename);
        }
        if(strcmp(command, "remove") == 0 || strcmp(command, "x") == 0){
            parse_remove(buffer, command);
        }

    }

   
    freeaddrinfo(res_fs);
    close(as_fd);
    //close(fs_fd);

    exit(EXIT_SUCCESS);
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

/*PARSERS*/

/*parse login*/
Boolean parse_login_message(char* buffer, char* command, char* uid, char* password) {
    char *token = strtok(buffer, " ");

    if(!token) {
        fprintf(stderr, "Command missing!\nMust give a command\n");
        return false;
    }
    else if(strcmp(token, "login")!=0){
        fprintf("You did not login.\nDid you mean to use command 'login'?\n");
        return false;
    }
    strcpy(command, token);

    token = strtok(NULL, " ");
    if (!token) {
        fprintf(stderr, "UID missing!\nMust give a UID\n");
        return false;
    }
    strcpy(uid, token);

    token = strtok(NULL, " ");
    if (!token) {
        fprintf(stderr, "Password missing!\nMust give a password\n");
        return false;
    }
    strcpy(password, token);

    return true;
}

/*parse req*/
Boolean parse_req(char* buffer, char* command, char* fop, char* fname){
    char *token;

    if(!(token = strtok(buffer, " "))) {
        fprintf(stderr, "Command missing!\nMust give a command\n");
        return false;
    }
    strcpy(command, token);

    token = strtok(NULL, " ");
    if (!token) {
        fprintf(stderr, "Fop missing!\nMust give a Fop\n");
        return false;
    }
    strcpy(fop, token);

    token = strtok(NULL, " ");
    if (!token) {
        fprintf(stderr, "Fname not given\nIt is not necessary\n");
    }
    else{
        strcpy(fname, token);
    }
    
    return true;
}

/*parse val*/
Boolean parse_val(char* buffer, char* command, char* vc){
    char *token;

    if(!(token = strtok(buffer, " "))) {
        fprintf(stderr, "Command missing!\nMust give a command\n");
        return false;
    }
    strcpy(command, token);

    token = strtok(NULL, " ");
    if (!token) {
        fprintf(stderr, "VC missing!\nMust give a VC\n");
        return false;
    }
    strcpy(vc, token);

    return true;
}

/*parse list*/
Boolean parse_list(char* buffer, char* command){
    char *token;

    if(!(token = strtok(buffer, " "))) {
        fprintf(stderr, "Command missing!\nMust give a command\n");
        return false;
    }
    strcpy(command, token);

    return true;
}

/*parse retrieve*/
Boolean parse_retrieve(char* buffer, char* command, char* filename){
    char *token;

    if(!(token = strtok(buffer, " "))) {
        fprintf(stderr, "Command missing!\nMust give a command\n");
        return false;
    }
    strcpy(command, token);

    return true;
}

/*parse upload*/
Boolean parse_upload(char* buffer, char* command, char* filename){
    char *token;

    if(!(token = strtok(buffer, " "))) {
        fprintf(stderr, "Command missing!\nMust give a command\n");
        return false;
    }
    strcpy(command, token);

    return true;
}

/*parse delete*/
Boolean parse_delete(char* buffer, char* command, char* filename){
    char *token;

    if(!(token = strtok(buffer, " "))) {
        fprintf(stderr, "Command missing!\nMust give a command\n");
        return false;
    }
    strcpy(command, token);

    return true;
}

/*parse remove*/
Boolean parse_remove(char* buffer, char* command){
    char *token;

    if(!(token = strtok(buffer, " "))) {
        fprintf(stderr, "Command missing!\nMust give a command\n");
        return false;
    }

    return true;
}

/*login*/
Boolean prepare_login_request(char* request, char* command, char* uid, char* password) {

    if (strcmp(command, USER_LOGIN)) {
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

Boolean verify_login_response(char* buffer, int size) {
    printf("response: %s\n", buffer);
    if (!size) {
        printf("%s\n", SERVER_DOWN_MESSAGE);
        return false;
    }

    if (!strcmp(buffer, login_success)) {
        printf("%s\n", SUCCESS_MESSAGE);
        return true;
    }

    printf("%s\n", FAILURE_MESSAGE);
    //printf("response: %s\n", buffer);
    return false;
}

void verify_command_response(char* buffer, int size) {
    printf("response: %s\n", buffer);
    if (!size) {
        printf("%s\n", SERVER_DOWN_MESSAGE);
    }

    if (!strcmp(buffer, login_success)) {
        printf("%s\n", SUCCESS_MESSAGE);
    }

    printf("%s\n", FAILURE_MESSAGE);
    //printf("response: %s\n", buffer);
}
