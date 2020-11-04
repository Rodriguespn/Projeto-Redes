#include "user.h"

/*TODO: encontrar userIP*/
char *asip, *asport, *fsip, *fsport;
char login_success[SIZE];

int main(int argc, char const *argv[]) {
    int as_fd, fs_fd, errcode;
    ssize_t n;
    socklen_t addrlen;
    struct addrinfo hints, *res;
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

    as_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (as_fd == ERROR)
        exit(EXIT_FAILURE); //error

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    errcode = getaddrinfo(asip, asport, &hints, &res);
    if (errcode != 0) {
        //error
        fprintf(stderr, "Error: could not get address info\n");
        exit(EXIT_FAILURE);
    }

    //TCP socket
    //IPv4
    //TCP socket

    n = connect(as_fd, res->ai_addr, res->ai_addrlen);
    if (n == ERROR) {
        //error
        fprintf(stderr, "Error: could not connect\n");
        exit(EXIT_FAILURE);
    }

    char command[SIZE], uid[SIZE], password[SIZE];
    memset(buffer, EOS, SIZE);
    memset(command, EOS, SIZE);
    memset(uid, EOS, SIZE);
    memset(password, EOS, SIZE);
    memset(login_success, EOS, SIZE);
    
    // writes the "registration success" message
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

        

    /*do {
        memset(buffer, EOS, SIZE);
        strcpy(buffer, "REQ 90531 1234 U f1.txt\n");

        n = tcp_write(fd, buffer);

        write(STDOUT, "request: ", 9);
        write(STDOUT, buffer, n);
        
        memset(buffer, EOS, SIZE);
        n = tcp_read(fd, buffer, SIZE);

        write(STDOUT, "response: ", 10);
        write(STDOUT, buffer, n);

        n = tcp_write(fd, "LOG 90531 password\n");

        memset(buffer, EOS, SIZE);

        n = tcp_read(fd, buffer, SIZE);

        write(STDOUT, "response: ", 10);
        write(STDOUT, buffer, n);

        memset(buffer, EOS, SIZE);
        strcpy(buffer, "REQ 90531 1234 U f1.txt\n");

        n = tcp_write(fd, buffer);

        write(STDOUT, "request: ", 9);
        write(STDOUT, buffer, n);
        
        memset(buffer, EOS, SIZE);
        n = tcp_read(fd, buffer, SIZE);

        write(STDOUT, "response: ", 10);
        write(STDOUT, buffer, n);

        char request_succeeded[SIZE];
        memset(request_succeeded, EOS, SIZE);
        
        strcpy(request_succeeded, REQ_RESPONSE);
        strcat(request_succeeded, " ");
        strcat(request_succeeded, OK);
        strcat(request_succeeded, "\n");

        if (!strcmp(request_succeeded, buffer)) {
            memset(buffer, EOS, SIZE);
            read_stdin(buffer); // "AUT 90531 1234 VC\n");

            strcat(buffer, "\n");

            n = tcp_write(fd, buffer);

            write(STDOUT, "request: ", 9);
            write(STDOUT, buffer, n);
            
            memset(buffer, EOS, SIZE);
            n = tcp_read(fd, buffer, SIZE);

            write(STDOUT, "response: ", 10);
            write(STDOUT, buffer, n);
        }

    } while (false); //strcmp(buffer, unregistration_success));
    */
   
    freeaddrinfo(res);
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

Boolean parse_login_message(char* buffer, char* command, char* uid, char* password) {
    char *token;

    if(!(token = strtok(buffer, " "))) {
        fprintf(stderr, "Command missing!\nMust give a command\n");
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
        printf("%s\n", LOGIN_SUCCESS_MESSAGE);
        return true;
    }

    printf("%s\n", LOGIN_FAILURE_MESSAGE);
    //printf("response: %s\n", buffer);
    return false;
}
