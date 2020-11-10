#include "pd.h"

// the buffers where
// PDIP, PDport, ASIP, ASport are stored
char *pdip, *pdport, *asip, *asport;
char registration_success[SIZE];

int main(int argc, char const *argv[]) {
    int fd, errcode, listenfd;
    fd_set inputs, testfds;
    int out_fds;

    ssize_t n;
    struct addrinfo hints,*client, *server;
    struct sockaddr_in addr;
    struct timeval timeout;
    char buffer[SIZE];
    
    // checks if the number of arguments is correct
    if (wrong_arguments(argc)) {
        usage();
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, handler_sigint); 

    // parses the argv arguments
    parse_arguments(argv, argc);

    printf("PD is running on IP=%s Port=%s\n", pdip, pdport);
    printf("AS is running on IP=%s Port=%s\n", asip, asport);
    
    // sets the socket
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == ERROR) {
        //error
        fprintf(stderr, "Error: socket returned null\n");
        exit(EXIT_FAILURE);
    }
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    
    // gets the address info
    errcode = getaddrinfo(asip, asport, &hints, &client);
    if (errcode != 0) {
        //error
        fprintf(stderr, "Error: getaddrinfo returned %d error code\n", errcode);
        exit(EXIT_FAILURE);
    }

    char command[SIZE], uid[SIZE], password[SIZE];
    memset(buffer, EOS, SIZE);
    memset(command, EOS, SIZE);
    memset(uid, EOS, SIZE);
    memset(password, EOS, SIZE);
    memset(registration_success, EOS, SIZE);
    
    // writes the "registration success" message
    strcpy(registration_success, REG_RESPONSE);
    strcat(registration_success, " ");
    strcat(registration_success, OK);
    strcat(registration_success, "\n");

    do {
        read_stdin(buffer);
        if (!parse_register_message(buffer, command, uid, password)) {
            continue;
        }

        memset(buffer, EOS, SIZE);
        if (!prepare_register_request(buffer, command, uid, password)) {
            continue;
        }

        printf("request: %s", buffer);

        // sends REG command
        n = udp_write(fd, buffer, client -> ai_addr, client -> ai_addrlen);

        memset(buffer, EOS, SIZE);
        n = udp_read(fd, buffer, SIZE, (struct sockaddr*) &addr);

    } while(!verify_register_response(buffer, n));

    char unregistration_success[SIZE];

    memset(unregistration_success, EOS, SIZE);
    // writes the "unregistration success" message
    strcat(unregistration_success, UNR_RESPONSE);
    strcat(unregistration_success, " ");
    strcat(unregistration_success, OK);
    strcat(unregistration_success, "\n");

    // the socket where the AS will send info
    listenfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (listenfd == ERROR) {
        //error
        fprintf(stderr, "Error: socket returned null\n");
        exit(EXIT_FAILURE);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_DGRAM; // UDP socket
    hints.ai_flags = AI_PASSIVE;

    errcode = getaddrinfo(NULL, pdport, &hints, &server);

    if (errcode != 0) {
        /*error*/ 
        fprintf(stderr, "Error: getaddrinfo returned %d error code\n", errcode);
        exit(EXIT_FAILURE);
    }

    n = bind(listenfd, server -> ai_addr, server -> ai_addrlen);

    if (n == ERROR) {
        /*error*/
        fprintf(stderr, "Error: bind returned %ld error code\n", n);
        exit(EXIT_FAILURE);
    }

    FD_ZERO(&inputs);
    FD_SET(STDIN, &inputs);
    FD_SET(listenfd, &inputs);

    do {
        testfds = inputs;
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;

        out_fds = select(FD_SETSIZE, &testfds, (fd_set*) NULL,(fd_set*) NULL, &timeout);

        /*
        printf("timeout time: %ld and %ld\n", timeout.tv_sec, timeout.tv_usec);
        printf("counter = %d\n", out_fds);
        */
        
        switch (out_fds) {
            case 0:
                break;
            
            case ERROR:
                /*error*/
                fprintf(stderr, "Error: select returned %d error code\n", out_fds);
                exit(EXIT_FAILURE);
                break;
                
            default:
                if (FD_ISSET(listenfd, &testfds)) {
                    memset(buffer, EOS, SIZE);

                    n = udp_read(listenfd, buffer, SIZE, (struct sockaddr*) &addr);

                    write(STDOUT, "response from AS: ", 19);
                    write(STDOUT, buffer, n);

                    if (parse_validation_code(buffer)) {
                        memset(buffer, EOS, SIZE);
                        strcpy(buffer, VAL_USER_RESPONSE);
                        strcat(buffer, " ");
                        strcat(buffer, uid);
                        strcat(buffer, " ");
                        strcat(buffer, OK);
                        strcat(buffer, "\n");


                        printf("message sent: %s\n", buffer);
                    } else {
                        memset(buffer, EOS, SIZE);
                        strcpy(buffer, VAL_USER_RESPONSE);
                        strcat(buffer, " ");
                        strcat(buffer, uid);
                        strcat(buffer, " ");
                        strcat(buffer, NOT_OK);
                        strcat(buffer, "\n");
                    }
                    n = udp_write(listenfd, buffer, (struct sockaddr*) &addr, sizeof(addr));
                }

                if (FD_ISSET(STDIN, &testfds)) {
                    memset(buffer, EOS, SIZE);
                    read_stdin(buffer);

                    parse_exit_message(buffer, command); 
                    memset(buffer, EOS, SIZE);
                    prepare_register_request(buffer, command, uid, password);

                    printf("message sent: %s", buffer);

                    n = udp_write(fd, buffer, client -> ai_addr, client -> ai_addrlen);

                    memset(buffer, EOS, SIZE);
                    n = udp_read(fd, buffer, SIZE, (struct sockaddr*) &addr);

                    write(STDOUT, "response: ", 10);
                    write(STDOUT, buffer, n);
                }
                break;
        }
    } while (strcmp(buffer, unregistration_success));

    freeaddrinfo(client);
    freeaddrinfo(server);

    close(fd);

    free(pdip);
    free(pdport);
    free(asip);
    free(asport);

    exit(EXIT_SUCCESS);
}

// returns true if the arguments given on the command line are on an invalid format, and false otherwise
int wrong_arguments(int argc) {
    return !(argc > 0 && argc%2 == 0 && argc <= 8);
}

// diplays a message with the correct usage of the file
void usage() {
    printf("usage: ./pd PDIP [-d PDport] [-n ASIP] [-p ASport]\n");
    printf("example: ./pd 10.0.2.15 -d 57000 -n 193.136.138.142 -p 58011\n");
}

// parses the register command
Boolean parse_register_message(char* buffer, char* command, char* uid, char* password) {
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

// parses the exit command 
void parse_exit_message(char* buffer, char* command) {
    char *token;

    if(!(token = strtok(buffer, " "))) {
        fprintf(stderr, "Command missing!\nMust give a command\n");
        exit(EXIT_FAILURE);
    }
    strcpy(command, token);

    printf("command: %s\t\n", command);
    printf("buffer: %s\n", buffer);
}

Boolean parse_validation_code(char* buffer) {
    char *token;
    char vc[VC_SIZE], fop[FOP_SIZE], fop_long_name[SIZE], filename[SIZE], aux[SIZE];

    memset(vc, EOS, VC_SIZE);
    memset(fop, EOS, FOP_SIZE);
    memset(fop_long_name, EOS, SIZE);
    memset(filename, EOS, SIZE);
    memset(aux, EOS, SIZE);

    // Validation Code instruction
    if(!(token = strtok(buffer, " "))) {
        fprintf(stderr, "Command missing!\nMust give a command\n");
        return false;
    }

    if (strcmp(token, VALIDATE_USER)) {
        fprintf(stderr, "Error: %s is not a valid instruction\n", token);
        return false;
    }

    // UID
    if(!(token = strtok(NULL, " "))) {
        fprintf(stderr, "Error: invalid UID\n");
        return false;
    }


    // Validation Code
    if(!(token = strtok(NULL, " "))) {
        fprintf(stderr, "Error: invalid VC\n");
        return false;
    }

    strcpy(vc, token);

    // Rest of the message
    if(!(token = strtok(NULL, "\n"))) {
        fprintf(stderr, "Error: invalid Fop\n");
        return false;
    }

    strcpy(aux, token);
    
    // Fop
    if(!(token = strtok(aux, " "))) {
        fprintf(stderr, "Error: invalid Fop\n");
        return false;
    }

    strcpy(fop, token);

    if (!get_fop_from_fop_code(fop, fop_long_name)) {
        return false;
    }

    // if the fop needs a filename and none is provided
    if(!(token = strtok(NULL, "\0")) && fop_has_file(fop)) {
        fprintf(stderr, "Error: Fop %s needs a file\n", fop);
        return false;
    }

    if (token) {
        strcpy(filename, token);
    }

    printf("VC=%s, %s: %s\n", vc, fop_long_name, filename);

    // VLC 90531 6785 U f1.txt
    return true;
}

Boolean get_fop_from_fop_code(char* fop, char* fop_long_name) {
    if (!strcmp(fop, FOP_DELETE)) {
        strcpy(fop_long_name, USER_DELETE);
    } 
    
    else if (!strcmp(fop, FOP_LIST)) {
        strcpy(fop_long_name, USER_LIST);
    }

    else if (!strcmp(fop, FOP_REMOVE)) {
        strcpy(fop_long_name, USER_REMOVE);
    }

    else if (!strcmp(fop, FOP_RETRIEVE)) {
        strcpy(fop_long_name, USER_RETRIEVE);
    }

    else if (!strcmp(fop, FOP_UPLOAD)) {
        strcpy(fop_long_name, USER_UPLOAD);
    }
    
    else {
        fprintf(stderr, "Error: Invalid Fop\n");
        return false;
    }
    return true;
}

Boolean fop_has_file(char* fop) {
    return !(strcmp(fop, FOP_UPLOAD) && 
            strcmp(fop, FOP_RETRIEVE) && 
            strcmp(fop, FOP_DELETE));
}

Boolean prepare_register_request(char* request, char* command, char* uid, char* password) {

    char aux[SIZE];
    
    strcpy(aux, " ");
    strcat(aux, uid);
    strcat(aux, " ");
    strcat(aux, password);
    
    if (!strcmp(command, PD_REGISTRATION)) {
        strcpy(request, REGISTRATION);
        strcat(request, aux);

        // puts PDIP and PDport at the end of register request 
        strcat(request, " ");
        strcat(request, pdip);
        strcat(request, " ");
        strcat(request, pdport);
    }
    else if (!strcmp(command, PD_EXIT)) {
        strcpy(request, UNREGISTRATION);
        strcat(request, aux);
    }
    else {
        fprintf(stderr, "Error: \"%s\" is an invalid command\n", command);
        return false;
    }
    
    strcat(request, "\n");
    return true;
}

Boolean verify_register_response(char* buffer, int size) {
    printf("response: %s\n", buffer);
    if (!size) {
        printf("%s\n", SERVER_DOWN_MESSAGE);
        return false;
    }

    if (!strcmp(buffer, registration_success)) {
        printf("%s\n", LOGIN_SUCCESS_MESSAGE);
        return true;
    }

    printf("%s\n", LOGIN_FAILURE_MESSAGE);
    return false;
}

// parses the arguments given on the command line
void parse_arguments(const char* argv[], int size) {
    parse_pd_port(argv, size, &pdport);
    parse_as_ip(argv, size, pdip, &asip);
    parse_as_port(argv, size, &asport);
}
