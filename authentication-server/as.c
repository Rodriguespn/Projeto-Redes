#include "as.h"

// the buffer where ASport is stored
char *asport;
Boolean verbose = false;
const char *users_directory = USERS_FOLDER_NAME;
FILE *userfd; 
struct stat st = {0};
int udpsocket, tcpsocket, connectfd;

int main(int argc, char const *argv[]) {
    int out_fds, childpid, errcode;
    fd_set inputs, testfds;
    struct timeval timeout;
    ssize_t n;
    socklen_t addrlen;
    struct addrinfo hints, *res;
    struct sockaddr_in cliaddr;
    char buffer[SIZE];
    void (*old_handler) (int);
    
    // checks if the number of arguments is correct
    if (wrong_arguments(argc)) {
        usage();
        exit(EXIT_FAILURE);
    }

    // treats the SIGINT signal
    signal(SIGINT, handler_sigint);

    // Ignores SIGCHLD signals
    if((old_handler = signal(SIGCHLD, SIG_IGN)) == SIG_ERR) {
        fprintf(stderr, "could not set handler to %d signal\n", SIGCHLD);
        exit(EXIT_FAILURE);
    }

    // parses the argv arguments
    parse_arguments(argv, argc);

    // Initial prints
    char host[256];
    char *asip;
    struct hostent *host_entry;
    gethostname(host, sizeof(host)); //find the host name
    host_entry = gethostbyname(host); //find host information
    asip = inet_ntoa(*((struct in_addr*) host_entry->h_addr_list[0])); //Convert into IP string
    printf("CONFIG: Verbose flag %s\n", verbose ? "true" : "false");
    
    verbose_message(verbose, "CONFIG: AS is running on Host=%s IP=%s Port=%s\n", host, asip, asport);

    // create and bind the UDP Socket
    udpsocket = socket(AF_INET, SOCK_DGRAM, 0);

    if(udpsocket == ERROR) {
        // error
        fprintf(stderr, "ERROR: it was not possible to create udp socket\n");
        exit(EXIT_FAILURE);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_DGRAM; // UDP socket
    hints.ai_flags = AI_PASSIVE;

    errcode = getaddrinfo(NULL, asport, &hints, &res);

    if (errcode != 0) {
        // error
        fprintf(stderr, "ERROR: udp socket getaddrinfo returned %d error code\n", errcode);
        exit(EXIT_FAILURE);
    }

    n = bind(udpsocket, res -> ai_addr, res -> ai_addrlen);
    if (n == ERROR)  {
        // error
        fprintf(stderr, "ERROR: udp socket bind returned %ld error code\n", n);
        exit(EXIT_FAILURE);
    }

    // create and bind the TCP Socket
    tcpsocket = socket(AF_INET, SOCK_STREAM, 0);

    if (tcpsocket == ERROR) {
        //error
        fprintf(stderr, "ERROR: it was not possible to create tcp socket\n");
        exit(EXIT_FAILURE);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    
    //TCP socket
    //IPv4
    //TCP socket
    errcode = getaddrinfo(NULL, asport, &hints, &res);
    if (errcode != 0) {
        // error
        fprintf(stderr, "ERROR: tcp socket getaddrinfo returned %d error code\n", errcode);
        exit(EXIT_FAILURE); 
    }

    n = bind(tcpsocket, res -> ai_addr, res -> ai_addrlen);
    if (n == ERROR) {
        fprintf(stderr, "ERROR: tcp socket bind returned %ld error code\n", n);
        // error 
        exit(EXIT_FAILURE);
    } 
        
    if (listen(tcpsocket, 5) == ERROR) {
        // error
        fprintf(stderr, "ERROR: tcp socket listen returned %d error code\n", ERROR);
        exit(EXIT_FAILURE);
    }

    // creates the directory where the users' information will be stored
    if (stat(users_directory, &st) == -1) { // if directory doesn t exists
        // check if directory is created or not 
        if (mkdir(users_directory, 0777)) { 
            fprintf(stderr, "ERROR: Unable to create directory \"%s\"\n", users_directory); 
            exit(EXIT_FAILURE); 
        }
    }

    char command[SIZE], uid[UID_SIZE], password[PASSWORD_SIZE], pdip[SIZE], pdport[SIZE];
    memset(command, EOS, SIZE);
    memset(uid, EOS, UID_SIZE);
    memset(password, EOS, PASSWORD_SIZE);
    memset(pdip, EOS, SIZE);
    memset(pdport, EOS, SIZE);

    // prepare the sockets which are going to the select function
    FD_ZERO(&inputs);
    FD_SET(udpsocket, &inputs);
    FD_SET(tcpsocket, &inputs);

    while (true) {
        testfds = inputs;
        timeout.tv_sec = SELECT_TIMEOUT_SECS;
        timeout.tv_usec = SELECT_TIMEOUT_USECS;

        out_fds = select(FD_SETSIZE, &testfds, (fd_set*) NULL,(fd_set*) NULL, &timeout);

        switch (out_fds) {
        case TIMEOUT:
            break;
        
        case ERROR:
            // error
            fprintf(stderr, "ERROR: select returned %d error code\n", ERROR);
            exit(EXIT_FAILURE);
            break;

        default:
            //  if udp socket is ready to listen
            if (FD_ISSET(udpsocket, &testfds)) {
                memset(buffer, EOS, SIZE);
                addrlen = sizeof(cliaddr);
                n = udp_read(udpsocket, buffer, SIZE, (struct sockaddr*) &cliaddr);
                verbose_message(verbose, "INFORM: Message received: %s\n", buffer);

                char client_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(((struct sockaddr_in *) &cliaddr) -> sin_addr), client_ip, INET_ADDRSTRLEN);
                verbose_message(verbose, "\nINFORM: Received UDP connection from IP=%s Port=%u\n", client_ip, ntohs((&cliaddr) -> sin_port));

                char tid[TID_SIZE];
                memset(tid, EOS, TID_SIZE); 

                if (parse_command(buffer, command)) {
                    if (!strcmp(command, REGISTRATION)) {
                        process_registration_request(buffer, uid, password, pdip, pdport);
                        verbose_message(verbose, "INFORM: Processed Command=%s UID=%s password=%s registration\n", command, uid, password);
                    } else if (!strcmp(command, UNREGISTRATION)) {
                        process_unregistration_request(buffer, uid, password);
                        verbose_message(verbose, "INFORM: Processed Command=%s UID=%s password=%s unregistration\n", command, uid, password);
                    } else if (!strcmp(command, VALIDATE_FILE)) {
                        process_fs_validation_request(buffer, uid, tid);
                        verbose_message(verbose, "INFORM: Processed Command=%s UID=%s TID=%s validation\n", command, uid, tid);
                    } else {
                        prepare_error_message(buffer);
                        verbose_message(verbose, "INFORM: Request=%s could not be processed\n", buffer);
                    } 
                } else {
                    prepare_error_message(buffer);
                    verbose_message(verbose, "ERROR: Request=%s with wrong format\n", buffer);
                }

                n = udp_write(udpsocket, buffer, (struct sockaddr*) &cliaddr, sizeof(cliaddr));
                verbose_message(verbose, "INFORM: Message sent: %s\n", buffer);
            }
            break;
        }

        //  if tcp socket is ready to listen
        if (FD_ISSET(tcpsocket, &testfds)) {
            connectfd = accept(tcpsocket, (struct sockaddr*) &cliaddr, &addrlen);
            addrlen = sizeof(cliaddr);
            char rid[TID_SIZE], fop[FOP_SIZE], *vc = NULL;

            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(((struct sockaddr_in *) &cliaddr) -> sin_addr), client_ip, INET_ADDRSTRLEN);
            verbose_message(verbose, "\nINFORM: Received TCP connection from IP=%s Port=%u\n", client_ip, ntohs((&cliaddr) -> sin_port));    

            memset(rid, EOS, TID_SIZE);
            memset(fop, EOS, FOP_SIZE);
            
            if ((childpid = fork()) == 0) {
                close(tcpsocket);
                char login_succeeded[SIZE];
                strcpy(login_succeeded, LOG_RESPONSE);
                strcat(login_succeeded, " ");
                strcat(login_succeeded, OK);
                strcat(login_succeeded, "\n");

                do { // user has to login before anything else
                    memset(buffer, EOS, SIZE);
                    n = tcp_read(connectfd, buffer, SIZE);
                    verbose_message(verbose, "INFORM: Message received: %s\n", buffer);

                    if (!n) { // the client has disconnected
                        continue;
                    }

                    if (parse_command(buffer, command)) {
                        if (!strcmp(command, LOGIN)) {
                            process_login_request(buffer, uid, password);
                            verbose_message(verbose, "INFORM: Processed Command=%s UID=%s password=%s login\n", command, uid, password);
                        } else if (!strcmp(command, REQUEST)) {
                            prepare_not_logged_in_message(buffer);
                            verbose_message(verbose, "INFORM: Request=%s could not be processed without login\n", buffer);
                        }
                        else {
                            prepare_error_message(buffer);
                            verbose_message(verbose, "INFORM: Request=%s is invalid", buffer);
                        } 
                    } else {
                        prepare_error_message(buffer);
                    }

                    n = tcp_write(connectfd, buffer);
                    verbose_message(verbose, "INFORM: Message sent: %s\n", buffer);
                } while (n && strcmp(buffer, login_succeeded)); // while the socket is connected and login not succeeded

                do { // after logged in, the user can make requests and authorize them
                    char operation[SIZE];
                    char request_succeeded[SIZE];
                    strcpy(request_succeeded, REQ_RESPONSE);
                    strcat(request_succeeded, " ");
                    strcat(request_succeeded, OK);
                    strcat(request_succeeded, "\n");

                    do { // until the socket disconnects
                        memset(buffer, EOS, SIZE);
                        n = tcp_read(connectfd, buffer, SIZE);
                        verbose_message(verbose, "INFORM: Message received: %s\n", buffer);
                        if (!n) { // the socket has disconnected
                            continue;
                        }
                        
                        if (parse_command(buffer, command)) {
                            if (!strcmp(command, LOGIN)) {
                                verbose_message(verbose, "INFORM: Processed Command=%s UID=%s password=%s login\n", command, uid, password);
                                process_login_request(buffer, uid, password);
                            } 
                            else if (!strcmp(command, REQUEST)) {
                                REQUEST_OP:
                                process_request_request(buffer, uid, rid, fop, &vc, operation);
                                verbose_message(verbose, "INFORM: Processed Command=%s UID=%s RID=%s Fop=%s VC=%s request\n", command, uid, rid, fop, vc);
                            } 
                            else {
                                prepare_error_message(buffer);
                                verbose_message(verbose, "INFORM: Request=%s is invalid", buffer);
                            } 
                        } else {
                            prepare_error_message(buffer);
                        }
                        
                        n = tcp_write(connectfd, buffer);
                        verbose_message(verbose, "INFORM: Message sent: %s\n", buffer);

                    } while (n && strcmp(buffer, request_succeeded)); // while the socket is connected and login not succeeded

                    if (!n) { // the socket has disconnected
                        continue;
                    }
                    char auth_failed[SIZE];
                    strcpy(auth_failed, AUT_RESPONSE);
                    strcat(auth_failed, " ");
                    strcat(auth_failed, NOT_OK);
                    strcat(auth_failed, "\n");

                    char error_message[SIZE];
                    prepare_error_message(error_message);

                    do { // user has to login before anything else
                        memset(buffer, EOS, SIZE);
                        n = tcp_read(connectfd, buffer, SIZE);
                        verbose_message(verbose, "INFORM: Message received: %s\n", buffer);

                        if (!n) { // the client has disconnected
                            continue;
                        }

                        if (parse_command(buffer, command)) {
                            if (!strcmp(command, AUTHENTICATION)) {
                                process_authentication_request(buffer, uid, rid, vc, operation);
                                verbose_message(verbose, "INFORM: Processed Command=%s UID=%s, RID=%s, VC=%s authentication\n", command, uid, rid, vc);
                                free(vc);
                            } else if (!strcmp(command, REQUEST)) {
                                goto REQUEST_OP;
                            } else {
                                prepare_error_message(buffer);
                                verbose_message(verbose, "INFORM: Request=%s is invalid", buffer);
                            } 
                        } else {
                            prepare_error_message(buffer);
                        }

                        n = tcp_write(connectfd, buffer);
                        verbose_message(verbose, "INFORM: Message sent: %s\n", buffer);
                    } while (n && (!strcmp(buffer, error_message) || !strcmp(buffer, auth_failed))); // while the socket is connected and login not succeeded

                } while (n);

                verbose_message(verbose, "INFORM: Disconnected TCP connection from IP=%s Port=%u\n", client_ip, ntohs((&cliaddr) -> sin_port));    
                close(connectfd);
                remove_file(uid, LOGIN_FILE_PREFIX, FILE_EXTENSION);
                exit(EXIT_SUCCESS);

            } else if (childpid == ERROR) {
                fprintf(stderr, "ERROR: could not create child process for tcp connection");
                exit(EXIT_FAILURE);
            }
            close(connectfd);
        }
    }

    freeaddrinfo(res);
    close (udpsocket);

    exit(EXIT_SUCCESS);
}

// Handler for SIGINT, caused by 
// Ctrl-C at keyboard 
void handler_sigint() { 
    close(udpsocket);
    close(tcpsocket);
    close(connectfd);
    printf("\nGoodbye...\n");
    exit(EXIT_SUCCESS);
}

// diplays a message with the correct usage of the file
void usage() {
    printf("usage: ./as [-p ASport] [-v]\n");
    printf("example: ./as -p 58011 -v\n");
}

// returns true if the arguments given on the command line are on an invalid format, and false otherwise
int wrong_arguments(int argc) {
    return !(argc >= 1 && argc <= 4);
}

void process_registration_request(char* buffer, char* uid, char* password, char* pdip, char* pdport) {
    if (parse_register_message(uid, password, pdip, pdport)) {
        int code = register_user(uid, password, pdip, pdport);
        switch (code) {
            case OK_CODE:
                prepare_ok_message(buffer, REG_RESPONSE);
                break;

            case INVALID_UID_ERR_CODE:
            case INVALID_PASSWORD_ERR_CODE:
            case INCORRECT_PASSWORD_ERR_CODE:
            case UNKNOWN_ERROR:
                prepare_nok_message(buffer, REG_RESPONSE);
                break;

            default:
                prepare_error_message(buffer);
                break;
        }
    } else {
        prepare_error_message(buffer);
    }
}

void process_unregistration_request(char* buffer, char* uid, char* password) {
    if (parse_unregister_message(uid, password)) {
        int code = unregister_user(uid, password);
        switch (code) {
            case OK_CODE:
                prepare_ok_message(buffer, UNR_RESPONSE);
                break;

            case INCORRECT_PASSWORD_ERR_CODE:
            case UNKNOWN_ERROR:
                prepare_nok_message(buffer, UNR_RESPONSE);
                break;
            
            default:
                prepare_error_message(buffer);
                break;
        }
    } else {
        prepare_error_message(buffer);
    }
}

void process_login_request(char* buffer, char* uid, char* password) {
    if (parse_login_message(uid, password)) {
        int code = login_user(uid, password);

        switch (code) {
            case OK_CODE:
                prepare_ok_message(buffer, LOG_RESPONSE); 
                break;
            
            case INCORRECT_PASSWORD_ERR_CODE:
                prepare_nok_message(buffer, LOG_RESPONSE);
                break;

            default:
                prepare_error_message(buffer);
                break;
        }

    } else {
        prepare_error_message(buffer);
    } 
}

void process_request_request(char* buffer, char* uid, char* rid, char* fop, char** vc, char* operation) {
    char filename[SIZE];
    if (parse_request_message(uid, rid, fop, filename)) {
        int code = request_user(uid, fop, filename, vc, operation);
        prepare_request_message(buffer, code);
    } else {
        prepare_error_message(buffer);
    } 
}

void process_authentication_request(char* buffer, char* uid, char* rid, char* vc, char* operation) {
    char request_uid[UID_SIZE], request_rid[TID_SIZE], request_vc[VC_SIZE], tid[TID_SIZE];

    memset(request_uid, EOS, UID_SIZE); 
    memset(request_rid, EOS, TID_SIZE);
    memset(request_vc, EOS, VC_SIZE);

    if (parse_authentication_message(request_uid, request_rid, request_vc)) {
        memset(tid, EOS, TID_SIZE);
        if (authenticate_user(uid, rid, vc, request_uid, request_rid, request_vc, tid, operation)) {
            prepare_authentication_message(buffer, tid); 
        } else {
            prepare_error_message(buffer);
        }
    } else {
        prepare_error_message(buffer);
    }
}

void process_fs_validation_request(char* buffer, char* uid, char* tid) {
    if (parse_fs_validation_message(uid, tid)) {
        char fop[SIZE];
        memset(fop, EOS, SIZE);
        validate_fop(uid, tid, fop);
        prepare_fs_validation_message(buffer, uid, tid, fop);
    } else {
        prepare_error_message(buffer);
    }
}

void prepare_error_message(char* buffer) {
    memset(buffer, EOS, SIZE);
    strcpy(buffer, PROTOCOL_ERROR);
    strcat(buffer, "\n");
}

void prepare_ok_message(char* buffer, const char* command) {
    memset(buffer, EOS, SIZE);
    strcpy(buffer, command);
    strcat(buffer, " ");
    strcat(buffer, OK);
    strcat(buffer, "\n");
}

void prepare_nok_message(char* buffer, const char* command) {
    memset(buffer, EOS, SIZE);
    strcpy(buffer, command);
    strcat(buffer, " ");
    strcat(buffer, NOT_OK);
    strcat(buffer, "\n");
}

void prepare_not_logged_in_message(char* buffer) {
    memset(buffer, EOS, SIZE);
    strcpy(buffer, REQ_RESPONSE);
    strcat(buffer, " ");
    strcat(buffer, NOT_LOGGED_IN);
    strcat(buffer, "\n");
}

void prepare_invalid_user_message(char* buffer) {
    memset(buffer, EOS, SIZE);
    strcpy(buffer, REQ_RESPONSE);
    strcat(buffer, " ");
    strcat(buffer, INVALID_UID);
    strcat(buffer, "\n");
}

void prepare_invalid_fop_message(char* buffer) {
    memset(buffer, EOS, SIZE);
    strcpy(buffer, REQ_RESPONSE);
    strcat(buffer, " ");
    strcat(buffer, INVALID_FOP);
    strcat(buffer, "\n");
}

void prepare_pd_error_message(char* buffer) {
    memset(buffer, EOS, SIZE);
    strcpy(buffer, REQ_RESPONSE);
    strcat(buffer, " ");
    strcat(buffer, PD_NOT_AVAILABLE);
    strcat(buffer, "\n");
}

void prepare_request_message(char* buffer, int code) {
   
    switch (code) {
        case INVALID_UID_ERR_CODE:
            prepare_invalid_user_message(buffer);
            break;

        case INVALID_FOP_ERR_CODE:
            prepare_invalid_fop_message(buffer);
            break;

        case PD_NOT_CONNECTED_ERR_CODE:
            prepare_pd_error_message(buffer);
            break;

        default:
            prepare_ok_message(buffer, REQ_RESPONSE);
            break;
    }
}

void prepare_validation_pd_request(char* buffer, char* uid, char* vc, char* fop, char* filename) {
    memset(buffer, EOS, SIZE);
    strcpy(buffer, VALIDATE_USER);
    strcat(buffer, " ");
    strcat(buffer, uid);
    strcat(buffer, " ");
    strcat(buffer, vc);
    strcat(buffer, " ");
    strcat(buffer, fop);
    if (strlen(filename) > 0) {
        strcat(buffer, " ");
        strcat(buffer, filename);
    }
    strcat(buffer, "\n");
}

void prepare_authentication_message(char* buffer, char* tid) {
    memset(buffer, EOS, SIZE);
    strcpy(buffer, AUT_RESPONSE);
    strcat(buffer, " ");
    strcat(buffer, tid);
    strcat(buffer, "\n");
}

void prepare_fs_validation_message(char* buffer, char* uid, char* tid, char* fop) {
// CNF UID TID Fop [Fname]
    memset(buffer, EOS, SIZE);
    strcpy(buffer, VAL_FILE_RESPONSE);
    strcat(buffer, " ");
    strcat(buffer, uid);
    strcat(buffer, " ");
    strcat(buffer, tid);
    strcat(buffer, " ");
    strcat(buffer, fop);
    strcat(buffer, "\n");
}

// parses the arguments given on the command line
void parse_arguments(const char* argv[], int size) {
    parse_as_port(argv, size, &asport);
    verbose = parse_verbose_flag(argv, size);
}

Boolean parse_command(char* buffer, char* command) {
    char *token;

    if(!(token = strtok(buffer, " "))) {
        fprintf(stderr, "wrong command!\n");
        return false;
    }
    strcpy(command, token);
    return true;
}

// parses the register command
Boolean parse_register_message(char* uid, char* password, char* pdip, char* pdport) {
    char *token;

    token = strtok(NULL, " ");
    if (!token) {
        fprintf(stderr, "ERROR: user field empty!\n");
        return false;
    }
    strcpy(uid, token);

    token = strtok(NULL, " ");
    if (!token) {
        fprintf(stderr, "ERROR: password field empty!\n");
        return false;
    }
    strcpy(password, token);

    token = strtok(NULL, " ");
    if (!token) {
        fprintf(stderr, "Invalid PDIP!\n");
        return false;
    }
    strcpy(pdip, token);

    token = strtok(NULL, "\n");
    if (!token) {
        fprintf(stderr, "Invalid PDPort!\n");
        return false;
    }
    strcpy(pdport, token);

   
    return true;
}

Boolean parse_unregister_message(char* uid, char* password) {
    char *token;

    token = strtok(NULL, " ");
   
    if (!valid_uid(token)) {
        fprintf(stderr, "Invalid user!\n");
        return false;
    }
    strcpy(uid, token);

    token = strtok(NULL, "\n");
   
    if (!valid_password(token)) {
        fprintf(stderr, "Invalid password!\n");
        return false;
    }
    strcpy(password, token);
    return true;
}

Boolean parse_login_message(char* uid, char* password) {
    char *token;

    token = strtok(NULL, " ");
    if (!valid_uid(token)) {
        return false;
    }
    strcpy(uid, token);

    token = strtok(NULL, "\n");
    if (!valid_password(token)) {
        return false;
    }
    strcpy(password, token);
    return true;
}

Boolean parse_request_message(char* uid, char* rid, char* fop, char* filename) {
    char *token, aux[SIZE];

    memset(aux, EOS, SIZE);
    memset(filename, EOS, SIZE);

    token = strtok(NULL, " ");
    if (!token) { // the user validation will be performed later
        fprintf(stderr, "ERROR: invalid user!\n");
        return false;
    }
   
    memset(uid, EOS, UID_SIZE);
    strcpy(uid, token);

    token = strtok(NULL, " ");
    if (!token) {
        fprintf(stderr, "ERROR: invalid RID!\n");
        return false;
    }
    strcpy(rid, token);

    // Rest of the message
    if(!(token = strtok(NULL, "\n"))) {
        fprintf(stderr, "ERROR: invalid Fop\n");
        return false;
    }

    strcpy(aux, token);
    
    // Fop
    if(!(token = strtok(aux, " "))) {
        fprintf(stderr, "ERROR: invalid Fop\n");
        return false;
    }

    strcpy(fop, token);

    // if the fop needs a filename and none is provided
    if(!(token = strtok(NULL, "\0")) && fop_has_file(fop)) {
        fprintf(stderr, "ERROR: Fop %s needs a file\n", fop);
        return false;
    }

    // if the fop needs a filename and none is provided
    if(token && !fop_has_file(fop)) {
        fprintf(stderr, "ERROR: Fop %s doesn't need a file\n", fop);
        return false;
    }

    if (token) {
        strcpy(filename, token);
    }

   
    return true;
}

Boolean parse_authentication_message(char* uid, char* rid, char* vc) {
    char* token;
    
    token = strtok(NULL, " ");
    if (!valid_uid(token)) { // the user validation will be performed later
        fprintf(stderr, "ERROR: invalid user!\n");
        return false;
    }
    
    memset(uid, EOS, UID_SIZE);
    strcpy(uid, token);

    token = strtok(NULL, " ");
    if (!token) {
        fprintf(stderr, "ERROR: invalid RID!\n");
        return false;
    }
    strcpy(rid, token);

    // Rest of the message
    if(!(token = strtok(NULL, "\n"))) {
        fprintf(stderr, "ERROR: invalid VC\n");
        return false;
    }

    strcpy(vc, token);
    
   
    return true;
}

Boolean parse_fs_validation_message(char* uid, char* tid) {
    char* token;
    
    token = strtok(NULL, " ");
    if (!valid_uid(token)) { // the user validation will be performed later
        fprintf(stderr, "ERROR: invalid user!\n");
        return false;
    }
    
    memset(uid, EOS, UID_SIZE);
    strcpy(uid, token);

    token = strtok(NULL, "\n");
    if (!token) {
        fprintf(stderr, "ERROR: invalid TID!\n");
        return false;
    }
    strcpy(tid, token);

   
    return true;
}

// returns true if the uid only contains numbers
// false otherwise
Boolean all_numbers(char* uid) {
    int len = strlen(uid);
    for (int i=0; i < len; i++) {
        if (uid[i] < '0' || uid[i] > '9') {
            return false;
        }
    }
    return true;
}

// returns true if the user is valid
// false otherwise
Boolean valid_uid(char* uid) {
    if (uid) {
        if (strlen(uid) != UID_SIZE-1 || !all_numbers(uid)) {
            fprintf(stderr, "Invalid UID\nThe UID must have 5 numbers\n");
            return false;
        }
        return true;
    }

    fprintf(stderr, "UID missing!\nMust give a UID\n");
    return false;
}

// returns true if the password only contains letters and/or numbers
// false otherwise
Boolean only_numbers_or_letters(char* password) {
    int len = strlen(password);
    for (int i=0; i < len; i++) {
        if ((password[i] >= '0' && password[i] <= '9') || 
            (password[i] >= 'A' && password[i] <= 'Z') ||
            (password[i] >= 'a' && password[i] <= 'z')) {
            continue;
        }
        return false;
    }
    return true;
}

// returns true if the user is valid
// false otherwise
Boolean valid_password(char* password) {
    if (password) {
        if (strlen(password) == (PASSWORD_SIZE-1) && only_numbers_or_letters(password)) {
            return true;
        }
        fprintf(stderr, "Invalid password!\nThe password must have 8 numbers and/or letters\n");
        return false;
    }

    fprintf(stderr, "Password missing!\nMust give a password\n");
    return false;
}

Boolean fop_has_file(char* fop) {
    return !(strcmp(fop, FOP_UPLOAD) && 
            strcmp(fop, FOP_RETRIEVE) && 
            strcmp(fop, FOP_DELETE));
}

Boolean valid_fop(char *fop) {
    return !(strcmp(fop, FOP_DELETE) && 
             strcmp(fop, FOP_LIST) &&
             strcmp(fop, FOP_REMOVE) &&
             strcmp(fop, FOP_RETRIEVE) &&
             strcmp(fop, FOP_UPLOAD));
}

Boolean send_vc_to_pd(char* uid, char* fop, char* filename, char** vc) {
    char pdip[SIZE], pdport[SIZE];
    char buffer[SIZE], *full_path;
    int pdsocket;
    struct addrinfo hints, *client;
    struct sockaddr_in addr;

    generate_random_vc(vc);
    printf("vc=%s\n", *vc);

    prepare_validation_pd_request(buffer, uid, *vc, fop, filename);

    get_user_file_path(&full_path, uid, REGISTRATION_FILE_PREFIX, FILE_EXTENSION);

    printf("path = %s\n", full_path);

    // opens the password file
    if (!(userfd = fopen(full_path, "r"))) {
        fprintf(stderr, "ERROR: could not open file %s\n", full_path);
        free(full_path);
        return false;
    }

    memset(pdip, EOS, SIZE);
    memset(pdport, EOS, SIZE);

    // reads the password from the file
    fscanf(userfd, "%s %s\n", pdip, pdport);

    // closes the password file
    fclose(userfd);

    free(full_path);

    printf("pdip=%s\npdport=%s\n", pdip, pdport);

    // sets the socket
    pdsocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (pdsocket == ERROR) {
        //error
        fprintf(stderr, "ERROR: socket returned null\n");
        return false;
    }
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    
    // gets the address info
    int errcode = getaddrinfo(pdip, pdport, &hints, &client);
    if (errcode != 0) {
        //error
        fprintf(stderr, "ERROR: getaddrinfo returned %d error code\n", errcode);
        return false;
    }

    struct timeval tv;
    tv.tv_sec = PD_TIMEOUT_SECS;
    tv.tv_usec = PD_TIMEOUT_USECS; 

    // sets socket timeout as 5s
    if ((errcode = setsockopt(pdsocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv))) < 0) {
        fprintf(stderr, "ERROR: setsockopt returned erro code %d\n", errcode);
        return false;
    }

    printf("sent to pd=%s", buffer);

    int n = udp_write(pdsocket, buffer, client -> ai_addr, client -> ai_addrlen);

    if (!n) return false;

    memset(buffer, EOS, SIZE);

    n = udp_read(pdsocket, buffer, SIZE, (struct sockaddr*) &addr);

    if (!n) return false;

    printf("received from pd = %s\n", buffer);

    char error_message[SIZE];
    memset(error_message, EOS, SIZE);
    strcpy(error_message, PROTOCOL_ERROR);
    strcat(error_message, "\n");

    if (!strcmp(buffer, error_message)) {
        fprintf(stderr, "ERROR: PD sent %s error message\n", PROTOCOL_ERROR);
        return false;
    }

    
    return true;
}

void get_user_directory(char* buffer, char *uid) {
    memset(buffer, EOS, strlen(buffer));
    strcpy(buffer, "./");
    strcat(buffer, users_directory);
    strcat(buffer, uid);
    strcat(buffer, "/");
}

void get_filename(char* buffer, char* uid, const char* filename, const char* file_ext) {
    memset(buffer, EOS, strlen(buffer));
    strcat(buffer, uid);
    strcat(buffer, filename);
    strcat(buffer, file_ext);
}

void generate_random_vc(char** vc) {
    int vc_alg, vc_number = 0;
    
    if (!(*vc = (char *) malloc(sizeof(char)*VC_SIZE))){
        perror("ERROR: allocating \"validation code\" buffer");
        exit(EXIT_FAILURE);
    }

    // uses the current time as seed for random generator
    srand(time(NULL));
    memset(*vc, EOS, VC_SIZE);
    for (int i = 0; i < (VC_SIZE - 1); i++) {
        vc_alg = rand() % 10;
        vc_number = vc_number * 10 + vc_alg;
        printf("vc_alg=%d\tvc_number=%d\n", vc_alg, vc_number);
    }

    // converts the random number into a string with 4 digits
    sprintf(*vc, "%04d", vc_number);
}

int register_user(char* uid, char* password, char* ip, char* port) {
    char* directory = NULL;
    char* full_path; // users_directory/uid/file

    if (!valid_uid(uid)) {
        fprintf(stderr, "ERROR: Invalid user!\n");
        return INVALID_UID_ERR_CODE;
    }

    if(!valid_password(password)) {
        fprintf(stderr, "ERROR: Invalid password!\n");
        return INVALID_PASSWORD_ERR_CODE;
    }

    // allocates memory for the relative path for the user with uid
    if (!(directory = (char *) malloc(sizeof(char)*(strlen(users_directory)+ strlen(uid) + 2)))) {
        perror("ERROR: allocating \"path\" buffer");
        return UNKNOWN_ERROR;
    }

    get_user_directory(directory, uid);
    get_user_file_path(&full_path, uid, PASSWORD_FILE_PREFIX, FILE_EXTENSION);

    // check if the directory is created or not 
    if (stat(directory, &st) == ERROR) { // if directory doesn t exists
        if (mkdir(directory, 0777)) { 
            printf("Unable to create directory \"%s\"\n", directory); 
            free(directory);
            free(full_path);
            return UNKNOWN_ERROR;
        }

        // opens the password file
        if (!(userfd = fopen(full_path, "w"))) {
            fprintf(stderr, "ERROR: could not open file: %s\n", full_path);
            free(directory);
            free(full_path);
            return UNKNOWN_ERROR;
        }

        // writes the password on the file
        fprintf(userfd, "%s\n", password);

        // closes the password file
        fclose(userfd);
    } else { // the user already exists
        // opens the password file
        if (!(userfd = fopen(full_path, "r"))) {
            fprintf(stderr, "ERROR: could not open file %s\n", full_path);
            free(directory);
            free(full_path);
            return UNKNOWN_ERROR;
        }
        char password_from_file[PASSWORD_SIZE];
        // reads the password from the file
        fscanf(userfd, "%s\n", password_from_file);

        if (strcmp(password, password_from_file)) {
            fprintf(stderr, "ERROR: wrong uid or password\n");
            free(directory);
            free(full_path);
            return INCORRECT_PASSWORD_ERR_CODE;
        }

        // closes the password file
        fclose(userfd);
    }

    free(full_path);
    get_user_file_path(&full_path, uid, REGISTRATION_FILE_PREFIX, FILE_EXTENSION);

    // opens the registration file
    if (!(userfd = fopen(full_path, "w"))) {
        fprintf(stderr, "ERROR: could not open file %s\n", full_path);
        free(directory);
        free(full_path);
        return UNKNOWN_ERROR;
    }

    // writes the ip and the port like "ip:port"
    fprintf(userfd, "%s %s\n", ip, port);
    
    // closes the registration file
    fclose(userfd);

    free(directory);
    free(full_path);

    return OK_CODE;
}

int unregister_user(char *uid, char *password) {
    char* full_path; // users_directory/uid/file

    get_user_file_path(&full_path, uid, PASSWORD_FILE_PREFIX, FILE_EXTENSION);
    // opens the password file
    if (!(userfd = fopen(full_path, "r"))) {
        fprintf(stderr, "ERROR: could not open file %s\n", full_path);
        free(full_path);
        return UNKNOWN_ERROR;
    }

    char password_from_file[PASSWORD_SIZE];
    // reads the password from the file
    fscanf(userfd, "%s\n", password_from_file);

    if (strcmp(password, password_from_file)) {
        fprintf(stderr, "ERROR: wrong uid or password\n");
        free(full_path);
        return INCORRECT_PASSWORD_ERR_CODE;
    }

    // closes the password file
    fclose(userfd);

    // clears the full_path and filename memory
    free(full_path);

    get_user_file_path(&full_path, uid, REGISTRATION_FILE_PREFIX, FILE_EXTENSION);

    if (remove(full_path)) {
        fprintf(stderr, "ERROR: could not remove file %s\n", full_path);
        free(full_path);
        return UNKNOWN_ERROR;
    };

    free(full_path);

    return OK_CODE;
}

int login_user(char* uid, char* password) {
    char* directory = NULL;
    char* full_path = NULL; // users_directory/uid/file

    // allocates memory for the relative path for the user with uid
    if (!(directory = (char *) malloc(sizeof(char)*(strlen(users_directory)+ strlen(uid) + 2)))) {
        perror("ERROR: allocating \"path\" buffer");
        return UNKNOWN_ERROR;
    }

    get_user_directory(directory, uid);

    // check if the directory is created or not 
    if (stat(directory, &st) == ERROR) { // if directory doesn't exists
        fprintf(stderr, "ERROR: user was not registered\n");
        free(directory);
        return UID_NOT_FOUND_ERROR ;
    }

    get_user_file_path(&full_path, uid, PASSWORD_FILE_PREFIX, FILE_EXTENSION);
   

    // opens the password file
    if (!(userfd = fopen(full_path, "r"))) {
        fprintf(stderr, "ERROR: could not open file %s\n", full_path);
        free(directory);
        free(full_path);
        return UNKNOWN_ERROR;
    }

    char password_from_file[PASSWORD_SIZE];
    // reads the password from the file
    fscanf(userfd, "%s\n", password_from_file);
   

    if (strcmp(password, password_from_file)) {
        fprintf(stderr, "ERROR: wrong uid or password\n");
        free(directory);
        free(full_path);
        return INCORRECT_PASSWORD_ERR_CODE;
    }

    // closes the password file
    fclose(userfd);

    free(full_path);

    get_user_file_path(&full_path, uid, LOGIN_FILE_PREFIX, FILE_EXTENSION);

    // opens the password file
    if (!(userfd = fopen(full_path, "w"))) {
        fprintf(stderr, "ERROR: could not open file %s\n", full_path);
        free(directory);
        free(full_path);
        return UNKNOWN_ERROR;
    }

    // writes the uid and the password on the file
    fprintf(userfd, "%s %s\n", uid, password);
    // closes the password file
    fclose(userfd);

    free(directory);
    free(full_path);
    return OK_CODE;
}

int request_user(char* uid, char* fop, char* filename, char** vc, char* operation) {
    // if the uid is invalid
    if (!valid_uid(uid)) {
        return INVALID_UID_ERR_CODE;
    }

    // if the fop is not valid
    if (!valid_fop(fop)) {
        return INVALID_FOP_ERR_CODE;
    }

    // if the PD doesn't respond
    if (!send_vc_to_pd(uid, fop, filename, vc)) {
        return PD_NOT_CONNECTED_ERR_CODE;
    }

    printf("exiting send_vc_to_pd\tvc=%s\n", *vc);

    memset(operation, EOS, SIZE);
    strcat(operation, fop);
    if (strlen(filename)) {
        strcat(operation, " ");
        strcat(operation, filename);
    }

    return OK_CODE;
}

Boolean authenticate_user(char* uid, char* rid, char* vc, char* request_uid, char* request_rid, char* request_vc, char* tid, char* request) {
    int tid_number = 1;
    strcpy(tid, "0");
    // if user, rid or vc are not initialized
    if (!(uid && rid && vc)) {
        fprintf(stderr, "uid or rid or vc were not initialized\n");
        return false;
    }

    if (strcmp(uid, request_uid)) {
        fprintf(stderr, "uid was incorrect\n");
        return false;
    }

    if (strcmp(rid, request_rid)) {
        fprintf(stderr, "rid was incorrect\n");
        return false;
    }

    if (strcmp(vc, request_vc)) {
        printf("vc=%s\trequest_vc=%s\n", vc, request_vc);
        fprintf(stderr, "vc was incorrect\n");
        return false;
    }

    char* path = NULL;
    FILE* f;

    char tid_file_prefix[TID_SIZE+1];
    memset(tid_file_prefix, EOS, TID_SIZE+1);
    sprintf(tid_file_prefix, "_%04d", tid_number);

    get_user_file_path(&path, uid, tid_file_prefix, FILE_EXTENSION);

    while ((f = fopen(path, "r"))) { // while file exists
        fclose(f);
        memset(tid_file_prefix, EOS, TID_SIZE+1);
        sprintf(tid_file_prefix, "_%04d", ++tid_number);
        free(path);
        get_user_file_path(&path, uid, tid_file_prefix, FILE_EXTENSION);
    }
   

    // opens the password file
    if (!(userfd = fopen(path, "w"))) {
        fprintf(stderr, "ERROR: could not open file %s\n", path);
        free(path);
        return false;
    }

    fprintf(userfd, "%s\n", request);

    fclose(userfd);

    memset(tid, EOS, TID_SIZE);
    // converts the number into a string
    sprintf(tid, "%04d", tid_number);

    return true;
}

Boolean validate_fop(char* uid, char* tid, char* fop) {
    FILE* f;
    char* path = NULL, filename[SIZE];

    memset(filename, EOS, SIZE);
    strcpy(filename, "_");
    strcat(filename, tid);

    get_user_file_path(&path, uid, filename, FILE_EXTENSION);

    if (!(f = fopen(path, "r"))) {
        fprintf(stderr, "ERROR: tid %s does not exist with uid %s\n", tid, uid);
        free(path);
        strcpy(fop, FOP_ERROR);
        return false;
    }

    int c;
    for (int i = 0; (c = fgetc(f)) != '\n'; i++) {
        // reads the fop from the file
        fop[i] = (char) c;
    }

    // closes the tid file
    fclose(f);

    free(path);

    if (!strcmp(fop, FOP_REMOVE)) { // remove operation
        char *directory = NULL;
        // allocates memory for the relative path for the user with uid
        if (!(directory = (char *) malloc(sizeof(char) * (strlen(users_directory) + strlen(uid) + 2)))) {
            perror("ERROR: allocating \"path\" buffer");
            return false;
        }
        get_user_directory(directory, uid);
       
        remove_all_files(directory);
        free(directory);
    }

    return true;
}

Boolean remove_all_files(char* dirname) {
    DIR *d;
    struct dirent *dir;
    char path[SIZE];
    d = opendir(dirname);
    if (d) {
        while((dir=readdir(d)) != NULL) {
            if (strcmp(dir->d_name, "..") && strcmp(dir->d_name, ".")) {
                memset(path, EOS, SIZE);
                strcpy(path, dirname);
                strcat(path, dir->d_name);
               
                if (remove(path)) {
                    fprintf(stderr, "ERROR: could not remove file %s\n", path);
                    return false;
                }
            }
        }
        rmdir(dirname); // removes the directory
        closedir(d);
        return true;
    } else {
        return false;
    }
    
}

Boolean get_user_file_path(char** path, char* uid, const char* file_name, const char* file_extension) {
    char* filename = NULL, *directory = NULL;
    Boolean return_value = true;

    // allocates memory for the password file for the user with uid
    int filename_size = strlen(uid) + strlen(file_name) + strlen(file_extension);
    if (!(filename = (char *) malloc(sizeof(char) * filename_size))){
        perror("ERROR: allocating \"filename\" buffer");
        return_value = false;
    }

    get_filename(filename, uid, file_name, file_extension);

    // allocates memory for the relative path for the user with uid
    if (!(directory = (char *) malloc(sizeof(char) * (strlen(users_directory) + strlen(uid) + 2)))) {
        perror("ERROR: allocating \"path\" buffer");
        return_value = false;
    }

    get_user_directory(directory, uid);

    // allocates memory for full relative path to the password file for the user with uid
    if (!(*path = (char *) malloc(sizeof(char)*(strlen(directory) + strlen(filename))))) {
        perror("ERROR: allocating \"path\" buffer");
        return_value = false;
    }

    memset(*path, EOS, strlen(directory) + strlen(filename));

    strcat(*path, directory);
    strcat(*path, filename);

    free(directory);
    free(filename);

    return return_value;
}

Boolean remove_file(char* uid, const char* filename, const char* file_extension) {
    char* path = NULL;
    if (!get_user_file_path(&path, uid, filename, file_extension)) {
        return false;
    }

    if (remove(path)) {
        fprintf(stderr, "ERROR: could not remove file %s\n", path);
        free(path);
        return false;
    };
    free(path);
    return true;
}
