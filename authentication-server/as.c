#include "as.h"

// the buffer where ASport is stored
char *asport;
const char *users_directory = USERS_FOLDER_NAME;
FILE *userfd; 
struct stat st = {0};

int main(int argc, char const *argv[]) {
    int udpsocket, tcpsocket, connectfd, out_fds, childpid, errcode;
    fd_set inputs, testfds;
    struct timeval timeout;
    ssize_t n;
    socklen_t addrlen;
    struct addrinfo hints,*res;
    struct sockaddr_in cliaddr;
    char buffer[SIZE];
    
    // checks if the number of arguments is correct
    if (wrong_arguments(argc)) {
        usage();
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, handler_sigint);

    // parses the argv arguments
    parse_arguments(argv, argc);

    printf("ASport=%s\n", asport);

    // create and bind the UDP Socket
    udpsocket = socket(AF_INET, SOCK_DGRAM, 0);

    if(udpsocket == ERROR) {
        /*error*/
        fprintf(stderr, "Error: it was not possible to create udp socket\n");
        exit(EXIT_FAILURE);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_DGRAM; // UDP socket
    hints.ai_flags = AI_PASSIVE;

    errcode = getaddrinfo(NULL, asport, &hints, &res);

    if (errcode != 0) {
        /*error*/ 
        fprintf(stderr, "Error: udp socket getaddrinfo returned %d error code\n", errcode);
        exit(EXIT_FAILURE);
    }

    n = bind(udpsocket, res -> ai_addr, res -> ai_addrlen);
    if (n == ERROR)  {
        /*error*/
        fprintf(stderr, "Error: udp socket bind returned %ld error code\n", n);
        exit(EXIT_FAILURE);
    }

    // create and bind the TCP Socket
    tcpsocket = socket(AF_INET, SOCK_STREAM, 0);

    if (tcpsocket == ERROR) {
        //error
        fprintf(stderr, "Error: it was not possible to create tcp socket\n");
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
        /*error*/
        fprintf(stderr, "Error: tcp socket getaddrinfo returned %d error code\n", errcode);
        exit(EXIT_FAILURE); 
    }

    n = bind(tcpsocket, res -> ai_addr, res -> ai_addrlen);
    if (n == ERROR) {
        fprintf(stderr, "Error: tcp socket bind returned %ld error code\n", n);
        /*error*/ 
        exit(EXIT_FAILURE);
    } 
        
    if (listen(tcpsocket, 5) == ERROR) {
        /*error*/
        fprintf(stderr, "Error: tcp socket listen returned %d error code\n", ERROR);
        exit(EXIT_FAILURE);
    }

    // creates the directory where the users' information will be stored
    if (stat(users_directory, &st) == -1) { // if directory doesn t exists
        // check if directory is created or not 
        if (mkdir(users_directory, 0777)) { 
            printf("Unable to create directory \"%s\"\n", users_directory); 
            exit(EXIT_FAILURE); 
        }
    }

    char command[SIZE], uid[UID_SIZE], password[PASSWORD_SIZE], pdip[SIZE], pdport[SIZE];
    memset(command, EOS, SIZE);
    memset(uid, EOS, UID_SIZE);
    memset(password, EOS, PASSWORD_SIZE);
    memset(pdip, EOS, SIZE);
    memset(pdport, EOS, SIZE);

    FD_ZERO(&inputs);
    FD_SET(udpsocket, &inputs);
    FD_SET(tcpsocket, &inputs);

    while (true) {
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
            //  if udp socket is ready to listen
            if (FD_ISSET(udpsocket, &testfds)) {
                printf("Received on UDP socket\n");
                memset(buffer, EOS, SIZE);
                addrlen = sizeof(cliaddr);
                n = udp_read(udpsocket, buffer, SIZE, (struct sockaddr*) &cliaddr);

                if (parse_command(buffer, command)) {
                    if (!strcmp(command, REGISTRATION)) {
                        process_registration_request(buffer, uid, password, pdip, pdport);
                    } else if (!strcmp(command, UNREGISTRATION)) {
                        process_unregistration_request(buffer, uid, password);
                    } else {
                        prepare_error_message(buffer);
                    } 
                } else {
                    prepare_error_message(buffer);
                }
                
                printf("command = %s\n", command);
                write(STDOUT, "received: ", 10);
                write(STDOUT, buffer, n);

                n = udp_write(udpsocket, buffer, (struct sockaddr*) &cliaddr, sizeof(cliaddr));
            }
            break;
        }

        //  if tcp socket is ready to listen
        if (FD_ISSET(tcpsocket, &testfds)) {
            printf("Received on TCP socket\n");
            addrlen = sizeof(cliaddr);
            connectfd = accept(tcpsocket, (struct sockaddr*) &cliaddr, &addrlen);
            printf("connectfd = %d\n", connectfd);
            char rid[TID_SIZE], fop[FOP_SIZE], *vc = NULL;

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

                    if (!n) { // the client has disconnected
                        continue;
                    }

                    if (parse_command(buffer, command)) {
                        if (!strcmp(command, LOGIN)) {
                            process_login_request(buffer, uid, password);
                        } else if (!strcmp(command, REQUEST)) {
                            prepare_not_logged_in_message(buffer);
                        }
                        else {
                            prepare_error_message(buffer);
                        } 
                    } else {
                        prepare_error_message(buffer);
                    }

                    n = tcp_write(connectfd, buffer);
                    printf("Message to tcp client: ");
                    puts(buffer);
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
                        printf("Message from tcp client: ");
                        puts(buffer);
                        if (!n) { // the socket has disconnected
                            continue;
                        }
                        
                        if (parse_command(buffer, command)) {
                            if (!strcmp(command, LOGIN)) {
                                process_login_request(buffer, uid, password);
                            } 
                            else if (!strcmp(command, REQUEST)) {
                                process_request_request(buffer, uid, rid, fop, &vc, operation);
                            } 
                            else {
                                prepare_error_message(buffer);
                            } 
                        } else {
                            prepare_error_message(buffer);
                        }
                        
                        n = tcp_write(connectfd, buffer);
                        printf("Message sent to tcp client: ");
                        puts(buffer);

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

                        if (!n) { // the client has disconnected
                            continue;
                        }

                        if (parse_command(buffer, command)) {
                            if (!strcmp(command, AUTHENTICATION)) {
                                printf("entering authentication vc=%s\n", vc);
                                process_authentication_request(buffer, uid, rid, vc, operation);
                            } else {
                                prepare_error_message(buffer);
                            } 
                        } else {
                            prepare_error_message(buffer);
                        }

                        n = tcp_write(connectfd, buffer);
                        printf("Message to tcp client: ");
                        puts(buffer);
                        
                    } while (n && (!strcmp(buffer, error_message) || !strcmp(buffer, auth_failed))); // while the socket is connected and login not succeeded

                } while (n);

                printf("Client %d disconnected\n", connectfd);
                close(connectfd);
                exit(EXIT_SUCCESS);

            } else if (childpid == ERROR) {
                fprintf(stderr, "Error: could not create child process for tcp connection");
                exit(EXIT_FAILURE);
            }
            close(connectfd);
        }
    }

    freeaddrinfo(res);
    close (udpsocket);

    exit(EXIT_SUCCESS);
}

// diplays a message with the correct usage of the file
void usage() {
    printf("usage: ./as [-p ASport] [-v]\n");
    printf("example: ./as -p 58011 -v\n");
}

// returns true if the arguments given on the command line are on an invalid format, and false otherwise
int wrong_arguments(int argc) {
    return argc != 1 && argc != 3 && argc != 4;
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
    printf("request code=%d\n", code);
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
    strcat(buffer, " ");
    strcat(buffer, filename);
    strcat(buffer, "\n");
}

void prepare_authentication_message(char* buffer, char* tid) {
    memset(buffer, EOS, SIZE);
    strcpy(buffer, AUT_RESPONSE);
    strcat(buffer, " ");
    strcat(buffer, tid);
    strcat(buffer, "\n");
}

// parses the arguments given on the command line
void parse_arguments(const char* argv[], int size) {
    parse_as_port(argv, size, &asport);
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
        fprintf(stderr, "Error: user field empty!\n");
        return false;
    }
    strcpy(uid, token);

    token = strtok(NULL, " ");
    if (!token) {
        fprintf(stderr, "Error: password field empty!\n");
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

    printf("uid: %s\npassword: %s\nPDIP: %s\nPDPort: %s\n", uid, password, pdip, pdport);
    return true;
}

Boolean parse_unregister_message(char* uid, char* password) {
    char *token;

    token = strtok(NULL, " ");
    printf("uid=%s\n", token);
    if (!valid_uid(token)) {
        fprintf(stderr, "Invalid user!\n");
        return false;
    }
    strcpy(uid, token);

    token = strtok(NULL, "\n");
    printf("password=%s\n", token);
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
        fprintf(stderr, "Error: invalid user!\n");
        return false;
    }
    printf("token=%s\n", token);
    memset(uid, EOS, UID_SIZE);
    strcpy(uid, token);

    token = strtok(NULL, " ");
    if (!token) {
        fprintf(stderr, "Error: invalid RID!\n");
        return false;
    }
    strcpy(rid, token);

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

    // if the fop needs a filename and none is provided
    if(!(token = strtok(NULL, "\0")) && fop_has_file(fop)) {
        fprintf(stderr, "Error: Fop %s needs a file\n", fop);
        return false;
    }

    if (token) {
        strcpy(filename, token);
    }

    printf("uid: %s\nRID: %s\nFop: %s\nFilename: %s\n", uid, rid, fop, filename);
    return true;
}

Boolean parse_authentication_message(char* uid, char* rid, char* vc) {
    char* token;
    
    token = strtok(NULL, " ");
    if (!valid_uid(token)) { // the user validation will be performed later
        fprintf(stderr, "Error: invalid user!\n");
        return false;
    }
    
    memset(uid, EOS, UID_SIZE);
    strcpy(uid, token);

    token = strtok(NULL, " ");
    if (!token) {
        fprintf(stderr, "Error: invalid RID!\n");
        return false;
    }
    strcpy(rid, token);

    // Rest of the message
    if(!(token = strtok(NULL, "\n"))) {
        fprintf(stderr, "Error: invalid VC\n");
        return false;
    }

    strcpy(vc, token);
    
    printf("uid: %s\nRID: %s\nVC: %s\n", uid, rid, vc);
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
        fprintf(stderr, "Error: could not open file %s\n", full_path);
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
        fprintf(stderr, "Error: socket returned null\n");
        return false;
    }
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    
    // gets the address info
    int errcode = getaddrinfo(pdip, pdport, &hints, &client);
    if (errcode != 0) {
        //error
        fprintf(stderr, "Error: getaddrinfo returned %d error code\n", errcode);
        return false;
    }

    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0; 

    // sets socket timeout as 5s
    if ((errcode = setsockopt(pdsocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv))) < 0) {
        fprintf(stderr, "Error: setsockopt returned erro code %d\n", errcode);
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
        fprintf(stderr, "Error: PD sent %s error message", PROTOCOL_ERROR);
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

    printf("get_directory = %s\n", buffer);
}

void get_filename(char* buffer, char* uid, const char* filename, const char* file_ext) {
    memset(buffer, EOS, strlen(buffer));
    strcat(buffer, uid);
    strcat(buffer, filename);
    strcat(buffer, file_ext);

    printf("get_filename = %s\n", buffer);
}

void generate_random_vc(char** vc) {
    int vc_alg, vc_number = 0;
    if (!(*vc = (char *) malloc(sizeof(char)*VC_SIZE))){
        perror("Error: allocating \"validation code\" buffer");
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
        fprintf(stderr, "Error: Invalid user!\n");
        return INVALID_UID_ERR_CODE;
    }

    if(!valid_password(password)) {
        fprintf(stderr, "Error: Invalid password!\n");
        return INVALID_PASSWORD_ERR_CODE;
    }

    // allocates memory for the relative path for the user with uid
    if (!(directory = (char *) malloc(sizeof(char)*(strlen(users_directory)+ strlen(uid) + 2)))) {
        perror("Error: allocating \"path\" buffer");
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
            fprintf(stderr, "Error: could not open file: %s\n", full_path);
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
            fprintf(stderr, "Error: could not open file %s\n", full_path);
            free(directory);
            free(full_path);
            return UNKNOWN_ERROR;
        }
        char password_from_file[PASSWORD_SIZE];
        // reads the password from the file
        fscanf(userfd, "%s\n", password_from_file);
        printf("password_from_file=%s\n", password_from_file);

        if (strcmp(password, password_from_file)) {
            fprintf(stderr, "Error: wrong uid or password\n");
            free(directory);
            free(full_path);
            return INCORRECT_PASSWORD_ERR_CODE;
        }

        // closes the password file
        fclose(userfd);
    }

    free(full_path);
    get_user_file_path(&full_path, uid, REGISTRATION_FILE_PREFIX, FILE_EXTENSION);

    printf("reg_path = %s\n", full_path);

    // opens the registration file
    if (!(userfd = fopen(full_path, "w"))) {
        fprintf(stderr, "Error: could not open file %s\n", full_path);
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
        fprintf(stderr, "Error: could not open file %s\n", full_path);
        free(full_path);
        return UNKNOWN_ERROR;
    }

    char password_from_file[PASSWORD_SIZE];
    // reads the password from the file
    fscanf(userfd, "%s\n", password_from_file);
    printf("password_from_file=%s\n", password_from_file);

    if (strcmp(password, password_from_file)) {
        fprintf(stderr, "Error: wrong uid or password\n");
        free(full_path);
        return INCORRECT_PASSWORD_ERR_CODE;
    }

    // closes the password file
    fclose(userfd);

    // clears the full_path and filename memory
    free(full_path);

    get_user_file_path(&full_path, uid, REGISTRATION_FILE_PREFIX, FILE_EXTENSION);

    printf("reg_path = %s\n", full_path);

    if (remove(full_path)) {
        fprintf(stderr, "Error: could not remove file %s\n", full_path);
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
        perror("Error: allocating \"path\" buffer");
        return UNKNOWN_ERROR;
    }

    get_user_directory(directory, uid);

    // check if the directory is created or not 
    if (stat(directory, &st) == ERROR) { // if directory doesn't exists
        fprintf(stderr, "Error: user was not registered\n");
        free(directory);
        return UID_NOT_FOUND_ERROR ;
    }

    get_user_file_path(&full_path, uid, PASSWORD_FILE_PREFIX, FILE_EXTENSION);
    printf("path = %s\n", full_path);

    // opens the password file
    if (!(userfd = fopen(full_path, "r"))) {
        fprintf(stderr, "Error: could not open file %s\n", full_path);
        free(directory);
        free(full_path);
        return UNKNOWN_ERROR;
    }

    char password_from_file[PASSWORD_SIZE];
    // reads the password from the file
    fscanf(userfd, "%s\n", password_from_file);
    printf("password_from_file=%s\n", password_from_file);

    if (strcmp(password, password_from_file)) {
        fprintf(stderr, "Error: wrong uid or password\n");
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
        fprintf(stderr, "Error: could not open file %s\n", full_path);
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
    strcpy(operation, uid);
    strcat(operation, " ");
    strcat(operation, fop);
    strcat(operation, " ");
    strcat(operation, filename);

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

    char tid_file_prefix[TID_SIZE+1];
    memset(tid_file_prefix, EOS, TID_SIZE+1);
    sprintf(tid_file_prefix, "_%04d", tid_number);

    get_user_file_path(&path, uid, tid_file_prefix, FILE_EXTENSION);

    while (fopen(path, "r")) { // file exists
        memset(tid_file_prefix, EOS, TID_SIZE+1);
        sprintf(tid_file_prefix, "_%04d", ++tid_number);
        free(path);
        get_user_file_path(&path, uid, tid_file_prefix, FILE_EXTENSION);
    }
    printf("tid=%d\n", tid_number);

    // opens the password file
    if (!(userfd = fopen(path, "w"))) {
        fprintf(stderr, "Error: could not open file %s\n", path);
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

Boolean get_user_file_path(char** path, char* uid, const char* file_name, const char* file_extension) {
    char* filename = NULL, *directory = NULL;
    Boolean return_value = true;

    // allocates memory for the password file for the user with uid
    int filename_size = strlen(uid) + strlen(file_name) + strlen(file_extension);
    if (!(filename = (char *) malloc(sizeof(char) * filename_size))){
        perror("Error: allocating \"filename\" buffer");
        return_value = false;
    }

    get_filename(filename, uid, file_name, file_extension);

    // allocates memory for the relative path for the user with uid
    if (!(directory = (char *) malloc(sizeof(char) * (strlen(users_directory) + strlen(uid) + 2)))) {
        perror("Error: allocating \"path\" buffer");
        return_value = false;
    }

    get_user_directory(directory, uid);

    // allocates memory for full relative path to the password file for the user with uid
    if (!(*path = (char *) malloc(sizeof(char)*(strlen(directory) + strlen(filename))))) {
        perror("Error: allocating \"path\" buffer");
        return_value = false;
    }

    memset(*path, EOS, strlen(directory) + strlen(filename));

    strcat(*path, directory);
    strcat(*path, filename);

    free(directory);
    free(filename);

    return return_value;
}
