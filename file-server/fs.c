#include "fs.h"

// +------------------------------------------+
// | Global Variables                         |
// +------------------------------------------+
char *fsip, *fsport, *asip, *asport;
Boolean verbose = false;
const char *users_directory = USERS_FOLDER_NAME;
FILE *userfd; 
struct stat st = {0};

int main(int argc, char const *argv[]) {
    int udpsocket, tcpsocket, connectfd, out_fds, childpid, errcode;
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

    // prepares SIGINT signal trigger
    signal(SIGINT, handler_sigint);

    // ignores SIGCHLD signals
    if((old_handler = signal(SIGCHLD, SIG_IGN)) == SIG_ERR) {
        fprintf(stderr, "could not set handler to %d signal\n", SIGCHLD);
        exit(EXIT_FAILURE);
    }

    char host[256];
    char *asip;
    struct hostent *host_entry;
    int hostname;
    hostname = gethostname(host, sizeof(host)); //find the host name
    host_entry = gethostbyname(host); //find host information
    fsip = inet_ntoa(*((struct in_addr*) host_entry->h_addr_list[0])); //Convert into IP string
    
    // parses the argv arguments
    parse_arguments(argv, argc);

    // initial prints
    printf("CONFIG: Verbose flag %s\n", verbose ? "true" : "false");
    verbose_message(verbose, "CONFIG: FS is running on Host=%s IP=%s Port=%s\n", host, fsip, fsport);

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

    // prepares the commands variables
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
                    char client_ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(((struct sockaddr_in *) &cliaddr) -> sin_addr), client_ip, INET_ADDRSTRLEN);
                    verbose_message(verbose, "\nINFORM: Received UDP connection from IP=%s Port=%u\n", client_ip, ntohs((&cliaddr) -> sin_port));
                    memset(buffer, EOS, SIZE);
                    addrlen = sizeof(cliaddr);
                    n = udp_read(udpsocket, buffer, SIZE, (struct sockaddr*) &cliaddr);

                    char tid[TID_SIZE];
                    char fop[FOP_SIZE];
                    char fname[FILENAME_MAX]; 
                    memset(tid, EOS, TID_SIZE);
                    memset(fop, EOS, FOP_SIZE);
                    memset(fname, EOS, FILENAME_MAX);

                    if (parse_command(buffer, command)) {
                        if (!strcmp(command, VAL_FILE_RESPONSE)) {
                            // recebe a validacao do pedido do user e executa o pedido no fs
                            process_val_file_response(buffer, uid, tid, fop, fname);
                            verbose_message(verbose, "INFORM: Processing Command=%s UID=%s password=%s registration\n", command, uid, password);
                        } else {
                            prepare_error_message(buffer);
                            verbose_message(verbose, "INFORM: Request=%s could not be processed\n", buffer);
                        } 
                    } else {
                        prepare_error_message(buffer);
                        verbose_message(verbose, "ERROR: Request=%s with wrong format\n", buffer);
                    }

                    n = udp_write(udpsocket, buffer, (struct sockaddr*) &cliaddr, sizeof(cliaddr));
                }
             

                //  if tcp socket is ready to listen
                if (FD_ISSET(tcpsocket, &testfds)) {
                    connectfd = accept(tcpsocket, (struct sockaddr*) &cliaddr, &addrlen);
                    char client_ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(((struct sockaddr_in *) &cliaddr) -> sin_addr), client_ip, INET_ADDRSTRLEN);
                    verbose_message(verbose, "\nINFORM: Received TCP connection from IP=%s Port=%u\n", client_ip, ntohs((&cliaddr) -> sin_port));    
                    addrlen = sizeof(cliaddr);
                    char rid[TID_SIZE], fop[FOP_SIZE], *vc = NULL;

                    memset(rid, EOS, TID_SIZE);
                    memset(fop, EOS, FOP_SIZE);
                    
                    if ((childpid = fork()) == 0) {
                        // child process that will handle the conversation USER-FS
                        close(tcpsocket);
                        char login_succeeded[SIZE];
                        strcpy(login_succeeded, LOG_RESPONSE);
                        strcat(login_succeeded, " ");
                        strcat(login_succeeded, OK);
                        strcat(login_succeeded, "\n");

                    
                        memset(buffer, EOS, SIZE);
                        n = tcp_read(connectfd, buffer, SIZE);

                        if (!n) { // the client has disconnected
                            continue;
                        }

                        if (parse_command(buffer, command)) {
                            if (!strcmp(command, RETRIEVE)) {
                                process_retrieve_file_request(buffer, uid, password);
                                verbose_message(verbose, "INFORM: Processing Command=%s UID=%s password=%s login\n", command, uid, password);
                            } else if (!strcmp(command, UPLOAD)) {
                                process_upload_file_request(buffer);
                                verbose_message(verbose, "INFORM: Request=%s could not be processed without login\n", buffer);
                            } else if (!strcmp(command, DELETE)) {
                                process_delete_file_request(buffer);
                                verbose_message(verbose, "INFORM: Request=%s could not be processed without login\n", buffer);
                            } else if (!strcmp(command, REMOVE)) {
                                process_not_logged_in_message(buffer);
                                verbose_message(verbose, "INFORM: Request=%s could not be processed without login\n", buffer);
                            } else {
                                prepare_error_message(buffer);
                                verbose_message(verbose, "INFORM: Request=%s is invalid", buffer);
                            } 
                        } else {
                            prepare_error_message(buffer);
                        }

                        n = tcp_write(connectfd, buffer);
            
                    } else if (childpid == ERROR) {
                        fprintf(stderr, "ERROR: could not create child process for tcp connection");
                        exit(EXIT_FAILURE);
                    }
                    close(connectfd);
                }
            break;
        }
    }

    freeaddrinfo(res);
    close (udpsocket);

    exit(EXIT_SUCCESS);
}

// +------------------------------------------+
// | Arguments Functions                      |
// +------------------------------------------+

// diplays a message with the correct usage of the file
void usage() {
    printf("usage: ./as [-p ASport] [-v]\n");
    printf("example: ./as -p 58011 -v\n");
}

// returns true if the arguments given on the command line are on an invalid format, and false otherwise
int wrong_arguments(int argc) {
    return !(argc >= 1 && argc <= 8);
}

// parses the arguments given on the command line
void parse_arguments(const char* argv[], int size) {
    parse_fs_port(argv, size, &fsport);
    parse_as_ip(argv, size, fsip, &asip);
    parse_as_port(argv, size, &asport);
    verbose = parse_verbose_flag(argv, size);
}

// parses next command from the buffer
Boolean parse_command(char* buffer, char* command) {
    char *token;

    if(!(token = strtok(buffer, " "))) {
        fprintf(stderr, "wrong command!\n");
        return false;
    }
    strcpy(command, token);
    return true;
}
