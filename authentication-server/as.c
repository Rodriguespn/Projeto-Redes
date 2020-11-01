#include "as.h"

// the buffer where ASport is stored
char *asport;
const char *users_directory = USERS_FOLDER_NAME;
FILE *userfd; 
struct stat st = {0};

int main(int argc, char const *argv[])
{
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

        printf("timeout time: %ld and %ld\n", timeout.tv_sec, timeout.tv_usec);
        printf("counter = %d\n", out_fds);

        switch (out_fds) {
        case 0:
            printf("Timeout event\n");
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
            char rid[TID_SIZE], fop[FOP_SIZE];

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

                while (n) { // until the socket disconnects
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
                            process_request_request(buffer, uid, rid, fop);
                            /*memset(buffer, EOS, SIZE);
                            strcpy(buffer, "REQ not implemented yet\n");*/
                        } else {
                            prepare_error_message(buffer);
                        } 
                    } else {
                        prepare_error_message(buffer);
                    }
                    
                    n = tcp_write(connectfd, buffer);
                    printf("Message sent to tcp client: ");
                    puts(buffer);
                }
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
        if (register_user(uid, password, pdip, pdport)) {
            prepare_ok_message(buffer, REG_RESPONSE);
        } else {
            prepare_nok_message(buffer, REG_RESPONSE);
        }
    } else {
        prepare_error_message(buffer);
    }
}

void process_unregistration_request(char* buffer, char* uid, char* password) {
    if (parse_unregister_message(uid, password)) {
        printf("uid=%s\npassword=%s\n", uid, password);
        if (unregister_user(uid, password)) {
            prepare_ok_message(buffer, UNR_RESPONSE);
        } else {
            prepare_nok_message(buffer, UNR_RESPONSE);
        }
    } else {
        prepare_error_message(buffer);
    }
}

void process_login_request(char* buffer, char* uid, char* password) {
    if (parse_login_message(uid, password)) {
        if (login_user(uid, password)) {
            prepare_ok_message(buffer, LOG_RESPONSE); 
        }
        else {
            prepare_nok_message(buffer, LOG_RESPONSE);
        }
    } else {
    prepare_error_message(buffer);
    } 
}

void process_request_request(char* buffer, char* uid, char* rid, char* fop) {
    char filename[SIZE];
    if (parse_request_message(uid, rid, fop, filename)) {
        int code = request_user(uid, fop, filename);
        prepare_request_message(buffer, code);
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
    strcpy(buffer, PD_NOT_AVAILABLE);
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
        case PD_SENT_ERR_MSG_ERR_CODE:
            prepare_pd_error_message(buffer);
            break;

        default:
            prepare_ok_message(buffer, REQ_RESPONSE);
            break;
    }
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
    if (!valid_uid(token)) {
        fprintf(stderr, "Invalid user!\n");
        return false;
    }
    strcpy(uid, token);

    token = strtok(NULL, " ");
    if (!valid_password(token)) {
        fprintf(stderr, "Invalid password!\n");
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
        if (strlen(password) > PASSWORD_SIZE || !only_numbers_or_letters(password)) {
            fprintf(stderr, "Invalid password!\nThe password must have 8 numbers and/or letters\n");
            return false;
        }
        return true;
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

void get_user_directory(char* buffer, char *uid) {

    memset(buffer, EOS, strlen(buffer));
    strcat(buffer, "./");
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

Boolean register_user(char* uid, char* password, char* ip, char* port) {
    char* filename = NULL;
    char* directory = NULL;
    char* full_path; // users_directory/uid/file

    // allocates memory for the password file for the user with uid
    int filename_size = strlen(uid) + strlen(PASSWORD_FILE_PREFIX) + strlen(FILE_EXTENSION);
    if (!(filename = (char *) malloc(sizeof(char)*filename_size))){
            perror("Error: allocating \"filename\" buffer");
            exit(EXIT_FAILURE);
    }

    get_filename(filename, uid, PASSWORD_FILE_PREFIX, FILE_EXTENSION);

    // allocates memory for the relative path for the user with uid
    if (!(directory = (char *) malloc(sizeof(char)*(strlen(users_directory)+ strlen(uid) + 2)))) {
        perror("Error: allocating \"path\" buffer");
        exit(EXIT_FAILURE);
    }

    get_user_directory(directory, uid);

    // allocates memory for full relative path to the password file for the user with uid
    if (!(full_path = (char *) malloc(sizeof(char)*(strlen(directory) + strlen(filename))))) {
        perror("Error: allocating \"path\" buffer");
        exit(EXIT_FAILURE);
    }

    strcat(full_path, directory);
    strcat(full_path, filename);

    // check if the directory is created or not 
    if (stat(directory, &st) == ERROR) { // if directory doesn t exists
        if (mkdir(directory, 0777)) { 
            printf("Unable to create directory \"%s\"\n", directory); 
            exit(EXIT_FAILURE); 
        }

        // opens the password file
        if (!(userfd = fopen(full_path, "w"))) {
            fprintf(stderr, "Error: could not open file %s\n", filename);
            exit(EXIT_FAILURE);
        }

        // writes the password on the file
        fprintf(userfd, "%s\n", password);

        // closes the password file
        fclose(userfd);
    } else { // the user already exists
        //fprintf(stderr, "Error: the user %s already exits\n", uid);
        printf("path = %s\n", full_path);

        // opens the password file
        if (!(userfd = fopen(full_path, "r"))) {
            fprintf(stderr, "Error: could not open file %s\n", filename);
            exit(EXIT_FAILURE);
        }
        char password_from_file[PASSWORD_SIZE];
        // reads the password from the file
        fscanf(userfd, "%s\n", password_from_file);
        printf("password_from_file=%s\n", password_from_file);

        if (strcmp(password, password_from_file)) {
            fprintf(stderr, "Error: wrong uid or password\n");
            return false;
        }

        // closes the password file
        fclose(userfd);
    }

    // clears the full_path and filename memory
    memset(full_path, EOS, strlen(full_path));

    filename_size = strlen(uid) + strlen(REGISTRATION_FILE_PREFIX) + strlen(FILE_EXTENSION);
    // allocates memory for the registration file for the user with uid
    if (!(filename = (char *) realloc(filename, sizeof(char)*filename_size))){
        perror("Error: allocating \"filename\" buffer");
        exit(EXIT_FAILURE);
    }

    get_filename(filename, uid, REGISTRATION_FILE_PREFIX, FILE_EXTENSION);

    printf("registration_filename = %s\n", filename);

    strcat(full_path, directory);
    strcat(full_path, filename);

    printf("path = %s\n", full_path);

    // opens the registration file
    if (!(userfd = fopen(full_path, "w"))) {
        fprintf(stderr, "Error: could not open file %s\n", filename);
        exit(EXIT_FAILURE);
    }

    // writes the ip and the port like "ip:port"
    fprintf(userfd, "%s", ip);
    fprintf(userfd, "%s", ":");
    fprintf(userfd, "%s\n", port);

    // closes the registration file
    fclose(userfd);

    free(filename);
    free(directory);
    free(full_path);

    return true;
}

Boolean unregister_user(char *uid, char *password) {
    char* filename = NULL;
    char* directory = NULL;
    char* full_path; // users_directory/uid/file

    // allocates memory for the password file for the user with uid
    int filename_size = strlen(uid) + strlen(PASSWORD_FILE_PREFIX) + strlen(FILE_EXTENSION);
    if (!(filename = (char *) malloc(sizeof(char)*filename_size))){
            perror("Error: allocating \"filename\" buffer");
            exit(EXIT_FAILURE);
    }

    get_filename(filename, uid, PASSWORD_FILE_PREFIX, FILE_EXTENSION);

    // allocates memory for the relative path for the user with uid
    if (!(directory = (char *) malloc(sizeof(char)*(strlen(users_directory)+ strlen(uid) + 2)))) {
        perror("Error: allocating \"path\" buffer");
        exit(EXIT_FAILURE);
    }

    get_user_directory(directory, uid);

    // allocates memory for full relative path to the password file for the user with uid
    if (!(full_path = (char *) malloc(sizeof(char)*(strlen(directory) + strlen(filename))))) {
        perror("Error: allocating \"path\" buffer");
        exit(EXIT_FAILURE);
    }

    strcat(full_path, directory);
    strcat(full_path, filename);

    printf("path = %s\n", full_path);

    // opens the password file
    if (!(userfd = fopen(full_path, "r"))) {
        fprintf(stderr, "Error: could not open file %s\n", filename);
        exit(EXIT_FAILURE);
    }

    char password_from_file[PASSWORD_SIZE];
    // reads the password from the file
    fscanf(userfd, "%s\n", password_from_file);
    printf("password_from_file=%s\n", password_from_file);

    if (strcmp(password, password_from_file)) {
        fprintf(stderr, "Error: wrong uid or password\n");
        return false;
    }

    // closes the password file
    fclose(userfd);

    // clears the full_path and filename memory
    memset(full_path, EOS, strlen(full_path));

    filename_size = strlen(uid) + strlen(REGISTRATION_FILE_PREFIX) + strlen(FILE_EXTENSION);
    // allocates memory for the registration file for the user with uid
    if (!(filename = (char *) realloc(filename, sizeof(char)*filename_size))){
        perror("Error: allocating \"filename\" buffer");
        exit(EXIT_FAILURE);
    }

    get_filename(filename, uid, REGISTRATION_FILE_PREFIX, FILE_EXTENSION);

    printf("registration_filename = %s\n", filename);

    strcat(full_path, directory);
    strcat(full_path, filename);

    printf("path = %s\n", full_path);

    if (remove(full_path)) {
        fprintf(stderr, "Error: could not remove file %s\n", filename);
        exit(EXIT_FAILURE);
    };

    free(filename);
    free(directory);
    free(full_path);

    return true;
}

Boolean login_user(char* uid, char* password) {
    char* filename = NULL;
    char* directory = NULL;
    char* full_path; // users_directory/uid/file

    // allocates memory for the password file for the user with uid
    int filename_size = strlen(uid) + strlen(PASSWORD_FILE_PREFIX) + strlen(FILE_EXTENSION);
    if (!(filename = (char *) malloc(sizeof(char)*filename_size))){
            perror("Error: allocating \"filename\" buffer");
            exit(EXIT_FAILURE);
    }

    get_filename(filename, uid, PASSWORD_FILE_PREFIX, FILE_EXTENSION);

    // allocates memory for the relative path for the user with uid
    if (!(directory = (char *) malloc(sizeof(char)*(strlen(users_directory)+ strlen(uid) + 2)))) {
        perror("Error: allocating \"path\" buffer");
        exit(EXIT_FAILURE);
    }

    get_user_directory(directory, uid);

    // check if the directory is created or not 
    if (stat(directory, &st) == ERROR) { // if directory doesn't exists
        fprintf(stderr, "Error: user was not registered\n");
        return false;
    }

    // allocates memory for full relative path to the password file for the user with uid
    if (!(full_path = (char *) malloc(sizeof(char)*(strlen(directory) + strlen(filename))))) {
        perror("Error: allocating \"path\" buffer");
        exit(EXIT_FAILURE);
    }

    strcat(full_path, directory);
    strcat(full_path, filename);

    printf("path = %s\n", full_path);

    // opens the password file
    if (!(userfd = fopen(full_path, "r"))) {
        fprintf(stderr, "Error: could not open file %s\n", filename);
        exit(EXIT_FAILURE);
    }

    char password_from_file[PASSWORD_SIZE];
    // reads the password from the file
    fscanf(userfd, "%s\n", password_from_file);
    printf("password_from_file=%s\n", password_from_file);

    if (strcmp(password, password_from_file)) {
        fprintf(stderr, "Error: wrong uid or password\n");
        return false;
    }

    // closes the password file
    fclose(userfd);

    // clears the full_path and filename memory
    memset(full_path, EOS, strlen(full_path));

    filename_size = strlen(uid) + strlen(REGISTRATION_FILE_PREFIX) + strlen(FILE_EXTENSION);
    // allocates memory for the registration file for the user with uid
    if (!(filename = (char *) realloc(filename, sizeof(char)*filename_size))){
        perror("Error: allocating \"filename\" buffer");
        exit(EXIT_FAILURE);
    }

    get_filename(filename, uid, LOGIN_FILE_PREFIX, FILE_EXTENSION);

    printf("registration_filename = %s\n", filename);

    strcat(full_path, directory);
    strcat(full_path, filename);

    // opens the password file
    if (!(userfd = fopen(full_path, "w"))) {
        fprintf(stderr, "Error: could not open file %s\n", filename);
        exit(EXIT_FAILURE);
    }

    // writes the uid and the password on the file
    fprintf(userfd, "%s:%s\n", uid, password);
    // closes the password file
    fclose(userfd);

    free(filename);
    free(directory);
    free(full_path);
    return true;
}

int request_user(char* uid, char* fop, char* filename) {
    // if the uid is invalid
    if (!valid_uid(uid)) {
        return INVALID_UID_ERR_CODE;
    }

    // if the fop is not valid
    if (!valid_fop(fop)) {
        return INVALID_FOP_ERR_CODE;
    }

    // if the PD doesn't respond
    // por implementar
    return USER_REQUEST_OK;
}
