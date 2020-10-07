#include "pd.h"

// the buffers where
// PDIP, PDport, ASIP, ASport are stored
char *pdip, *pdport, *asip, *asport;

int main(int argc, char const *argv[]) {
    int fd,errcode;
    ssize_t n;
    socklen_t addrlen;
    struct addrinfo hints,*res;
    struct sockaddr_in addr;
    char buffer[SIZE];
    
    // checks if the number of arguments is correct
    if (wrong_arguments(argc)) {
        usage();
        exit(EXIT_FAILURE);
    }

    // parses the argv arguments
    parse_arguments(argv, argc);

    printf("\nPDIP=%s\n", pdip);
    printf("PDport=%s\n", pdport);
    printf("ASIP=%s\n", asip);
    printf("ASport=%s\n\n", asport);
    
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
    errcode = getaddrinfo(IP, asport, &hints, &res);
    if(errcode != 0) {
        //error
        fprintf(stderr, "Error: getaddrinfo returned %d error code\n", errcode);
        exit(EXIT_FAILURE);
    }

    char command[SIZE], uid[SIZE], password[SIZE];
    memset(buffer, EOS, SIZE);
    memset(command, EOS, SIZE);
    memset(uid, EOS, SIZE);
    memset(password, EOS, SIZE);

    read_stdin(buffer);
    parse_register_message(buffer, command, uid, password);

    memset(buffer, EOS, SIZE);
    prepare_request(buffer, command, uid, password);

    printf("message sent: %s", buffer);

    // sends REG command
    n = sendto(fd, buffer, strlen(buffer), 0, res -> ai_addr, res -> ai_addrlen);
    if (n == ERROR) {
        //error
        fprintf(stderr, "Error: sendto returned %d error code\n", ERROR);
        exit(EXIT_FAILURE);
    }

    addrlen = sizeof(addr);
    n = recvfrom (fd, buffer, SIZE, 0, (struct sockaddr*) &addr, &addrlen);
    if(n == ERROR) {
        //error
        fprintf(stderr, "Error: recvfrom returned %d error code\n", ERROR);
        exit(EXIT_FAILURE);
    }

    write(1, "response: ", 10);
    write(1, buffer, n);

    do {
        memset(buffer, EOS, SIZE);
        read_stdin(buffer);

        parse_exit_message(buffer, command); 
        memset(buffer, EOS, SIZE);
        prepare_request(buffer, command, uid, password);

        printf("message sent: %s", buffer);

        // sends REG command
        n = sendto(fd, buffer, strlen(buffer), 0, res -> ai_addr, res -> ai_addrlen);
        if (n == ERROR) {
            //error
            fprintf(stderr, "Error: sendto returned %d error code\n", ERROR);
            exit(EXIT_FAILURE);
        }

        addrlen = sizeof(addr);
        n = recvfrom (fd, buffer, SIZE, 0, (struct sockaddr*) &addr, &addrlen);
        if(n == ERROR) {
            //error
            fprintf(stderr, "Error: recvfrom returned %d error code\n", ERROR);
            exit(EXIT_FAILURE);
        }

        write(1, "response: ", 10);
        write(1, buffer, n);
    } while (strcmp(command, PD_EXIT));

    freeaddrinfo(res);

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
    printf("example: ./pd 10.0.2.15 -d 57000 -n 193.136.138.142 -p 58000\n");
}

void read_stdin(char* buffer) {
    // reads a line from the stdin
    char c;
    int i = 0;
    for (;(c=getchar())!='\n'; i++) {
        buffer[i] = c;
    }
    buffer[i] = EOS;
}

// parses the register command
void parse_register_message(char* buffer, char* command, char* uid, char* password) {
    char *token;

    if(!(token = strtok(buffer, " "))) {
        fprintf(stderr, "Command missing!\nMust give a command\n");
        exit(EXIT_FAILURE);
    }
    strcpy(command, token);

    token = strtok(NULL, " ");
    if (!valid_uid(token)) {
        exit(EXIT_FAILURE);
    }
    strcpy(uid, token);

    token = strtok(NULL, " ");
    if (!valid_password(token)) {
        exit(EXIT_FAILURE);
    }
    strcpy(password, token);

    printf("command: %s\tuid: %s\tpassword: %s\n", command, uid, password);
    printf("buffer: %s\n", buffer);
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

// returns true if the uid only contains numbers
// false otherwise
enum boolean all_numbers(char* uid) {
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
enum boolean valid_uid(char* uid) {
    if (uid) {
        if (strlen(uid) > UID_SIZE || !all_numbers(uid)) {
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
enum boolean only_numbers_or_letters(char* password) {
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
enum boolean valid_password(char* password) {
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

void prepare_request(char* request, char* command, char* uid, char* password) {

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
        exit(EXIT_FAILURE);
    }
    
    strcat(request, "\n");
}

// parses the arguments given on the command line
void parse_arguments(const char* argv[], int size) {
    if (!(pdip = (char *) malloc(sizeof(char)*strlen(argv[1])))){
        perror("Error: allocating \"port\" buffer");
        exit(EXIT_FAILURE);
    }

    strcpy(pdip, argv[1]);

    parse_pd_port(argv, size);
    parse_as_ip(argv, size);
    parse_as_port(argv, size);
}

// parses the PDport value, given with the PD_PORT flag
// if no port given, sets the default value of 57000+GN
void parse_pd_port(const char* argv[], int size) {
    for(int i = 0; i < size; ++i) {   
        if (!strcmp(argv[i], PD_PORT_FLAG)) {
            if (!(pdport = (char *) malloc(sizeof(char)*strlen(argv[i+1])))) {
                perror("Error: allocating \"PDport\" buffer");
                exit(EXIT_FAILURE);
            }
            strcpy(pdport, argv[i+1]);
            break;
        }
    }
    if (!pdport) {
        if (!(pdport = (char *) malloc(sizeof(char)*5))) {
                perror("Error: allocating \"PDport\" buffer");
                exit(EXIT_FAILURE);
        }

        int port = PDPORT+GN;
        sprintf(pdport, "%d", port);
    }
}


// parses the ASIP value, given with the -n flag
// if no ip given, sets the default value equals to PDIP
void parse_as_ip(const char* argv[], int size) {
    for(int i = 0; i < size; ++i) {   
        if (!strcmp(argv[i], AS_IP_FLAG)) {
            if (!(asip = (char *) malloc(sizeof(char)*strlen(argv[i+1])))) {
                perror("Error: allocating \"PDport\" buffer");
                exit(EXIT_FAILURE);
            }
            strcpy(asip, argv[i+1]);
            break;
        }
    }
    if (!asip) {
        if (!(asip = (char *) malloc(sizeof(char)*strlen(pdip)))) {
                perror("Error: allocating \"PDport\" buffer");
                exit(EXIT_FAILURE);
        }
        strcpy(asip, pdip);
    }
}


// parses the ASport value, given with the AS_PORT flag
// if no port given, sets the default value of 58000+GN
void parse_as_port(const char* argv[], int size) {
    for (int i = 0; i < size; ++i) {   
        if (!strcmp(argv[i], AS_PORT_FLAG)) {
            if (!(asport = (char *) malloc(sizeof(char)*strlen(argv[i+1])))) {
                perror("Error: allocating \"PDport\" buffer");
                exit(EXIT_FAILURE);
            }
            strcpy(asport, argv[i+1]);
            break;
        }
    }
    if (!asport) {
        if (!(asport = (char *) malloc(sizeof(char)*5))) {
                perror("Error: allocating \"PDport\" buffer");
                exit(EXIT_FAILURE);
        }

        int port = ASPORT+GN;
        sprintf(asport, "%d", port);
    }
}
