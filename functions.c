#include "functions.h"

// Handler for SIGINT, caused by 
// Ctrl-C at keyboard 
void handler_sigint() { 
    printf("\nGoodbye...\n");
    exit(EXIT_SUCCESS);
}

// reads a paragraph from the stdin
void read_stdin(char* buffer) {
    char c;
    int i = 0;
    for (;(c=getchar())!='\n'; i++) {
        buffer[i] = c;
    }
    buffer[i] = EOS;
}

// parses the PDport value, given with the PD_PORT flag
// if no port given, sets the default value of 57000+GN
void parse_pd_port(const char* argv[], int size, char** pdport) {
    Boolean flag = false;
    for(int i = 0; i < size; ++i) {   
        if (!strcmp(argv[i], PD_PORT_FLAG)) {
            if (!(*pdport = (char *) malloc(sizeof(char)*strlen(argv[i+1])))) {
                perror("Error: allocating \"PDport\" buffer");
                exit(EXIT_FAILURE);
            }
            strcpy(*pdport, argv[i+1]);
            flag = true;
            break;
        }
    }
    if (!flag) {
        if (!(*pdport = (char *) malloc(sizeof(char)*5))) {
                perror("Error: allocating \"PDport\" buffer");
                exit(EXIT_FAILURE);
        }

        int port = PDPORT+GN;
        sprintf(*pdport, "%d", port);
    }

}

// parses the ASIP value, given with the AS_IP flag
// if no ip given, sets the default value equals to DEFAULTIP
void parse_as_ip(const char* argv[], int size, char* defaultip, char** asip) {
    Boolean flag = false;
    for(int i = 0; i < size; ++i) {   
        if (!strcmp(argv[i], AS_IP_FLAG)) {
            if (!(*asip = (char *) malloc(sizeof(char)*strlen(argv[i+1])))) {
                perror("Error: allocating \"PDport\" buffer");
                exit(EXIT_FAILURE);
            }
            strcpy(*asip, argv[i+1]);
            flag = true;
            break;
        }
    }
    if (!flag) {
        if (!(*asip = (char *) malloc(sizeof(char)*strlen(defaultip)))) {
                perror("Error: allocating \"PDport\" buffer");
                exit(EXIT_FAILURE);
        }
        strcpy(*asip, defaultip);
    }
}


// parses the ASport value, given with the AS_PORT flag
// if no port given, sets the default value of 58000+GN
void parse_as_port(const char* argv[], int size, char** asport) {
    Boolean flag = false;
    for (int i = 0; i < size; ++i) {   
        if (!strcmp(argv[i], AS_PORT_FLAG)) {
            if (!(*asport = (char *) malloc(sizeof(char)*strlen(argv[i+1])))) {
                perror("Error: allocating \"PDport\" buffer");
                exit(EXIT_FAILURE);
            }
            strcpy(*asport, argv[i+1]);
            flag = true;
            break;
        }
    }
    if (!flag) {
        if (!(*asport = (char *) malloc(sizeof(char)*5))) {
                perror("Error: allocating \"PDport\" buffer");
                exit(EXIT_FAILURE);
        }

        int port = ASPORT+GN;
        sprintf(*asport, "%d", port);
    }
}

// parses the FSport value, given with the FS_PORT flag
// if no port given, sets the default value of 59000+GN
void parse_fs_port(const char* argv[], int size, char** fsport) {
    Boolean flag = false;
    for (int i = 0; i < size; ++i) {   
        if (!strcmp(argv[i], FS_PORT_FLAG)) {
            if (!(*fsport = (char *) malloc(sizeof(char)*strlen(argv[i+1])))) {
                perror("Error: allocating \"PDport\" buffer");
                exit(EXIT_FAILURE);
            }
            strcpy(*fsport, argv[i+1]);
            flag = true;
            break;
        }
    }
    if (!flag) {
        if (!(*fsport = (char *) malloc(sizeof(char)*5))) {
                perror("Error: allocating \"PDport\" buffer");
                exit(EXIT_FAILURE);
        }

        int port = FSPORT+GN;
        sprintf(*fsport, "%d", port);
    }
}

// parses the FSIP value, given with the FS_IP flag
// if no ip given, sets the default value equals to DEFAULTIP
void parse_fs_ip(const char* argv[], int size, char* defaultip, char** fsip) {
    Boolean flag = false;
    for(int i = 0; i < size; ++i) {   
        if (!strcmp(argv[i], FS_IP_FLAG)) {
            if (!(*fsip = (char *) malloc(sizeof(char)*strlen(argv[i+1])))) {
                perror("Error: allocating \"PDport\" buffer");
                exit(EXIT_FAILURE);
            }
            strcpy(*fsip, argv[i+1]);
            flag = true;
            break;
        }
    }
    if (!flag) {
        if (!(*fsip = (char *) malloc(sizeof(char)*strlen(defaultip)))) {
                perror("Error: allocating \"PDport\" buffer");
                exit(EXIT_FAILURE);
        }
        strcpy(*fsip, defaultip);
    }
}

int tcp_write(int sockfd, char* buffer) {
    int n = write(sockfd, buffer, strlen(buffer));
    if (n == ERROR) {
            //error
            fprintf(stderr, "Error: could not write \"%s\"\nTo sockfd = %d\n", buffer, sockfd);
            return false;
    }
    return n;
}

int tcp_read(int sockfd, char* buffer, int size) {
    int n = read(sockfd, buffer, size);
    if (n == ERROR) {
        //error
        fprintf(stderr, "Error: could not read from sockfd = %d\n", sockfd);
        return false;
    }
    return n;
}

int udp_write(int sockfd, char* buffer, struct sockaddr *addr, socklen_t addrlen) {
    printf("%s\n", buffer);
    int n = sendto(sockfd, buffer, strlen(buffer), 0, addr,  addrlen);
    if (n == ERROR) {
        //error
        fprintf(stderr, "Error: sendto returned %d error code\n", ERROR);
        return false;
    }
    return n;
}

int udp_read(int sockfd, char* buffer, int size, struct sockaddr* addr) {
    socklen_t addrlen = sizeof(addr);
    int n = recvfrom (sockfd, buffer, size, 0, addr, &addrlen);
    if(n == ERROR) {
        //error
        fprintf(stderr, "Error: recvfrom returned %d error code\n", ERROR);
        return false;
    }

    return n;
}