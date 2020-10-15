#include "as.h"

// the buffer where ASport is stored
char* asport;

int main(int argc, char const *argv[])
{
    int fd, errcode;
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

    signal(SIGINT, handler_sigint);

    // parses the argv arguments
    parse_arguments(argv, argc);

    printf("ASport=%s\n", asport);

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    if(fd == ERROR) 
        /*error*/
        exit(EXIT_FAILURE);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_DGRAM; // UDP socket
    hints.ai_flags = AI_PASSIVE;

    errcode = getaddrinfo(NULL, asport, &hints, &res);

    if (errcode != 0) 
        /*error*/ 
        fprintf(stderr, "Error: getaddrinfo returned %d error code\n", errcode);
        exit(EXIT_FAILURE);

    n = bind(fd, res -> ai_addr, res -> ai_addrlen);
    if (n == ERROR) 
        /*error*/
        fprintf(stderr, "Error: bind returned %d error code\n", n);
        exit(EXIT_FAILURE);

    while (true) {
        addrlen = sizeof(addr);
        n = recvfrom(fd, buffer, SIZE, 0, (struct sockaddr*) &addr, &addrlen);
        if (n == ERROR)
            /*error*/
            exit(EXIT_FAILURE);
        
        write(STDOUT, "received: ", 10);
        write(STDOUT, buffer, n);

        n = sendto(fd, buffer, n, 0, (struct sockaddr*) &addr, addrlen);
        if (n == ERROR)
            /*error*/
            exit(EXIT_FAILURE);
    }

    freeaddrinfo(res);
    close (fd);

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

// parses the arguments given on the command line
void parse_arguments(const char* argv[], int size) {
    asport = parse_as_port(argv, size);
}
