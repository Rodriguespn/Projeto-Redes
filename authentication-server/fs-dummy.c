#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "../constants.h"
#include "../functions.h"

void parse_arguments(const char *argv[], int size);

char *asip, *asport;

int main(int argc, char const *argv[]) {
    int fd, errcode;
    ssize_t n;
    struct addrinfo hints, *res;
    struct sockaddr_in addr;
    char buffer[SIZE];

    // parses the argv arguments
    parse_arguments(argv, argc);

    printf("FSIP=%s\n", asip);
    printf("FSport=%s\n", asport);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == ERROR) {
        //error
        fprintf(stderr, "Error: socket returned null\n");
        exit(EXIT_FAILURE);
    }
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    // gets the address info
    errcode = getaddrinfo(asip, asport, &hints, &res);
    if (errcode != 0) {
        //error
        fprintf(stderr, "Error: getaddrinfo returned %d error code\n", errcode);
        exit(EXIT_FAILURE);
    }

    //UDP socket
    //IPv4
    //UDP socket

    
    char command[SIZE], uid[SIZE], password[SIZE], login_success[SIZE];
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
        memset(buffer, EOS, SIZE);
        read_stdin(buffer);

        printf("request: %s\n", buffer);
        printf("socket = %d\n", fd);
        n = tcp_write(fd, buffer);

        if (!n) continue;
        
        memset(buffer, EOS, SIZE);
        n = tcp_read(fd, buffer, SIZE);

        printf("response: %s\n", buffer);
    } while (n); //strcmp(buffer, unregistration_success));

    freeaddrinfo(res);
    free(asip);
    free(asport);
    close(fd);

    exit(EXIT_SUCCESS);
}

// parses the arguments given on the command line
void parse_arguments(const char *argv[], int size) {
    parse_fs_ip(argv, size, LOCALHOST, &asip);
    parse_fs_port(argv, size, &asport);
}
