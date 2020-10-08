#include "as.h"

// the buffer where ASport is stored
char* asport;

int main(int argc, char const *argv[])
{
    /*int fd, errcode;
    ssize_t n;
    socklen_t addrlen;
    struct addrinfo hints,*res;
    struct sockaddr_in addr;
    char buffer[SIZE];*/
    
    // checks if the number of arguments is correct
    if (wrong_arguments(argc)) {
        usage();
        exit(EXIT_FAILURE);
    }

    // parses the argv arguments
    parse_arguments(argv, argc);

    printf("ASport=%s\n\n", asport);

    exit(EXIT_SUCCESS);
}

// diplays a message with the correct usage of the file
void usage() {
    printf("usage: ./as [-p ASport] [-v]\n");
    printf("example: ./as -p 58000 -v\n");
}

// returns true if the arguments given on the command line are on an invalid format, and false otherwise
int wrong_arguments(int argc) {
    return argc != 1 && argc != 3 && argc != 4;
}

// parses the arguments given on the command line
void parse_arguments(const char* argv[], int size) {
    parse_as_port(argv, size, asport);
}
