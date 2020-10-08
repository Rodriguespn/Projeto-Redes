#include "as.h"

int main(int argc, char const *argv[])
{
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
    exit(EXIT_SUCCESS);
}

// diplays a message with the correct usage of the file
void usage() {
    printf("usage: ./as [-p ASport] [-v]\n");
    printf("example: ./as -p 58000 -v\n");
}

// returns true if the arguments given on the command line are on an invalid format, and false otherwise
int wrong_arguments(int argc) {
    return !(argc > 0 && argc <= 3);
}