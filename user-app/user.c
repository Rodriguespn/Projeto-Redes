#include "user.h"

/*TODO: encontrar userIP*/
char *asip, *asport, *fsip, *fsport;

int main(int argc, char const *argv[])
{
    int fd, errcode;
    ssize_t n;
    socklen_t addrlen;
    struct addrinfo hints, *res;
    struct sockaddr_in addr;
    char buffer[SIZE];

    // checks if the number of arguments is correct
    if (wrong_arguments(argc))
    {
        usage();
        exit(EXIT_FAILURE);
    }

    // parses the argv arguments
    parse_arguments(argv, argc);

    printf("ASIP=%s\n", asip);
    printf("ASport=%s\n", asport);
    printf("FSIP=%s\n", fsip);
    printf("FSport=%s\n\n", fsport);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == ERROR)
        exit(EXIT_FAILURE); //error

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    errcode = getaddrinfo(asip, asport, &hints, &res);
    if (errcode != 0) {
        //error
        fprintf(stderr, "Error: could not get address info\n");
        exit(EXIT_FAILURE);
    }

    //TCP socket
    //IPv4
    //TCP socket

    n = connect(fd, res->ai_addr, res->ai_addrlen);
    if (n == ERROR) {
        //error
        fprintf(stderr, "Error: could not connect\n");
        exit(EXIT_FAILURE);
    }

    n = write(fd, "LOG 12346 password\n", strlen("LOG 12346 password\n"));
    if (n == ERROR) {
        //error
        fprintf(stderr, "Error: could not write.\n");
        exit(EXIT_FAILURE);
    }


    n = read(fd, buffer, SIZE);
    if (n == ERROR) {
        //error
        fprintf(stderr, "Error: could not read.\n");
        exit(EXIT_FAILURE);
    }

    write(STDOUT, "response: ", 10);
    write(STDOUT, buffer, n);
    

    freeaddrinfo(res);
    close(fd);

    exit(EXIT_SUCCESS);
}

void usage()
{
    printf("usage: ./user [-n ASIP] [-p ASport] [-m FSIP] [-q FSport]\n");
    printf("example: ./user -n 193.136.138.142 -p 58011 -m 193.136.138.142 -q 59000\n");
    //alterar exemplo flag -m
}

int wrong_arguments(int argc)
{
    return !(argc > 0 && argc % 2 == 1 && argc <= 9);
}

// parses the arguments given on the command line
void parse_arguments(const char *argv[], int size)
{
    asip = parse_as_ip(argv, size, LOCALHOST);
    asport = parse_as_port(argv, size);
    fsip = parse_fs_ip(argv, size, LOCALHOST);
    fsport = parse_fs_port(argv, size);
}
