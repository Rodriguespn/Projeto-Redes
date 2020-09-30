#include "pd.h"

char *pdip, *pdport, *asip, *asport;

int main(int argc, char const *argv[]) {
    /*int fd,errcode;
    ssize_t n;
    socklen_t addrlen;
    struct addrinfo hints,*res;
    struct sockaddr_in addr;
    char buffer[SIZE];*/
    

    if (wrong_arguments(argc)) {
        usage();
        exit(EXIT_FAILURE);
    }

    parse_arguments(argv, argc);
    
    /*
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == ERROR) //error
        exit(EXIT_FAILURE);
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    
    //UDP socket
    //IPv4
    //UDP socket
    errcode = getaddrinfo(IP, PORT, &hints, &res);
    if(errcode != 0) // error 
        exit(EXIT_FAILURE);

    n = sendto(fd, "Hello!\n", 7, 0, res -> ai_addr, res -> ai_addrlen);
    if (n == ERROR) //error
        exit(EXIT_FAILURE);

    addrlen = sizeof(addr);
    n= recvfrom (fd, buffer, SIZE, 0, (struct sockaddr*) &addr, &addrlen);
    if(n == ERROR) //error
        exit(EXIT_FAILURE);
    write(1, "echo: ", 6); 
    write(1, buffer, n);
    freeaddrinfo(res);

    close (fd);
    */

   free(pdip);
   free(pdport);
   free(asip);
   free(asport);

    exit(EXIT_SUCCESS);
}

int wrong_arguments(int argc) {
    return !(argc > 0 && argc%2 == 0 && argc <= 8);
}

void usage() {
    printf("./pd PDIP [-d PDport] [-n ASIP] [-p ASport]\n");
    printf("./pd 10.0.2.15 -d 57000 -n 193.136.138.142 -p 58000");
}

void parse_arguments(const char* argv[], int size) {
    if (!(pdip = (char *) malloc(sizeof(char)*strlen(argv[1])))){
        perror("Error: allocating \"port\" buffer");
        exit(EXIT_FAILURE);
    }

    strcpy(pdip, argv[1]);

    printf("PDIP=%s\n", pdip);

    parse_d_flag(argv, size);
    parse_n_flag(argv, size);
    parse_p_flag(argv, size);
}

void parse_d_flag(const char* argv[], int size) {
    for(int i = 0; i < size; ++i) {   
        if (!strcmp(argv[i], "-d")) {
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
    printf("PDport=%s\n", pdport);
}

void parse_n_flag(const char* argv[], int size) {
    for(int i = 0; i < size; ++i) {   
        if (!strcmp(argv[i], "-n")) {
            if (!(asip = (char *) malloc(sizeof(char)*strlen(argv[i+1])))) {
                perror("Error: allocating \"PDport\" buffer");
                exit(EXIT_FAILURE);
            }
            strcpy(asip, argv[i+1]);
            printf("ASIP=%s\n", asip);
            break;
        }
    }
}

void parse_p_flag(const char* argv[], int size) {
    for (int i = 0; i < size; ++i) {   
        if (!strcmp(argv[i], "-p")) {
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
    printf("ASport=%s\n", asport);
}
