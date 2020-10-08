#include "functions.h"

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
void parse_pd_port(const char* argv[], int size, char* pdport) {
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


// parses the ASIP value, given with the AS_IP flag
// if no ip given, sets the default value equals to PDIP
void parse_as_ip(const char* argv[], int size, char* asip, char* pdip) {
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
void parse_as_port(const char* argv[], int size, char* asport) {
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

// parses the FSport value, given with the FS_PORT flag
// if no port given, sets the default value of 59000+GN
void parse_fs_port(const char* argv[], int size, char* fsport) {
    for (int i = 0; i < size; ++i) {   
        if (!strcmp(argv[i], FS_PORT_FLAG)) {
            if (!(fsport = (char *) malloc(sizeof(char)*strlen(argv[i+1])))) {
                perror("Error: allocating \"PDport\" buffer");
                exit(EXIT_FAILURE);
            }
            strcpy(fsport, argv[i+1]);
            break;
        }
    }
    if (!fsport) {
        if (!(fsport = (char *) malloc(sizeof(char)*5))) {
                perror("Error: allocating \"PDport\" buffer");
                exit(EXIT_FAILURE);
        }

        int port = FSPORT+GN;
        sprintf(fsport, "%d", port);
    }
}

// parses the FSIP value, given with the FS_IP flag
// if no ip given, sets the default value equals to PDIP
void parse_fs_ip(const char* argv[], int size, char* fsip, char* pdip) {
    for(int i = 0; i < size; ++i) {   
        if (!strcmp(argv[i], FS_IP_FLAG)) {
            if (!(fsip = (char *) malloc(sizeof(char)*strlen(argv[i+1])))) {
                perror("Error: allocating \"PDport\" buffer");
                exit(EXIT_FAILURE);
            }
            strcpy(fsip, argv[i+1]);
            break;
        }
    }
    if (!fsip) {
        if (!(fsip = (char *) malloc(sizeof(char)*strlen(pdip)))) {
                perror("Error: allocating \"PDport\" buffer");
                exit(EXIT_FAILURE);
        }
        strcpy(fsip, pdip);
    }
}
