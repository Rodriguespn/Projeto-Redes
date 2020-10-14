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
char* parse_pd_port(const char* argv[], int size) {
    char* pdport;
    enum boolean flag = false;
    for(int i = 0; i < size; ++i) {   
        if (!strcmp(argv[i], PD_PORT_FLAG)) {
            if (!(pdport = (char *) malloc(sizeof(char)*strlen(argv[i+1])))) {
                perror("Error: allocating \"PDport\" buffer");
                exit(EXIT_FAILURE);
            }
            strcpy(pdport, argv[i+1]);
            flag = true;
            break;
        }
    }
    if (!flag) {
        if (!(pdport = (char *) malloc(sizeof(char)*5))) {
                perror("Error: allocating \"PDport\" buffer");
                exit(EXIT_FAILURE);
        }

        int port = PDPORT+GN;
        sprintf(pdport, "%d", port);
    }
    return pdport;
}

// parses the ASIP value, given with the AS_IP flag
// if no ip given, sets the default value equals to PDIP
char* parse_as_ip(const char* argv[], int size, char* pdip) {
    char* asip;
    enum boolean flag = false;
    for(int i = 0; i < size; ++i) {   
        if (!strcmp(argv[i], AS_IP_FLAG)) {
            if (!(asip = (char *) malloc(sizeof(char)*strlen(argv[i+1])))) {
                perror("Error: allocating \"PDport\" buffer");
                exit(EXIT_FAILURE);
            }
            strcpy(asip, argv[i+1]);
            flag = true;
            break;
        }
    }
    if (!flag) {
        if (!(asip = (char *) malloc(sizeof(char)*strlen(pdip)))) {
                perror("Error: allocating \"PDport\" buffer");
                exit(EXIT_FAILURE);
        }
        strcpy(asip, pdip);
    }
    return asip;
}


// parses the ASport value, given with the AS_PORT flag
// if no port given, sets the default value of 58000+GN
char* parse_as_port(const char* argv[], int size) {
    char* asport;
    enum boolean flag = false;
    for (int i = 0; i < size; ++i) {   
        if (!strcmp(argv[i], AS_PORT_FLAG)) {
            if (!(asport = (char *) malloc(sizeof(char)*strlen(argv[i+1])))) {
                perror("Error: allocating \"PDport\" buffer");
                exit(EXIT_FAILURE);
            }
            strcpy(asport, argv[i+1]);
            flag = true;
            break;
        }
    }
    if (!flag) {
        if (!(asport = (char *) malloc(sizeof(char)*5))) {
                perror("Error: allocating \"PDport\" buffer");
                exit(EXIT_FAILURE);
        }

        int port = ASPORT+GN;
        sprintf(asport, "%d", port);
    }
    printf("%s\n", asport);
    return asport;
}

// parses the FSport value, given with the FS_PORT flag
// if no port given, sets the default value of 59000+GN
char* parse_fs_port(const char* argv[], int size) {
    char* fsport;
    enum boolean flag = false;
    for (int i = 0; i < size; ++i) {   
        if (!strcmp(argv[i], FS_PORT_FLAG)) {
            if (!(fsport = (char *) malloc(sizeof(char)*strlen(argv[i+1])))) {
                perror("Error: allocating \"PDport\" buffer");
                exit(EXIT_FAILURE);
            }
            strcpy(fsport, argv[i+1]);
            flag = true;
            break;
        }
    }
    if (!flag) {
        if (!(fsport = (char *) malloc(sizeof(char)*5))) {
                perror("Error: allocating \"PDport\" buffer");
                exit(EXIT_FAILURE);
        }

        int port = FSPORT+GN;
        sprintf(fsport, "%d", port);
    }
    return fsport;
}

// parses the FSIP value, given with the FS_IP flag
// if no ip given, sets the default value equals to PDIP
char* parse_fs_ip(const char* argv[], int size, char* pdip) {
    char* fsip;
    enum boolean flag = false;
    for(int i = 0; i < size; ++i) {   
        if (!strcmp(argv[i], FS_IP_FLAG)) {
            if (!(fsip = (char *) malloc(sizeof(char)*strlen(argv[i+1])))) {
                perror("Error: allocating \"PDport\" buffer");
                exit(EXIT_FAILURE);
            }
            strcpy(fsip, argv[i+1]);
            flag = true;
            break;
        }
    }
    if (!flag) {
        if (!(fsip = (char *) malloc(sizeof(char)*strlen(pdip)))) {
                perror("Error: allocating \"PDport\" buffer");
                exit(EXIT_FAILURE);
        }
        strcpy(fsip, pdip);
    }
    return fsip;
}
