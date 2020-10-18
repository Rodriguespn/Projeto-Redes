#include "as.h"

// the buffer where ASport is stored
char *asport;
char *users_directory = USERS_FOLDER_NAME;
FILE *userfd; 
struct stat st = {0};

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

    if (errcode != 0) {
        /*error*/ 
        fprintf(stderr, "Error: getaddrinfo returned %d error code\n", errcode);
        exit(EXIT_FAILURE);
    }

    n = bind(fd, res -> ai_addr, res -> ai_addrlen);
    if (n == ERROR)  {
        /*error*/
        fprintf(stderr, "Error: bind returned %ld error code\n", n);
        exit(EXIT_FAILURE);
    }

    if (stat(users_directory, &st) == -1) { // if directory doesn t exists
        // check if directory is created or not 
        if (mkdir(users_directory, 0777)) { 
            printf("Unable to create directory \"%s\"\n", users_directory); 
            exit(EXIT_FAILURE); 
        }
    }

    char command[SIZE], uid[UID_SIZE], password[PASSWORD_SIZE], pdip[SIZE], pdport[SIZE];
    memset(command, EOS, SIZE);
    memset(uid, EOS, UID_SIZE);
    memset(password, EOS, PASSWORD_SIZE);
    memset(pdip, EOS, SIZE);
    memset(pdport, EOS, SIZE);

    while (true) {
        memset(buffer, EOS, SIZE);
        addrlen = sizeof(addr);
        n = recvfrom(fd, buffer, SIZE, 0, (struct sockaddr*) &addr, &addrlen);
        if (n == ERROR) {
            /*error*/
            exit(EXIT_FAILURE);
        }

        if (parse_command(buffer, command)) {
            if (!strcmp(command, REGISTRATION)) {
                if (parse_register_message(uid, password, pdip, pdport)) {
                    if (register_user(uid, password, pdip, pdport)) {
                        prepare_ok_message(buffer, REG_RESPONSE);
                    } else {
                        prepare_nok_message(buffer, REG_RESPONSE);
                    }
                } else {
                    prepare_error_message(buffer);
                }

            } else if (!strcmp(command, UNREGISTRATION)) {
                if (parse_unregister_message(uid, password)) {
                    printf("uid=%s\npassword=%s\n", uid, password);
                    if (unregister_user(uid, password)) {
                        prepare_ok_message(buffer, UNR_RESPONSE);
                    } else {
                        prepare_nok_message(buffer, UNR_RESPONSE);
                    }
                }
            } else {
                prepare_error_message(buffer);
            } 
        } else {
            prepare_error_message(buffer);
        }
        
        printf("command = %s\n", command);
        write(STDOUT, "received: ", 10);
        write(STDOUT, buffer, n);

        n = sendto(fd, buffer, n, 0, (struct sockaddr*) &addr, addrlen);
        if (n == ERROR) {
            /*error*/
            exit(EXIT_FAILURE);
        }
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

void prepare_error_message(char* buffer) {
    memset(buffer, EOS, SIZE);
    strcpy(buffer, PROTOCOL_ERROR);
    strcat(buffer, "\n");
}

void prepare_ok_message(char* buffer, const char* command) {
    memset(buffer, EOS, SIZE);
    strcpy(buffer, command);
    strcat(buffer, " ");
    strcat(buffer, OK);
    strcat(buffer, "\n");
}

void prepare_nok_message(char* buffer, const char* command) {
    memset(buffer, EOS, SIZE);
    strcpy(buffer, command);
    strcat(buffer, " ");
    strcat(buffer, NOT_OK);
    strcat(buffer, "\n");
}

// parses the arguments given on the command line
void parse_arguments(const char* argv[], int size) {
    asport = parse_as_port(argv, size);
}

Boolean parse_command(char* buffer, char* command) {
    char *token;

    if(!(token = strtok(buffer, " "))) {
        fprintf(stderr, "wrong command!\n");
        return false;
    }
    strcpy(command, token);
    return true;
}

// parses the register command
Boolean parse_register_message(char* uid, char* password, char* pdip, char* pdport) {
    char *token;

    token = strtok(NULL, " ");
    if (!valid_uid(token)) {
        fprintf(stderr, "Invalid user!\n");
        return false;
    }
    strcpy(uid, token);

    token = strtok(NULL, " ");
    if (!valid_password(token)) {
        fprintf(stderr, "Invalid password!\n");
        return false;
    }
    strcpy(password, token);

    token = strtok(NULL, " ");
    if (!token) {
        fprintf(stderr, "Invalid PDIP!\n");
        return false;
    }
    strcpy(pdip, token);

    token = strtok(NULL, "\n");
    if (!token) {
        fprintf(stderr, "Invalid PDPort!\n");
        return false;
    }
    strcpy(pdport, token);

    printf("uid: %s\npassword: %s\nPDIP: %s\nPDPort: %s\n", uid, password, pdip, pdport);
    return true;
}

Boolean parse_unregister_message(char* uid, char* password) {
    char *token;

    token = strtok(NULL, " ");
    printf("uid=%s\n", token);
    if (!valid_uid(token)) {
        fprintf(stderr, "Invalid user!\n");
        return false;
    }
    strcpy(uid, token);

    token = strtok(NULL, "\n");
    printf("password=%s\n", token);
    if (!valid_password(token)) {
        fprintf(stderr, "Invalid password!\n");
        return false;
    }
    strcpy(password, token);
    return true;
}

// returns true if the uid only contains numbers
// false otherwise
Boolean all_numbers(char* uid) {
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
Boolean valid_uid(char* uid) {
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
Boolean only_numbers_or_letters(char* password) {
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
Boolean valid_password(char* password) {
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

/*void parse_pd_request(char* buffer, char* command, char* uid, char* password) {

}*/

void get_user_directory(char* buffer, char *uid) {

    memset(buffer, EOS, strlen(buffer));
    strcat(buffer, "./");
    strcat(buffer, users_directory);
    strcat(buffer, uid);
    strcat(buffer, "/");

    printf("get_directory = %s\n", buffer);
}

void get_filename(char* buffer, char* uid, const char* filename, const char* file_ext) {
    memset(buffer, EOS, strlen(buffer));
    strcat(buffer, uid);
    strcat(buffer, filename);
    strcat(buffer, file_ext);

    printf("get_filename = %s\n", buffer);
}

Boolean register_user(char* uid, char* password, char* ip, char* port) {
    char* filename = NULL;
    char* directory = NULL;
    char* full_path; // users_directory/uid/file

    // allocates memory for the password file for the user with uid
    int filename_size = strlen(uid) + strlen(PASSWORD_FILE_PREFIX) + strlen(FILE_EXTENSION);
    if (!(filename = (char *) malloc(sizeof(char)*filename_size))){
            perror("Error: allocating \"filename\" buffer");
            exit(EXIT_FAILURE);
    }

    get_filename(filename, uid, PASSWORD_FILE_PREFIX, FILE_EXTENSION);

    // allocates memory for the relative path for the user with uid
    if (!(directory = (char *) malloc(sizeof(char)*(strlen(users_directory)+ strlen(uid) + 2)))) {
        perror("Error: allocating \"path\" buffer");
        exit(EXIT_FAILURE);
    }

    get_user_directory(directory, uid);

    // check if the directory is created or not 
    if (stat(directory, &st) == ERROR) { // if directory doesn t exists
        if (mkdir(directory, 0777)) { 
            printf("Unable to create directory \"%s\"\n", directory); 
            exit(EXIT_FAILURE); 
        }
    } else { // the user already exists
        fprintf(stderr, "Error: the user %s already exits\n", uid);
        return false;
    }

    // allocates memory for full relative path to the password file for the user with uid
    if (!(full_path = (char *) malloc(sizeof(char)*(strlen(directory) + strlen(filename))))) {
        perror("Error: allocating \"path\" buffer");
        exit(EXIT_FAILURE);
    }

    strcat(full_path, directory);
    strcat(full_path, filename);

    printf("path = %s\n", full_path);
    // opens the password file
    if (!(userfd = fopen(full_path, "w"))) {
        fprintf(stderr, "Error: could not open file %s\n", filename);
        exit(EXIT_FAILURE);
    }

    // writes the password on the file
    fprintf(userfd, "%s\n", password);

    // closes the password file
    fclose(userfd);

    // clears the full_path and filename memory
    memset(full_path, EOS, strlen(full_path));

    filename_size = strlen(uid) + strlen(REGISTRATION_FILE_PREFIX) + strlen(FILE_EXTENSION);
    // allocates memory for the registration file for the user with uid
    if (!(filename = (char *) realloc(filename, sizeof(char)*filename_size))){
        perror("Error: allocating \"filename\" buffer");
        exit(EXIT_FAILURE);
    }

    get_filename(filename, uid, REGISTRATION_FILE_PREFIX, FILE_EXTENSION);

    printf("registration_filename = %s\n", filename);

    strcat(full_path, directory);
    strcat(full_path, filename);

    printf("path = %s\n", full_path);

    // opens the registration file
    if (!(userfd = fopen(full_path, "w"))) {
        fprintf(stderr, "Error: could not open file %s\n", filename);
        exit(EXIT_FAILURE);
    }

    // writes the ip and the port like "ip:port"
    fprintf(userfd, "%s", ip);
    fprintf(userfd, "%s", ":");
    fprintf(userfd, "%s\n", port);

    // closes the registration file
    fclose(userfd);

    free(filename);
    free(directory);
    free(full_path);

    return true;
}

Boolean unregister_user(char *uid, char *password) {
    char* filename = NULL;
    char* directory = NULL;
    char* full_path; // users_directory/uid/file

    // allocates memory for the password file for the user with uid
    int filename_size = strlen(uid) + strlen(PASSWORD_FILE_PREFIX) + strlen(FILE_EXTENSION);
    if (!(filename = (char *) malloc(sizeof(char)*filename_size))){
            perror("Error: allocating \"filename\" buffer");
            exit(EXIT_FAILURE);
    }

    get_filename(filename, uid, PASSWORD_FILE_PREFIX, FILE_EXTENSION);

    // allocates memory for the relative path for the user with uid
    if (!(directory = (char *) malloc(sizeof(char)*(strlen(users_directory)+ strlen(uid) + 2)))) {
        perror("Error: allocating \"path\" buffer");
        exit(EXIT_FAILURE);
    }

    get_user_directory(directory, uid);

    // allocates memory for full relative path to the password file for the user with uid
    if (!(full_path = (char *) malloc(sizeof(char)*(strlen(directory) + strlen(filename))))) {
        perror("Error: allocating \"path\" buffer");
        exit(EXIT_FAILURE);
    }

    strcat(full_path, directory);
    strcat(full_path, filename);

    printf("path = %s\n", full_path);

    // opens the password file
    if (!(userfd = fopen(full_path, "r"))) {
        fprintf(stderr, "Error: could not open file %s\n", filename);
        exit(EXIT_FAILURE);
    }

    char password_from_file[PASSWORD_SIZE];
    // reads the password from the file
    fscanf(userfd, "%s\n", password_from_file);
    printf("password_from_file=%s\n", password_from_file);

    if (strcmp(password, password_from_file)) {
        fprintf(stderr, "Error: wrong uid or password\n");
        return false;
    }

    // closes the password file
    fclose(userfd);

    // clears the full_path and filename memory
    memset(full_path, EOS, strlen(full_path));

    filename_size = strlen(uid) + strlen(REGISTRATION_FILE_PREFIX) + strlen(FILE_EXTENSION);
    // allocates memory for the registration file for the user with uid
    if (!(filename = (char *) realloc(filename, sizeof(char)*filename_size))){
        perror("Error: allocating \"filename\" buffer");
        exit(EXIT_FAILURE);
    }

    get_filename(filename, uid, REGISTRATION_FILE_PREFIX, FILE_EXTENSION);

    printf("registration_filename = %s\n", filename);

    strcat(full_path, directory);
    strcat(full_path, filename);

    printf("path = %s\n", full_path);

    if (remove(full_path)) {
        fprintf(stderr, "Error: could not remove file %s\n", filename);
        exit(EXIT_FAILURE);
    };

    free(filename);
    free(directory);
    free(full_path);

    return true;
}
