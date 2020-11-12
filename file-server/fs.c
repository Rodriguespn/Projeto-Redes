#include "fs.h"

// +------------------------------------------+
// | Global Variables                         |
// +------------------------------------------+
int tcp_sockfd;                     // used by sigint_handler
Boolean running_flag = true;        // used by sigint_handler. indicates if the process is running
Boolean user_connected_flag = true; // indicates if the user still has connection or dropped
struct stat st = {0};

int main(int argc, char const *argv[])
{
    // Define program running flag and threat SIGINT
    signal(SIGINT, sigint_handler);
    
    // Check if the number of arguments are right
    if (wrong_arguments(argc))
    {
        usage();
        exit(EXIT_FAILURE);
    }

    // Create database directory
    if (!make_main_directory())
    {
        fprintf(stderr, "\nError Unable to make main directory.\n");
        exit(EXIT_FAILURE);
    }

    // Define file system argument variables
    int fs_port, as_port;
    char fs_hostname[HOSTNAME_SIZE], fs_ip[IP_SIZE], as_ip[IP_SIZE];
    Boolean verbose;

    // Get localhost information
    bzero(fs_hostname, HOSTNAME_SIZE);
    bzero(fs_ip, IP_SIZE);
    bzero(as_ip, IP_SIZE);
    get_localhost_info(fs_hostname, fs_ip);

    // Parse arguments to respective variables
    fs_port = parse_argument_int(argc, argv, FS_PORT_FLAG, FSPORT+GN);
    as_port = parse_argument_int(argc, argv, AS_PORT_FLAG, ASPORT+GN);
    verbose = parse_argument_flag(argc, argv, VERBOSE_FLAG);
    parse_argument_string(argc, argv, AS_IP_FLAG, LOCALHOST, as_ip);
    
    // Define TCP socket variables (Communication with User)
    struct sockaddr_in tcp_servaddr;

    // Create TCP socket
    tcp_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_sockfd == ERROR)
    {
        fprintf(stderr, "Unable to create the tcp socket.\n");
        exit(EXIT_FAILURE);
    }

    // Assign IP address and PORT to the TCP socket 
    bzero(&tcp_servaddr, sizeof(tcp_servaddr));
    tcp_servaddr.sin_family = AF_INET; 
    tcp_servaddr.sin_addr.s_addr = htons(INADDR_ANY); 
    tcp_servaddr.sin_port = htons(fs_port); 
  
    // Bind TCP socket to the assigned IP address and Port 
    // (bind(tcp_sockfd, (struct sockaddr*) &tcp_servaddr, sizeof(tcp_servaddr))
    if ((bind(tcp_sockfd, (struct sockaddr*) &tcp_servaddr, sizeof(tcp_servaddr))) != 0)
    { 
        fprintf(stderr, "Unable to bind the tcp socket.\n");
        exit(EXIT_FAILURE);  
    } 
  
    // Start listening for users in the TCP socket
    if ((listen(tcp_sockfd, 5)) != 0)
    { 
        fprintf(stderr, "Unable to start listening for user in the TCP socket.\n");
        exit(EXIT_FAILURE);
    }

    // Print important network information if verbose flag is true
    verbose_message(verbose, "File-System Details:\nHostname = %s\nIP = %s\nPort = %d\n\nAuthentication-System Details:\nIP = %s\nPort = %d\n\n", fs_hostname, fs_ip, fs_port, as_ip, as_port);
    

    // Repeat the routine while main process is running
    while (running_flag == true)
    {
        // Define user socket variables
        int user_sockfd;    // close
        struct sockaddr_in user_servaddr;
        socklen_t user_servaddr_len = sizeof(user_servaddr);

        // Accept users trying to connect via TCP socket (Blocks here) while running flag is up
        user_sockfd = accept(tcp_sockfd, (struct sockaddr*) &user_servaddr, &user_servaddr_len);
        if (user_sockfd == ERROR)
        {
            fprintf(stderr, "\nTCP socket was closed.\n");
            continue;
        }
        else if (user_sockfd < 0) { 
            fprintf(stderr, "Unable to accept TCP connections.\n");
            exit(EXIT_FAILURE); 
        }
        
        // If the code gets here then a new user connected.
        // Create a new process to handle the conversation with the user
        int pid = fork();

        // Redirect the child process to handle the conversation
        if (pid == 0)   // Child process
        {
            // Closes the tcp_sockfd as it wont be used by the child process
            close(tcp_sockfd);

            // Define UDP socket variables (Communication with Authentication Server)
            int udp_sockfd; // close
            struct sockaddr_in udp_servaddr;
            
            // Create UDP socket 
            udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
            if (udp_sockfd == ERROR)
            {
                fprintf(stderr, "Unable to create the udp socket from User.\n");
                exit(EXIT_FAILURE);
            }
            
            // Assign IP address and PORT to the UDP socket
            bzero(&udp_servaddr, sizeof(udp_servaddr));
            udp_servaddr.sin_family = AF_INET; 
            udp_servaddr.sin_addr.s_addr = INADDR_ANY; 
            udp_servaddr.sin_port = htons(as_port);

            struct timeval tv;
            tv.tv_sec = 2;
            tv.tv_usec = 0; 
            int errcode;

            // sets socket timeout as 5s
            if ((errcode = setsockopt(udp_sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv))) < 0) {
                fprintf(stderr, "Error: setsockopt returned erro code %d\n", errcode);
                return false;
            }
            
            // Define user IP and Port variables
            char user_ip[IP_SIZE];
            int user_port;

            // Assign user IP and Port variables
            bzero(user_ip, IP_SIZE);
            strcpy(user_ip, inet_ntoa(user_servaddr.sin_addr));
            user_port = user_servaddr.sin_port;
            
            // Print the IP and Port of the new connection received
            verbose_message(verbose, "IP = %s | Port = %d | Connection established.\n", user_ip, user_port);
            
            // Define all possible atributes sent by the User
            char user_command[COMMAND_SIZE], user_uid[UID_SIZE], user_tid[TID_SIZE], user_filename[FILENAME_SIZE], user_filesize[FILE_SIZE_DIG];
            char* user_filename_data = NULL;    // free

            // Define all possible attributes sent by the AS
            char as_command[COMMAND_SIZE], as_uid[UID_SIZE], as_tid[TID_SIZE], as_fop[FOP_SIZE], as_filename[FILENAME_SIZE];

            // Tries to read while the user is connected
            while (user_connected_flag == true)
            {
                // Tries to read the command, uid and tid sent by the user
                if(!read_user_request_arg(user_sockfd, user_command, COMMAND_SIZE, false, " "))
                    break;
                verbose_message(verbose, "IP = %s | Port = %d | Command = %s ", user_ip, user_port, user_command);

                // Decides which operation to perform
                if (strcmp(user_command, RETRIEVE) == 0)
                {
                    
                }
                else if (strcmp(user_command, LIST) == 0)
                {
                    // Read user uid
                    if(!read_user_request_arg(user_sockfd, user_uid, UID_SIZE, false,  " "))
                        break;
                    verbose_message(verbose, "| UID = %s ", user_uid);
                    
                    // Read user tid
                    if (!read_user_request_arg(user_sockfd, user_tid, TID_SIZE, false, "\n"))
                        break;
                    verbose_message(verbose, "| TID = %s\n", user_tid);

                    // Send AS validation message
                    if(!send_as_val_request(udp_sockfd, (struct sockaddr*) &udp_servaddr, user_sockfd,user_uid, user_tid))
                        break;
                    verbose_message(verbose, "IP = %s | Port = %s | Sent AS Validation Request.\n", fs_ip, fs_port);
                    
                    // Read AS command response
                    if(!read_as_val_response(udp_sockfd, (struct sockaddr*) &udp_servaddr, user_sockfd, as_command, COMMAND_SIZE, false, " ", VAL_FILE_RESPONSE, NULL))
                        break;
                    verbose_message(verbose, "IP = %s | Port = %s | Command = ", as_ip, as_port, as_command);

                    // Read AS uid response
                    if (!read_as_val_response(udp_sockfd, (struct sockaddr*) &udp_servaddr, user_sockfd, as_uid, UID_SIZE, false, " ", user_uid, LIS_RESPONSE))
                        break;
                    verbose_message(verbose, "| UID = %s ", as_uid);

                    // Read AS tid response
                    if (!read_as_val_response(udp_sockfd, (struct sockaddr*) &udp_servaddr, user_sockfd, as_tid, TID_SIZE, false, " ", user_tid, LIS_RESPONSE))
                        break;
                    verbose_message(verbose, "| TID = %s ", as_tid);

                    // Read AS fop response
                    if (!read_as_val_response(udp_sockfd, (struct sockaddr*) &udp_servaddr, user_sockfd, as_fop, FOP_SIZE, false, "\n", USER_LIST_SHORT, LIS_RESPONSE))
                        break;
                    verbose_message(verbose, "| FOP = %s\n", as_fop);

                    // Tries to find the filename
                    if (find_user_directory(user_uid))
                    {
                        if (find_user_filename(user_uid, NULL))
                        {
                            int n = count_user_filenames(user_uid);
                            memset(user_filesize, EOS, FILE_SIZE_DIG);
                            sprintf(user_filesize, "%d", n);
                            int lst_size = (n * FILENAME_SIZE + n * FILE_SIZE_DIG + n * 2 + 1);
                            char* lst = (char *) malloc(lst_size*sizeof(char));
                            list_user_filenames(user_uid, lst, lst_size);

                            int res_size = (COMMAND_SIZE+lst_size+1);
                            char* res = (char *) malloc(res_size*sizeof(char));
                            memset(res, EOS, res_size);
                            strcpy(res, LIS_RESPONSE);
                            strcat(res, " ");
                            strcat(res, user_filesize);
                            strcat(res, lst);
                            if (write(user_sockfd, res, res_size) == ERROR)
                            {
                                fprintf(stderr, "\nError Unable to write properly on the user socket.\n");
                                user_connected_flag = false;
                            }
                            verbose_message(verbose, "IP = %s | Port = %s | List request fullfilled.\n", fs_ip, fs_port);
                            free(lst);
                            free(res);
                        }
                        else  // No files to list
                        {
                            verbose_message(verbose, "IP = %s | Port = %s | List request fullfilled: User has no files.\n", fs_ip, fs_port);
                            send_user_response(user_sockfd, LIS_RESPONSE, "0");
                        }
                    }
                    else    // returns NOK
                    {
                        verbose_message(verbose, "IP = %s | Port = %s | List request failed: User must do at least one upload.\n", fs_ip, fs_port);
                        send_user_response(user_sockfd, LIS_RESPONSE, NOT_OK);
                    }
                }
                else if (strcmp(user_command, UPLOAD) == 0)
                {
                    

                }
                else if (strcmp(user_command, DELETE) == 0)
                {
                    // Read user uid
                    if(!read_user_request_arg(user_sockfd, user_uid, UID_SIZE, false,  " "))
                        break;
                    verbose_message(verbose, "| UID = %s ", user_uid);

                    // Read user tid
                    if (!read_user_request_arg(user_sockfd, user_tid, TID_SIZE, false, " "))
                        break;
                    verbose_message(verbose, "| TID = %s ", user_tid);

                    // Read user filename
                    if (!read_user_request_arg(user_sockfd, user_filename, FILENAME_SIZE, true, "\n"))
                        break;
                    verbose_message(verbose, "| Filename = %s ", user_filename);

                    // Send AS validation message
                    if(!send_as_val_request(udp_sockfd, (struct sockaddr*) &udp_servaddr, user_sockfd, user_uid, user_tid))
                        break;
                    verbose_message(verbose, "IP = %s | Port = %s | Sent AS Validation Request.\n", fs_ip, fs_port);
                    
                    // Read AS command response
                    if(!read_as_val_response(udp_sockfd, (struct sockaddr*) &udp_servaddr, user_sockfd, as_command, COMMAND_SIZE, false, " ", VAL_FILE_RESPONSE, NULL))
                        break;
                    verbose_message(verbose, "IP = %s | Port = %s | Command = ", as_ip, as_port, as_command);

                    // Read AS uid response
                    if (!read_as_val_response(udp_sockfd, (struct sockaddr*) &udp_servaddr, user_sockfd, as_uid, UID_SIZE, false, " ", user_uid, DEL_RESPONSE))
                        break;
                    verbose_message(verbose, "| UID = %s ", as_uid);

                    // Read AS tid response
                    if (!read_as_val_response(udp_sockfd, (struct sockaddr*) &udp_servaddr, user_sockfd, as_tid, TID_SIZE, false, " ", user_tid, DEL_RESPONSE))
                        break;
                    verbose_message(verbose, "| TID = %s ", as_tid);

                    // Read AS fop response
                    if (!read_as_val_response(udp_sockfd, (struct sockaddr*) &udp_servaddr, user_sockfd, as_fop, FOP_SIZE, false, " ", USER_DELETE_SHORT, DEL_RESPONSE))
                        break;
                    verbose_message(verbose, "| FOP = %s ", as_fop);

                    // Read AS filename response
                    if (!read_as_val_response(udp_sockfd, (struct sockaddr*) &udp_servaddr, user_sockfd, as_filename, FILENAME_SIZE, true, "\n", user_filename, DEL_RESPONSE))
                        break;
                    verbose_message(verbose, "| Filename = %s\n", as_filename);

                    // Tries to find the filename
                    if (find_user_directory(user_uid))
                    {
                        if (find_user_filename(user_uid, user_filename))
                        {
                            if (delete_user_file(user_uid, user_filename))
                            {
                                verbose_message(verbose, "IP = %s | Port = %s | Delete request fullfilled.\n", fs_ip, fs_port);
                                send_user_response(user_sockfd, DEL_RESPONSE, OK);
                            }
                            else  // returns ERR
                            {
                                verbose_message(verbose, "IP = %s | Port = %s | Delete request failed: Unable to delete the file.\n", fs_ip, fs_port);
                                send_user_response(user_sockfd, PROTOCOL_ERROR, NULL);
                            }
                            
                        }
                        else // returns EOF
                        {
                            verbose_message(verbose, "IP = %s | Port = %s | Delete request failed: File not found.\n", fs_ip, fs_port);
                            send_user_response(user_sockfd, DEL_RESPONSE, EOF_FILE);
                        }
                    }
                    else    // returns NOK
                    {
                        verbose_message(verbose, "IP = %s | Port = %s | Delete request failed: User not found.\n", fs_ip, fs_port);
                        send_user_response(user_sockfd, DEL_RESPONSE, NOT_OK);
                    }
                }
                else if (strcmp(user_command, REMOVE) == 0)
                {
                    // Read user uid
                    if(!read_user_request_arg(user_sockfd, user_uid, UID_SIZE, false,  " "))
                        break;
                    verbose_message(verbose, "| UID = %s ", user_uid);

                    // Read user tid
                    if (!read_user_request_arg(user_sockfd, user_tid, TID_SIZE, false, "\n"))
                        break;
                    verbose_message(verbose, "| UID = %s ", user_tid);

                    // Send AS validation message
                    if(!send_as_val_request(udp_sockfd, (struct sockaddr*) &udp_servaddr, user_sockfd, user_uid, user_tid))
                        break;
                    verbose_message(verbose, "IP = %s | Port = %s | Sent AS Validation Request.\n", fs_ip, fs_port);
                    
                    // Read AS command response
                    if(!read_as_val_response(udp_sockfd, (struct sockaddr*) &udp_servaddr, user_sockfd, as_command, COMMAND_SIZE, false, " ", VAL_FILE_RESPONSE, NULL))
                        break;
                    verbose_message(verbose, "IP = %s | Port = %s | Command = ", as_ip, as_port, as_command);

                    // Read AS uid response
                    if (!read_as_val_response(udp_sockfd, (struct sockaddr*) &udp_servaddr, user_sockfd, as_uid, UID_SIZE, false, " ", user_uid, REM_RESPONSE))
                        break;
                    verbose_message(verbose, "| UID = %s ", as_uid);
                    
                    // Read AS tid response
                    if (!read_as_val_response(udp_sockfd, (struct sockaddr*) &udp_servaddr, user_sockfd, as_tid, TID_SIZE, false, " ", user_tid, REM_RESPONSE))
                        break;
                    verbose_message(verbose, "| TID = %s ", as_tid);

                    // Read AS fop response
                    if (!read_as_val_response(udp_sockfd, (struct sockaddr*) &udp_servaddr, user_sockfd, as_fop, FOP_SIZE, false, "\n", USER_REMOVE_SHORT, REM_RESPONSE))
                        break;
                    verbose_message(verbose, "| FOP = %s ", as_fop);

                    // Tries to find the filename
                    if (find_user_directory(user_uid))
                    {
                        if (remove_user_dir(user_uid))
                        {
                            verbose_message(verbose, "IP = %s | Port = %s | Remove request fullfilled.\n", fs_ip, fs_port);
                            send_user_response(user_sockfd, REM_RESPONSE, OK);
                        }
                        else  // returns ERR
                        {
                            verbose_message(verbose, "IP = %s | Port = %s | Remove request failed: Unable to remove the directory.\n", fs_ip, fs_port);
                            send_user_response(user_sockfd, PROTOCOL_ERROR, NULL);
                        }   
                    }
                    else    // returns NOK
                    {
                        verbose_message(verbose, "IP = %s | Port = %s | Remove request failed: User not found.\n", fs_ip, fs_port);
                        send_user_response(user_sockfd, REM_RESPONSE, NOT_OK);
                    }   
                }
                else
                {
                    verbose_message(verbose, "IP = %s | Port = %s | Invalid command.\n", fs_ip, fs_port);
                    send_user_response(user_sockfd, PROTOCOL_ERROR, NULL);
                }
            }            
            
            // Frees memory dinamically allocated and closes sockets left open
            free(user_filename_data);
            close(udp_sockfd);
            close(user_sockfd);
            
            // Child process
            running_flag = false;
        }
        else    // Parent process
        {
            close(user_sockfd);
            continue;
        }
    }

    // Program terminated
    fprintf(stdout, "Process Terminated.\n");
    exit(EXIT_SUCCESS);
}

// +------------------------------------------+
// | Arguments Functions                      |
// +------------------------------------------+

// Prints to stdin the usage when user gives wrong arguments
void usage()
{    
    fprintf(stdin, "usage: ./FS [-q FSport] [-n ASIP] [-p ASport] [-v]\n");
}

// Checks if the number of arguments is correct
Boolean wrong_arguments(int argc)
{
    return (argc >= 1 && argc <= 8) ? false : true;
}

// Parses the argument with the given flag. In case there is none uses the default buffer given.
void parse_argument_string(int argc, char const* argv[], char* flag, char* default_buffer, char* argument_buffer)
{
    for (int i = 0; i < argc; i++)
    {
        if (strcmp(argv[i], flag) == 0)
        {
            strcpy(argument_buffer, argv[i+1]);
            return;
        }
    }
    strcpy(argument_buffer, default_buffer);
}

int parse_argument_int(int argc, char const* argv[], char* flag, int default_int)
{
    for (int i = 0; i < argc; i++)
    {
        if (strcmp(argv[i], flag) == 0)
        {
            return atoi(argv[i+1]);
        }
    }
    return default_int;
}
// Parses the arguments and finds a flag.
Boolean parse_argument_flag(int argc, char const* argv[], char* flag)
{
    for (int i = 0; i < argc; i++)
    {
        if (strcmp(argv[i], flag) == 0)
        {
            return true;
        }
    }
    return false;
}

// +------------------------------------------+
// | Directory Functions                      |
// +------------------------------------------+
// Creates the main directory if it does not already exist
Boolean make_main_directory()
{
    // creates the directory where the users' information will be stored
    if (stat(MAIN_DIR_NAME, &st) == -1) { // if directory doesn t exists
        // check if directory is created or not 
        if (mkdir(MAIN_DIR_NAME, 0777))
        {
            return false;
        }
    }
    return true;
}

// Tries to find the user directory with the respective uid
Boolean find_user_directory(char* uid)
{
    DIR* main_dir;
    main_dir = opendir(MAIN_DIR_NAME);
    struct dirent* user_dir;
    while ((user_dir = readdir(main_dir)) != NULL)
    {
        if(strcmp(user_dir->d_name, uid) == 0)
        {
            closedir(main_dir);
            return true;
        }
    }
    closedir(main_dir);
    return false;
}

// Creates a user directory if it does not already exist
Boolean make_user_directory(char* uid)
{
    char aux[MAIN_DIR_NAME_SIZE+UID_SIZE];
    strcpy(aux, MAIN_DIR_NAME);
    strcat(aux, uid);
    if (!mkdir(aux, 0777))
    {
        return false;
    }
    return true;
}

// Tries to find a filename in the respective user directory
Boolean find_user_filename(char* uid, char* filename)
{
    char aux[MAIN_DIR_NAME_SIZE+UID_SIZE];
    strcpy(aux, MAIN_DIR_NAME);
    strcat(aux, uid);
    DIR *dir = opendir(aux);
    struct dirent *file;
    while ((file=readdir(dir)) != NULL)
    {
        if (filename == NULL)
            return true;
        if(strcmp(file->d_name, filename) == 0)
        {
            closedir(dir);
            return true;
        }
    }
    closedir(dir);
    return false;
}

int count_user_filenames(char* uid)
{
    char aux[MAIN_DIR_NAME_SIZE+UID_SIZE];
    strcpy(aux, MAIN_DIR_NAME);
    strcat(aux, uid);
    DIR *dir = opendir(aux);
    struct dirent *file;
    int count = 0;
    while ((file=readdir(dir)) != NULL)
    {
        count++;
    }
    closedir(dir);
    return count;
}

void list_user_filenames(char* uid, char* res, int res_size)
{
    memset(res, EOS, res_size);
    
    char aux[MAIN_DIR_NAME_SIZE+UID_SIZE];
    strcpy(aux, MAIN_DIR_NAME);
    strcat(aux, uid);
    DIR *dir = opendir(aux);
    struct dirent *file;
    char filesize[FILE_SIZE_DIG];
    while ((file=readdir(dir)) != NULL)
    {
        stat(file->d_name, &st);
        strcat(res, " ");
        strcat(res, file->d_name);
        strcat(res, " ");
        memset(filesize, EOS, FILE_SIZE_DIG);
        sprintf(filesize, "%lld", st.st_size);
        strcat(res, filesize);
    }
    closedir(dir);
}

// Counts the filenames in the user directory and check if it has reached the limit
Boolean reached_user_file_limit(char* uid, int max)
{
    char aux[MAIN_DIR_NAME_SIZE+UID_SIZE];
    strcpy(aux, MAIN_DIR_NAME);
    strcat(aux, uid);
    DIR *dir = opendir(aux);
    struct dirent *file;
    int count = 0;
    while ((file=readdir(dir)) != NULL)
    {
        count++;
    }
    closedir(dir);
    return count == max;
}

// Creates a new filename in the user directory with the respective data
Boolean create_user_file(char* uid, char* filename, char* data)
{
    FILE* fp;
    char aux[MAIN_DIR_NAME_SIZE+UID_SIZE+1+FILENAME_SIZE];
    bzero(aux, MAIN_DIR_NAME_SIZE+UID_SIZE+1+FILENAME_SIZE);
    strcpy(aux, MAIN_DIR_NAME);
    strcat(aux, uid);
    strcat(aux, "/");
    strcat(aux, filename);
    if (!(fp = fopen(aux, "w")))
    {
        fprintf(stderr, "\nError Unable to open %s path\n", aux);
        return false;
    }
    fprintf(fp, "%s", data);
    fclose(fp);
    printf("File %s created\n", aux);
    return true;
}

// Deletes a filename in the user directory
Boolean delete_user_file(char* uid, char* filename)
{
    char aux[MAIN_DIR_NAME_SIZE+UID_SIZE+1+FILENAME_SIZE];
    bzero(aux, MAIN_DIR_NAME_SIZE+UID_SIZE+1+FILENAME_SIZE);
    strcpy(aux, MAIN_DIR_NAME);
    strcat(aux, uid);
    strcat(aux, "/");
    strcat(aux, filename);
    if (remove(aux))
    {
        fprintf(stderr, "\nError Unable to remove %s\n", aux);
        return false;
    } 
    printf("File %s removed\n", aux);
    return true;
}

// Removes the entire user directory
Boolean remove_user_dir(char* uid)
{
    DIR *d;
    struct dirent *dir;
    char file_path[SIZE];
    char aux[MAIN_DIR_NAME_SIZE+UID_SIZE];
    bzero(aux, MAIN_DIR_NAME_SIZE+UID_SIZE);
    strcpy(aux, MAIN_DIR_NAME);
    strcat(aux, uid);
    d = opendir(aux);

    if (d) {
        while((dir = readdir(d)) != NULL) {
            if (strcmp(dir->d_name, "..") && strcmp(dir->d_name, ".")) {
                bzero(file_path, SIZE);
                strcpy(file_path, aux);
                strcat(file_path, dir->d_name);
               
                if (remove(file_path)) {
                    fprintf(stderr, "\nError Unable to remove file %s\n", file_path);
                    closedir(d);
                    return false;
                }
            }
        }
        if (rmdir(aux)) // removes the directory
        {
            fprintf(stderr, "\nError Unable to remove directory %s\n", aux);
            closedir(d); 
            return false;   
        }
            
        closedir(d);
        return true;
    }
    return false; 
}

// +------------------------------------------+
// | Internet Functions                       |
// +------------------------------------------+
// Get localhost information and write in the given buffers
void get_localhost_info(char* hostname_buffer, char* ip_buffer)
{
    gethostname(hostname_buffer, HOSTNAME_SIZE);                                    // Find the hostname
    struct hostent *host_entry = gethostbyname(hostname_buffer);                    // Find host information
    strcpy(ip_buffer, inet_ntoa(*((struct in_addr*) host_entry->h_addr_list[0])));  // Convert into IP string
}

Boolean read_user_request_arg(int sockfd, char* dest, int dest_size, Boolean skip_len,  char* delimiter)
{
    memset(dest, EOS, dest_size);
    char aux[dest_size];
    int n = read(sockfd, aux, dest_size);
    if (n == 0)                                 // Checks if the user disconnected
    {
        user_connected_flag = false;
        return false;
    }
    else if (n == ERROR || n < dest_size || (skip_len == true || strlen(aux) < (uint) dest_size))
    {
        fprintf(stderr, "\nError Unable to read properly from the user socket. User might have sent invalid argument.\n");
        send_user_response(sockfd, PROTOCOL_ERROR, NULL);
        user_connected_flag = false;
        return false;
    }
    char* token = strtok(aux, delimiter);
    strcpy(dest, token);
    return true;
}

Boolean read_as_val_response(int sockfd, struct sockaddr* addr, int user_sockfd, char* dest, int dest_size, Boolean skip_len, char* delimiter, char* dest_default, char* special_res_err)
{
    memset(dest, EOS, dest_size);
    char aux[dest_size];
    int addr_size = sizeof(addr);
    int n = recvfrom(sockfd, aux, dest_size, MSG_WAITALL, addr, (socklen_t*) &addr_size);
    if (n == 0)                                 // Checks if the user disconnected
    {
        user_connected_flag = false;
        return false;
    }
    else if (n == ERROR || n < dest_size || (skip_len == true || strlen(aux) < (uint) dest_size))
    {
        fprintf(stderr, "\nError Unable to read properly from the as socket. AS might have sent invalid argument.\n");
        if (special_res_err != NULL)
        {
            send_user_response(user_sockfd, PROTOCOL_ERROR, special_res_err);
        }
        else
        {
            send_user_response(user_sockfd, PROTOCOL_ERROR, NULL);
        }
        user_connected_flag = false;
        return false;
    }
    char* token = strtok(aux, delimiter);
    strcpy(dest, token);
    return (strcmp(dest, dest_default) == 0) ? true : false;
}


Boolean send_as_val_request(int sockfd, struct sockaddr* addr, int user_sockfd, char* uid, char* tid)
{
    memset(uid, EOS, UID_SIZE);
    memset(tid, EOS, TID_SIZE);
    const int dest_size = COMMAND_SIZE+UID_SIZE+TID_SIZE+1;
    char aux[dest_size];
    memset(aux, EOS, dest_size);
    strcpy(aux, VALIDATE_FILE);
    strcat(aux, " ");
    strcat(aux, uid);
    strcat(aux, " ");
    strcat(aux, tid);
    strcat(aux, "\n");
    int n = sendto(sockfd, aux, strlen(aux), 0, addr, sizeof(addr));
    if (n == 0)                                 // Checks if the user disconnected
    {
        user_connected_flag = false;
        return false;
    }
    else if (n == ERROR || n < dest_size || strlen(aux) < dest_size)
    {
        fprintf(stderr, "\nError Unable to write properly to the as socket.\n");
        send_user_response(user_sockfd, PROTOCOL_ERROR, NULL);
        return false;
    }
    return true;
}

Boolean send_user_response(int sockfd, char* protocol, char* status)
{
    if (status == NULL)
    {
        char res_err[COMMAND_SIZE+1];
        memset(res_err, EOS, COMMAND_SIZE+1);
        strcpy(res_err, protocol);
        strcat(res_err, "\n");
        if (write(sockfd, res_err, COMMAND_SIZE+1) == ERROR)
        {
            fprintf(stderr, "\nError Unable to write properly on the user socket.\n");
            user_connected_flag = false;
            return false;
        }
        return true;
    }
    else
    {
        char res_err[COMMAND_SIZE+STATUS_SIZE+1];
        memset(res_err, EOS, COMMAND_SIZE+STATUS_SIZE+1);
        strcpy(res_err, protocol);
        strcat(res_err, " ");
        strcat(res_err, status);
        strcat(res_err, "\n");
        if (write(sockfd, res_err, COMMAND_SIZE+STATUS_SIZE+1) == ERROR)
        {
            fprintf(stderr, "\nError Unable to write properly on the user socket.\n");
            user_connected_flag = false;
            return false;
        }
        return true;
    }
}

// +------------------------------------------+
// | Signal Threatment Functions              |
// +------------------------------------------+
// Handle SIGINT signal (CTRL + C)
void sigint_handler()
{
    running_flag = false;
    close(tcp_sockfd);      // This will unblock accept()
}
