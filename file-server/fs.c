#include "fs.h"

// +------------------------------------------+
// | Global Variables                         |
// +------------------------------------------+
int tcp_sockfd;                 // used by sigint_handler
Boolean running_flag = true;    // used by sigint_handler
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
        fprintf(stderr, "Error: Unable to make main directory.\n");
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
    parse_argument_string(argc, argv, AS_IP_FLAG, fs_ip, as_ip);
    
    // Define TCP socket variables (Communication with User)
    struct addrinfo hints, *res;
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
    tcp_servaddr.sin_addr.s_addr = inet_addr(fs_ip); 
    tcp_servaddr.sin_port = fs_port; 

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    char fs_port_char[SIZE];
    bzero(fs_port_char, SIZE);
    sprintf(fs_port_char, "%d", fs_port);

    int errcode = getaddrinfo(NULL, fs_port_char, &hints, &res);
    if (errcode != 0) {
        // error
        fprintf(stderr, "ERROR: tcp socket getaddrinfo returned %d error code\n", errcode);
        exit(EXIT_FAILURE); 
    } 
  
    // Bind TCP socket to the assigned IP address and Port 
    // (bind(tcp_sockfd, (struct sockaddr*) &tcp_servaddr, sizeof(tcp_servaddr))
    if ((bind(tcp_sockfd, res -> ai_addr, res -> ai_addrlen)) != 0)
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
    
    // Define user socket variables
    int user_sockfd;
    struct sockaddr_in user_servaddr;
    socklen_t user_servaddr_len = sizeof(user_servaddr);

    // Repeat the routine while main process is running
    while (running_flag == true)
    {
        // Accept users trying to connect via TCP socket (Blocks here) while running flag is up
        user_sockfd = accept(tcp_sockfd, (struct sockaddr*) &user_servaddr, &user_servaddr_len);
        if (user_sockfd == ERROR) // socket is closed
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
        if (pid == 0)
        {
            // Closes the tcp_sockfd as it wont be used by the child process
            close(tcp_sockfd);

            // Define UDP socket variables (Communication with Authentication Server)
            int udp_sockfd;
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
            udp_servaddr.sin_addr.s_addr = inet_addr(as_ip); 
            udp_servaddr.sin_port = as_port;
            
            // Define user IP and Port variables
            char user_ip[IP_SIZE];
            int user_port;

            // Assign user IP and Port variables
            bzero(user_ip, IP_SIZE);
            strcpy(user_ip, inet_ntoa(user_servaddr.sin_addr));
            user_port = user_servaddr.sin_port;
            
            // Print the IP and Port of the new connection received
            verbose_message(verbose, "IP = %s | Port = %d | Connection established\n", user_ip, user_port);

            // Define the auxilary variables
            int command_size = COMMAND_SIZE+1;
            char command[COMMAND_SIZE+1];
            
            // Wait for a request (Blocks here)
            // Read the request command. If bytes read are fewer that the command size or negative = error responds ERR to the user
            if (tcp_read(user_sockfd, command, COMMAND_SIZE) != COMMAND_SIZE)
            {
                bzero(command, command_size);
                strcpy(command, PROTOCOL_ERROR);
                strcat(command, "\n");
                tcp_write(user_sockfd, command);
                close(udp_sockfd);
                close(user_sockfd);
                fprintf(stderr, "Error: Unable to read the full command from User.\n");
                exit(EXIT_SUCCESS);
            }
            command[COMMAND_SIZE-1] = EOS;

            // Print the command read from the tcp socket
            verbose_message(verbose, "Command = %s | ", command);

            // Decide which operation the user requested and respond
            if (strcmp(command, UPLOAD) == 0)           // Upload command requested
            {
                // Define auxilary variables
                int command_status_size = COMMAND_SIZE+STATUS_SIZE+1;
                char command_status[COMMAND_SIZE+STATUS_SIZE+1], uid[UID_SIZE+1], tid[TID_SIZE+1], filename[FILENAME_SIZE+1], filesize[FILE_SIZE_DIG+1];
                
                // Read the request uid
                if (tcp_read(user_sockfd, uid, UID_SIZE) != UID_SIZE)
                {
                    bzero(command, command_size);
                    strcpy(command, PROTOCOL_ERROR);
                    strcat(command, "\n");
                    tcp_write(user_sockfd, command);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: Unable to read the full uid from User.\n");
                    exit(EXIT_SUCCESS);
                }
                uid[UID_SIZE-1] = EOS;

                // Print the uid read from the tcp socket
                verbose_message(verbose, "UID = %s | ", uid);

                // Read the request tid
                if (tcp_read(user_sockfd, tid, TID_SIZE) != TID_SIZE)
                {
                    bzero(command, command_size);
                    strcpy(command, PROTOCOL_ERROR);
                    strcat(command, "\n");
                    tcp_write(user_sockfd, command);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: Unable to read the full tid from User.\n");
                    exit(EXIT_SUCCESS);
                }
                tid[TID_SIZE-1] = EOS;

                // Print the tid read from the tcp socket
                verbose_message(verbose, "TID = %s | ", tid);

                // Read the request filename
                if (tcp_read(user_sockfd, filename, FILENAME_SIZE) != FILENAME_SIZE)
                {
                    bzero(command, command_size);
                    strcpy(command, PROTOCOL_ERROR);
                    strcat(command, "\n");
                    tcp_write(user_sockfd, command);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: Unable to read the full filename from User.\n");
                    exit(EXIT_SUCCESS);
                }
                filename[FILENAME_SIZE-1] = EOS;

                // Print the filename read from the tcp socket
                verbose_message(verbose, "Filename = %s | ", filename);

                // Read the request filesize
                if (tcp_read(user_sockfd, filesize, FILE_SIZE_DIG) != FILE_SIZE_DIG)
                {
                    bzero(command, command_size);
                    strcpy(command, PROTOCOL_ERROR);
                    strcat(command, "\n");
                    tcp_write(user_sockfd, command);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: Unable to read the full size from User.\n");
                    exit(EXIT_SUCCESS);
                }
                filesize[FILE_SIZE_DIG-1] = EOS;

                // Print the filesize read from the tcp socket
                verbose_message(verbose, "Size = %s | ", filesize);

                // Obtain the data size as an integer
                int data_size = atoi(filesize);

                // Allocate an array with the size of the data
                char* data = (char*) malloc(data_size*sizeof(char));
                if (!data)
                {
                    bzero(command, command_size);
                    strcpy(command, PROTOCOL_ERROR);
                    strcat(command, "\n");
                    tcp_write(user_sockfd, command);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: Unable to allocate memory for the required data size from User.\n");
                    exit(EXIT_SUCCESS);
                }

                // Read the request data
                if (tcp_read(user_sockfd, data, data_size) != data_size)
                {
                    bzero(command, command_size);
                    strcpy(command, PROTOCOL_ERROR);
                    strcat(command, "\n");
                    tcp_write(user_sockfd, command);
                    free(data);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: Unable to read the full data from User.\n");
                    exit(EXIT_SUCCESS);
                }
                data[data_size-1] = EOS;

                // Print the data read from the tcp socket
                verbose_message(verbose, "Data = %s | ", data);

                // Prepare the validation message to send to the AS
                char vld[COMMAND_SIZE+UID_SIZE+TID_SIZE+1];
                bzero(vld, COMMAND_SIZE+UID_SIZE+TID_SIZE);
                strcpy(vld, VALIDATE_FILE);
                strcat(vld, " ");
                strcat(vld, uid);
                strcat(vld, " ");
                strcat(vld, tid);
                strcat(vld, "\n");

                // Send the message to the AS
                if (udp_write(udp_sockfd, vld, (struct sockaddr *) &udp_servaddr, sizeof(udp_servaddr)) == false)
                {
                    bzero(command, command_size);
                    strcpy(command, PROTOCOL_ERROR);
                    strcat(command, "\n");
                    tcp_write(user_sockfd, command);
                    free(data);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: Unable to send validation request to AS.\n");
                    exit(EXIT_FAILURE);
                }

                // Receive the command response from the AS
                if (udp_read(udp_sockfd, command, COMMAND_SIZE, (struct sockaddr *) &udp_servaddr) != COMMAND_SIZE)
                {
                    bzero(command, command_size);
                    strcpy(command, PROTOCOL_ERROR);
                    strcat(command, "\n");
                    tcp_write(user_sockfd, command);
                    free(data);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: Unable to read validation command from AS.\n");
                    exit(EXIT_FAILURE);
                }
                command[COMMAND_SIZE-1] = EOS;

                // Verify AS command response
                if (strcmp(command, VAL_FILE_RESPONSE))
                {
                    bzero(command_status, command_status_size);
                    strcpy(command_status, UPL_RESPONSE);
                    strcat(command_status, " ");
                    strcat(command_status, AS_VALIDATION_ERROR);
                    strcat(command_status, "\n");
                    tcp_write(user_sockfd, command_status);
                    free(data);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: %s command from AS not valid.\n", command);
                    exit(EXIT_SUCCESS);
                }

                // Receive the uid response from the AS
                char as_uid[UID_SIZE];
                if (udp_read(udp_sockfd, as_uid, UID_SIZE, (struct sockaddr *) &udp_servaddr) != UID_SIZE)
                {
                    bzero(command, command_size);
                    strcpy(command, PROTOCOL_ERROR);
                    strcat(command, "\n");
                    tcp_write(user_sockfd, command);
                    free(data);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: Unable to read validation uid from AS.\n");
                    exit(EXIT_FAILURE);
                }
                as_uid[UID_SIZE-1] = EOS;

                // Verify AS uid response
                if (strcmp(as_uid, uid))
                {
                    bzero(command_status, command_status_size);
                    strcpy(command_status, UPL_RESPONSE);
                    strcat(command_status, " ");
                    strcat(command_status, AS_VALIDATION_ERROR);
                    strcat(command_status, "\n");
                    tcp_write(user_sockfd, command_status);
                    free(data);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: %s uid from AS not valid.\n", uid);
                    exit(EXIT_SUCCESS);
                }

                // Receive the tid response from the AS
                char as_tid[TID_SIZE];
                if (udp_read(udp_sockfd, as_tid, TID_SIZE, (struct sockaddr *) &udp_servaddr) != TID_SIZE)
                {
                    bzero(command, command_size);
                    strcpy(command, PROTOCOL_ERROR);
                    strcat(command, "\n");
                    tcp_write(user_sockfd, command);
                    free(data);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: Unable to read validation tid from AS.\n");
                    exit(EXIT_FAILURE);
                }
                as_tid[TID_SIZE-1] = EOS;

                // Verify AS tid response
                if (strcmp(as_tid, tid))
                {
                    bzero(command_status, command_status_size);
                    strcpy(command_status, UPL_RESPONSE);
                    strcat(command_status, " ");
                    strcat(command_status, AS_VALIDATION_ERROR);
                    strcat(command_status, "\n");
                    tcp_write(user_sockfd, command_status);
                    free(data);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: %s tid from AS not valid.\n", tid);
                    exit(EXIT_SUCCESS);
                }

                // Receive the fop response from the AS
                char as_fop[FOP_SIZE];
                if (udp_read(udp_sockfd, as_fop, FOP_SIZE, (struct sockaddr *) &udp_servaddr) != FOP_SIZE)
                {
                    bzero(command, command_size);
                    strcpy(command, PROTOCOL_ERROR);
                    strcat(command, "\n");
                    tcp_write(user_sockfd, command);
                    free(data);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: Unable to read validation fop from AS.\n");
                    exit(EXIT_FAILURE);
                }
                as_fop[FOP_SIZE-1] = EOS;

                // Verify AS fop response
                if (strcmp(as_fop, USER_UPLOAD_SHORT))
                {
                    bzero(command_status, command_status_size);
                    strcpy(command_status, UPL_RESPONSE);
                    strcat(command_status, " ");
                    strcat(command_status, AS_VALIDATION_ERROR);
                    strcat(command_status, "\n");
                    tcp_write(user_sockfd, command_status);
                    free(data);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: %s fop from AS not valid.\n", as_fop);
                    exit(EXIT_SUCCESS);
                }

                // Receive the filename response from the AS
                char as_filename[FILENAME_SIZE];
                if (udp_read(udp_sockfd, as_filename, FILENAME_SIZE, (struct sockaddr *) &udp_servaddr) != FILENAME_SIZE)
                {
                    bzero(command, command_size);
                    strcpy(command, PROTOCOL_ERROR);
                    strcat(command, "\n");
                    tcp_write(user_sockfd, command);
                    free(data);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: Unable to read validation filename.\n");
                    exit(EXIT_FAILURE);
                }
                as_filename[FILENAME_SIZE-1] = EOS;

                // Verify AS filename response
                if (strcmp(as_filename, filename))
                {
                    bzero(command_status, command_status_size);
                    strcpy(command_status, UPL_RESPONSE);
                    strcat(command_status, " ");
                    strcat(command_status, AS_VALIDATION_ERROR);
                    strcat(command_status, "\n");
                    tcp_write(user_sockfd, command_status);
                    free(data);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: %s filename from AS not valid.\n", filename);
                    exit(EXIT_SUCCESS);
                }

                // Verify if the user directory already exists
                if (!find_user_directory(uid))
                {
                    // If not, creates a new one
                    if (!make_user_directory(uid))
                    {
                        bzero(command, command_size);
                        strcpy(command, PROTOCOL_ERROR);
                        strcat(command, "\n");
                        tcp_write(user_sockfd, command);
                        free(data);
                        close(udp_sockfd);
                        close(user_sockfd);
                        exit(EXIT_FAILURE);
                    }
                }

                // Verify if the filename is duplicated
                if (find_user_filename(uid, filename))
                {
                    bzero(command_status, command_status_size);
                    strcpy(command_status, UPL_RESPONSE);
                    strcat(command_status, " ");
                    strcat(command_status, DUPLICATED_FILE);
                    strcat(command_status, "\n");
                    tcp_write(user_sockfd, command_status);
                    free(data);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: Unable to upload the file because it already exists.\n");
                    exit(EXIT_SUCCESS);
                }

                // Verify if the user already has the maximum permitted files stored
                if (reached_user_file_limit(uid, USERS_DIR_SIZE))
                {
                    bzero(command_status, command_status_size);
                    strcpy(command_status, UPL_RESPONSE);
                    strcat(command_status, " ");
                    strcat(command_status, LIMIT_FILES_REACHED);
                    strcat(command_status, "\n");
                    tcp_write(user_sockfd, command_status);
                    free(data);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: Unable to upload the file because it already exists.\n");
                    exit(EXIT_SUCCESS);
                }

                // Create the requested filename with the data
                if (!create_user_file(uid, filename, data))
                {
                    bzero(command, command_size);
                    strcpy(command, PROTOCOL_ERROR);
                    strcat(command, "\n");
                    tcp_write(user_sockfd, command);
                    free(data);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: Unable to upload the file because it already exists.\n");
                    exit(EXIT_SUCCESS);
                }

                bzero(command_status, command_status_size);
                strcpy(command_status, UPL_RESPONSE);
                strcat(command_status, " ");
                strcat(command_status, OK);
                strcat(command_status, "\n");
                tcp_write(user_sockfd, command_status);
                verbose_message(verbose, "INFORM: Response to User%s\n", command_status);
                free(data);
                close(udp_sockfd);
                close(user_sockfd);
                exit(EXIT_SUCCESS);
                
            }
            else if (strcmp(command, DELETE) == 0)      // Delete command requested
            {
                // Define auxilary variables
                int command_status_size = COMMAND_SIZE+STATUS_SIZE+1;
                char command_status[COMMAND_SIZE+STATUS_SIZE+1], uid[UID_SIZE+1], tid[TID_SIZE+1], filename[FILENAME_SIZE+1];
                
                // Read the request uid
                if (tcp_read(user_sockfd, uid, UID_SIZE) != UID_SIZE)
                {
                    bzero(command, command_size);
                    strcpy(command, PROTOCOL_ERROR);
                    strcat(command, "\n");
                    tcp_write(user_sockfd, command);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: Unable to read the full uid from User.\n");
                    exit(EXIT_SUCCESS);
                }
                uid[UID_SIZE-1] = EOS;

                // Print the uid read from the tcp socket
                verbose_message(verbose, "UID = %s | ", uid);

                // Read the request tid
                if (tcp_read(user_sockfd, tid, TID_SIZE) != TID_SIZE)
                {
                    bzero(command, command_size);
                    strcpy(command, PROTOCOL_ERROR);
                    strcat(command, "\n");
                    tcp_write(user_sockfd, command);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: Unable to read the full tid from User.\n");
                    exit(EXIT_SUCCESS);
                }
                tid[TID_SIZE-1] = EOS;

                // Print the tid read from the tcp socket
                verbose_message(verbose, "TID = %s | ", tid);

                // Read the request filename
                if (tcp_read(user_sockfd, filename, FILENAME_SIZE) != FILENAME_SIZE)
                {
                    bzero(command, command_size);
                    strcpy(command, PROTOCOL_ERROR);
                    strcat(command, "\n");
                    tcp_write(user_sockfd, command);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: Unable to read the full filename from User.\n");
                    exit(EXIT_SUCCESS);
                }
                filename[FILENAME_SIZE-1] = EOS;

                // Print the filename read from the tcp socket
                verbose_message(verbose, "Filename = %s | ", filename);

                // Prepare the validation message to send to the AS
                char vld[COMMAND_SIZE+UID_SIZE+TID_SIZE+1];
                bzero(vld, COMMAND_SIZE+UID_SIZE+TID_SIZE);
                strcpy(vld, VALIDATE_FILE);
                strcat(vld, " ");
                strcat(vld, uid);
                strcat(vld, " ");
                strcat(vld, tid);
                strcat(vld, "\n");

                // Send the message to the AS
                if (udp_write(udp_sockfd, vld, (struct sockaddr *) &udp_servaddr, udp_servaddr.sin_len) == false)
                {
                    bzero(command, command_size);
                    strcpy(command, PROTOCOL_ERROR);
                    strcat(command, "\n");
                    tcp_write(user_sockfd, command);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: Unable to send validation request to AS.\n");
                    exit(EXIT_FAILURE);
                }

                // Receive the command response from the AS
                if (udp_read(udp_sockfd, command, COMMAND_SIZE, (struct sockaddr *) &udp_servaddr) != COMMAND_SIZE)
                {
                    bzero(command, command_size);
                    strcpy(command, PROTOCOL_ERROR);
                    strcat(command, "\n");
                    tcp_write(user_sockfd, command);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: Unable to read validation command from AS.\n");
                    exit(EXIT_FAILURE);
                }
                command[COMMAND_SIZE-1] = EOS;

                // Verify AS command response
                if (strcmp(command, VAL_FILE_RESPONSE))
                {
                    bzero(command_status, command_status_size);
                    strcpy(command_status, DEL_RESPONSE);
                    strcat(command_status, " ");
                    strcat(command_status, AS_VALIDATION_ERROR);
                    strcat(command_status, "\n");
                    tcp_write(user_sockfd, command_status);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: %s command from AS not valid.\n", command);
                    exit(EXIT_SUCCESS);
                }

                // Receive the uid response from the AS
                char as_uid[UID_SIZE];
                if (udp_read(udp_sockfd, as_uid, UID_SIZE, (struct sockaddr *) &udp_servaddr) != UID_SIZE)
                {
                    bzero(command, command_size);
                    strcpy(command, PROTOCOL_ERROR);
                    strcat(command, "\n");
                    tcp_write(user_sockfd, command);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: Unable to read validation uid from AS.\n");
                    exit(EXIT_FAILURE);
                }
                as_uid[UID_SIZE-1] = EOS;

                // Verify AS uid response
                if (strcmp(as_uid, uid))
                {
                    bzero(command_status, command_status_size);
                    strcpy(command_status, DEL_RESPONSE);
                    strcat(command_status, " ");
                    strcat(command_status, AS_VALIDATION_ERROR);
                    strcat(command_status, "\n");
                    tcp_write(user_sockfd, command_status);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: %s uid from AS not valid.\n", uid);
                    exit(EXIT_SUCCESS);
                }

                // Receive the tid response from the AS
                char as_tid[TID_SIZE];
                if (udp_read(udp_sockfd, as_tid, TID_SIZE, (struct sockaddr *) &udp_servaddr) != TID_SIZE)
                {
                    bzero(command, command_size);
                    strcpy(command, PROTOCOL_ERROR);
                    strcat(command, "\n");
                    tcp_write(user_sockfd, command);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: Unable to read validation tid from AS.\n");
                    exit(EXIT_FAILURE);
                }
                as_tid[TID_SIZE-1] = EOS;

                // Verify AS tid response
                if (strcmp(as_tid, tid))
                {
                    bzero(command_status, command_status_size);
                    strcpy(command_status, DEL_RESPONSE);
                    strcat(command_status, " ");
                    strcat(command_status, AS_VALIDATION_ERROR);
                    strcat(command_status, "\n");
                    tcp_write(user_sockfd, command_status);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: %s tid from AS not valid.\n", tid);
                    exit(EXIT_SUCCESS);
                }

                // Receive the fop response from the AS
                char as_fop[FOP_SIZE];
                if (udp_read(udp_sockfd, as_fop, FOP_SIZE, (struct sockaddr *) &udp_servaddr) != FOP_SIZE)
                {
                    bzero(command, command_size);
                    strcpy(command, PROTOCOL_ERROR);
                    strcat(command, "\n");
                    tcp_write(user_sockfd, command);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: Unable to read validation fop from AS.\n");
                    exit(EXIT_FAILURE);
                }
                as_fop[FOP_SIZE-1] = EOS;

                // Verify AS fop response
                if (strcmp(as_fop, USER_DELETE_SHORT))
                {
                    bzero(command_status, command_status_size);
                    strcpy(command_status, DEL_RESPONSE);
                    strcat(command_status, " ");
                    strcat(command_status, AS_VALIDATION_ERROR);
                    strcat(command_status, "\n");
                    tcp_write(user_sockfd, command_status);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: %s fop from AS not valid.\n", as_fop);
                    exit(EXIT_SUCCESS);
                }

                // Receive the filename response from the AS
                char as_filename[FILENAME_SIZE];
                if (udp_read(udp_sockfd, as_filename, FILENAME_SIZE, (struct sockaddr *) &udp_servaddr) != FILENAME_SIZE)
                {
                    bzero(command, command_size);
                    strcpy(command, PROTOCOL_ERROR);
                    strcat(command, "\n");
                    tcp_write(user_sockfd, command);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: Unable to read validation filename.\n");
                    exit(EXIT_FAILURE);
                }
                as_filename[FILENAME_SIZE-1] = EOS;

                // Verify AS filename response
                if (strcmp(as_filename, filename))
                {
                    bzero(command_status, command_status_size);
                    strcpy(command_status, DEL_RESPONSE);
                    strcat(command_status, " ");
                    strcat(command_status, AS_VALIDATION_ERROR);
                    strcat(command_status, "\n");
                    tcp_write(user_sockfd, command_status);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: %s filename from AS not valid.\n", filename);
                    exit(EXIT_SUCCESS);
                }

                // Verify if the user directory and user filename already exists
                if (find_user_directory(uid) && find_user_filename(uid, filename))
                {
                    if (!delete_user_file(uid, filename))
                    {
                        bzero(command, command_size);
                        strcpy(command, PROTOCOL_ERROR);
                        strcat(command, "\n");
                        tcp_write(user_sockfd, command);
                        close(udp_sockfd);
                        close(user_sockfd);
                        fprintf(stderr, "Error: Unable to delete the user filename.\n");
                        exit(EXIT_FAILURE);
                    }
                }

                // Respond ok to the User
                bzero(command_status, command_status_size);
                strcpy(command_status, DEL_RESPONSE);
                strcat(command_status, " ");
                strcat(command_status, OK);
                strcat(command_status, "\n");
                tcp_write(user_sockfd, command_status);
                verbose_message(verbose, "INFORM: Response to User%s\n", command_status);
                close(udp_sockfd);
                close(user_sockfd);
                exit(EXIT_SUCCESS);
            }
            else if (strcmp(command, REMOVE) == 0)      // Remove command requested
            {
                // Define auxilary variables
                int command_status_size = COMMAND_SIZE+STATUS_SIZE+1;
                char command_status[COMMAND_SIZE+STATUS_SIZE+1], uid[UID_SIZE+1], tid[TID_SIZE+1];
                
                // Read the request uid
                if (tcp_read(user_sockfd, uid, UID_SIZE) != UID_SIZE)
                {
                    bzero(command, command_size);
                    strcpy(command, PROTOCOL_ERROR);
                    strcat(command, "\n");
                    tcp_write(user_sockfd, command);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: Unable to read the full uid from User.\n");
                    exit(EXIT_SUCCESS);
                }
                uid[UID_SIZE-1] = EOS;

                // Print the uid read from the tcp socket
                verbose_message(verbose, "UID = %s | ", uid);

                // Read the request tid
                if (tcp_read(user_sockfd, tid, TID_SIZE) != TID_SIZE)
                {
                    bzero(command, command_size);
                    strcpy(command, PROTOCOL_ERROR);
                    strcat(command, "\n");
                    tcp_write(user_sockfd, command);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: Unable to read the full tid from User.\n");
                    exit(EXIT_SUCCESS);
                }
                tid[TID_SIZE-1] = EOS;

                // Print the tid read from the tcp socket
                verbose_message(verbose, "TID = %s | ", tid);

                // Prepare the validation message to send to the AS
                char vld[COMMAND_SIZE+UID_SIZE+TID_SIZE+1];
                bzero(vld, COMMAND_SIZE+UID_SIZE+TID_SIZE);
                strcpy(vld, VALIDATE_FILE);
                strcat(vld, " ");
                strcat(vld, uid);
                strcat(vld, " ");
                strcat(vld, tid);
                strcat(vld, "\n");

                // Send the message to the AS
                if (udp_write(udp_sockfd, vld, (struct sockaddr *) &udp_servaddr, udp_servaddr.sin_len) == false)
                {
                    bzero(command, command_size);
                    strcpy(command, PROTOCOL_ERROR);
                    strcat(command, "\n");
                    tcp_write(user_sockfd, command);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: Unable to send validation request to AS.\n");
                    exit(EXIT_FAILURE);
                }

                // Receive the command response from the AS
                if (udp_read(udp_sockfd, command, COMMAND_SIZE, (struct sockaddr *) &udp_servaddr) != COMMAND_SIZE)
                {
                    bzero(command, command_size);
                    strcpy(command, PROTOCOL_ERROR);
                    strcat(command, "\n");
                    tcp_write(user_sockfd, command);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: Unable to read validation command from AS.\n");
                    exit(EXIT_FAILURE);
                }
                command[COMMAND_SIZE-1] = EOS;

                // Verify AS command response
                if (strcmp(command, VAL_FILE_RESPONSE))
                {
                    bzero(command_status, command_status_size);
                    strcpy(command_status, REM_RESPONSE);
                    strcat(command_status, " ");
                    strcat(command_status, AS_VALIDATION_ERROR);
                    strcat(command_status, "\n");
                    tcp_write(user_sockfd, command_status);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: %s command from AS not valid.\n", command);
                    exit(EXIT_SUCCESS);
                }

                // Receive the uid response from the AS
                char as_uid[UID_SIZE];
                if (udp_read(udp_sockfd, as_uid, UID_SIZE, (struct sockaddr *) &udp_servaddr) != UID_SIZE)
                {
                    bzero(command, command_size);
                    strcpy(command, PROTOCOL_ERROR);
                    strcat(command, "\n");
                    tcp_write(user_sockfd, command);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: Unable to read validation uid from AS.\n");
                    exit(EXIT_FAILURE);
                }
                as_uid[UID_SIZE-1] = EOS;

                // Verify AS uid response
                if (strcmp(as_uid, uid))
                {
                    bzero(command_status, command_status_size);
                    strcpy(command_status, REM_RESPONSE);
                    strcat(command_status, " ");
                    strcat(command_status, AS_VALIDATION_ERROR);
                    strcat(command_status, "\n");
                    tcp_write(user_sockfd, command_status);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: %s uid from AS not valid.\n", uid);
                    exit(EXIT_SUCCESS);
                }

                // Receive the tid response from the AS
                char as_tid[TID_SIZE];
                if (udp_read(udp_sockfd, as_tid, TID_SIZE, (struct sockaddr *) &udp_servaddr) != TID_SIZE)
                {
                    bzero(command, command_size);
                    strcpy(command, PROTOCOL_ERROR);
                    strcat(command, "\n");
                    tcp_write(user_sockfd, command);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: Unable to read validation tid from AS.\n");
                    exit(EXIT_FAILURE);
                }
                as_tid[TID_SIZE-1] = EOS;

                // Verify AS tid response
                if (strcmp(as_tid, tid))
                {
                    bzero(command_status, command_status_size);
                    strcpy(command_status, REM_RESPONSE);
                    strcat(command_status, " ");
                    strcat(command_status, AS_VALIDATION_ERROR);
                    strcat(command_status, "\n");
                    tcp_write(user_sockfd, command_status);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: %s tid from AS not valid.\n", tid);
                    exit(EXIT_SUCCESS);
                }

                // Receive the fop response from the AS
                char as_fop[FOP_SIZE];
                if (udp_read(udp_sockfd, as_fop, FOP_SIZE, (struct sockaddr *) &udp_servaddr) != FOP_SIZE)
                {
                    bzero(command, command_size);
                    strcpy(command, PROTOCOL_ERROR);
                    strcat(command, "\n");
                    tcp_write(user_sockfd, command);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: Unable to read validation fop from AS.\n");
                    exit(EXIT_FAILURE);
                }
                as_fop[FOP_SIZE-1] = EOS;

                // Verify AS fop response
                if (strcmp(as_fop, USER_REMOVE_SHORT))
                {
                    bzero(command_status, command_status_size);
                    strcpy(command_status, REM_RESPONSE);
                    strcat(command_status, " ");
                    strcat(command_status, AS_VALIDATION_ERROR);
                    strcat(command_status, "\n");
                    tcp_write(user_sockfd, command_status);
                    close(udp_sockfd);
                    close(user_sockfd);
                    fprintf(stderr, "Error: %s fop from AS not valid.\n", as_fop);
                    exit(EXIT_SUCCESS);
                }

                // Verify if the user directory and user filename already exists
                if (find_user_directory(uid))
                {
                    if (!remove_user_dir(uid))
                    {
                        bzero(command, command_size);
                        strcpy(command, PROTOCOL_ERROR);
                        strcat(command, "\n");
                        tcp_write(user_sockfd, command);
                        close(udp_sockfd);
                        close(user_sockfd);
                        fprintf(stderr, "Error: Unable to remove the user directory.\n");
                        exit(EXIT_FAILURE);
                    }
                }

                // Respond ok to the User
                bzero(command_status, command_status_size);
                strcpy(command_status, REM_RESPONSE);
                strcat(command_status, " ");
                strcat(command_status, OK);
                strcat(command_status, "\n");
                tcp_write(user_sockfd, command_status);
                verbose_message(verbose, "INFORM: Response to User%s\n", command_status);
                close(udp_sockfd);
                close(user_sockfd);
                exit(EXIT_SUCCESS);
            }
            else if (strcmp(command, RETRIEVE) == 0)    // Retrieve command requested
            {

            }
            else if (strcmp(command, LIST) == 0)        // List command requested
            {

            }
            else                                        // Invalid command requested
            {
            }

            // Respond to the user


            
            
            // Conversation is handled. Closes the user socket and exits with success
            close(user_sockfd);
            exit(EXIT_SUCCESS);
        }
        else
        {
            // Closes the user_fd as it wont be used by the parent process
            close(user_sockfd);
            continue;
        }
    }

    // Program terminated. Closed server socket and exits with success
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

Boolean find_user_filename(char* uid, char* filename)
{
    char aux[MAIN_DIR_NAME_SIZE+UID_SIZE];
    strcpy(aux, MAIN_DIR_NAME);
    strcat(aux, uid);
    DIR *dir = opendir(aux);
    struct dirent *file;
    while ((file=readdir(dir)) != NULL)
    {
        if(strcmp(file->d_name, filename) == 0)
        {
            closedir(dir);
            return true;
        }
    }
    closedir(dir);
    return false;
}

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
        fprintf(stderr, "Error: Unable to open %s path\n", aux);
        return false;
    }
    fprintf(fp, "%s", data);
    fclose(fp);
    printf("File %s created\n", aux);
    return true;
}

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
        fprintf(stderr, "Error: Unable to remove %s\n", aux);
        return false;
    } 
    printf("File %s removed\n", aux);
    return true;
}

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
                    fprintf(stderr, "Error: Unable to remove file %s\n", file_path);
                    closedir(d);
                    return false;
                }
            }
        }
        if (rmdir(aux)) // removes the directory
        {
            fprintf(stderr, "Error: Unable to remove directory %s\n", aux);
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

// +------------------------------------------+
// | Signal Threatment Functions              |
// +------------------------------------------+
// Handle SIGINT signal (CTRL + C)
void sigint_handler()
{
    running_flag = false;
    close(tcp_sockfd);      // This will unblock accept()
}
