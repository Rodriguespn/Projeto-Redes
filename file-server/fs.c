#include "fs.h"

// +------------------------------------------+
// | Global Variables                         |
// +------------------------------------------+
int tcp_sockfd;                 // used by sigint_handler
Boolean running_flag = true;    // used by sigint_handler

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
  
    // Bind TCP socket to the assigned IP address and Port 
    if ((bind(tcp_sockfd, (struct sockaddr*) &tcp_servaddr, sizeof(tcp_servaddr))) != 0)
    { 
        fprintf(stderr, "Unable to bind the tcp socket.\n");
        exit(EXIT_FAILURE);  
    } 
  
    // Define UDP socket variables (Communication with Authentication Server)
    int udp_sockfd;
    struct sockaddr_in udp_servaddr;
    
    // Create UDP socket 
    udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sockfd == ERROR)
    {
        fprintf(stderr, "Unable to create the udp socket.\n");
        exit(EXIT_FAILURE);
    }
    
    // Assign IP address and PORT to the UDP socket
    bzero(&udp_servaddr, sizeof(udp_servaddr));
    udp_servaddr.sin_family = AF_INET; 
    udp_servaddr.sin_addr.s_addr = inet_addr(as_ip); 
    udp_servaddr.sin_port = as_port;

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
        if (user_sockfd == EINTR)
            continue;
        else if (user_sockfd < 0) { 
            fprintf(stderr, "Unable to accept TCP connections.");
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
            int n;
            char command[COMMAND_SIZE], uid[UID_SIZE], tid[TID_SIZE], filename[FILENAME_SIZE], fop[FOP_SIZE], filesize[FILE_SIZE_DIG];
            
            // Wait for a request (Blocks here)
            // Read the request command
            if (tcp_read(user_sockfd, command, COMMAND_SIZE) != COMMAND_SIZE)
            {
                bzero(command, COMMAND_SIZE);
                strcat(command, PROTOCOL_ERROR);
                command[COMMAND_SIZE-1] = '\n';
                tcp_write(user_sockfd, command);
                close(user_sockfd);
                exit(EXIT_SUCCESS);
            }
            command[COMMAND_SIZE-1] = '\0';

            // Decide which operation the user requested and respond
            if (strcmp(command, UPLOAD) == 0)          // Upload command requested
            {
                // Read the request uid
                if (tcp_read(user_sockfd, uid, UID_SIZE) != UID_SIZE)
                {
                    bzero(command, COMMAND_SIZE);
                    strcat(command, PROTOCOL_ERROR);
                    command[COMMAND_SIZE-1] = '\n';
                    tcp_write(user_sockfd, command);
                }
                
                if (chop_next_argument(uid) && chop_next_argument(tid) && chop_next_argument(filename) && chop_next_argument(filesize))
            }
            else if (strcmp(command, RETRIEVE) == 0)    // Retrieve command requested
            {

            }
            else if (strcmp(command, LIST) == 0)        // List command requested
            {

            }
            else if (strcmp(command, DELETE) == 0)      // Delete command requested
            {

            }
            else if (strcmp(command, REMOVE) == 0)      // Remove command requested
            {

            }
            else                                        // Invalid command requested
            {
                strcpy(response, PROTOCOL_ERROR);
            }

            // Respond to the user
            tcp_write(user_sockfd, response);


            
            
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
    close(tcp_sockfd); 
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
// | User Conversation Functions              |
// +------------------------------------------+
Boolean chop_first_argument(char* buffer, char* argument)
{
    char *token;
    if(!(token = strtok(buffer, " "))) 
        return false;
    strcpy(argument, token);
    return true;
}

Boolean chop_next_argument(char* argument)
{
    char *token;
    if(!(token = strtok(NULL, " "))) 
        return false;
    strcpy(argument, token);
    return true;
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
