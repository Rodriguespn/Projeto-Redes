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

                int n;
                // Read the request tid
                if ((n = tcp_read(user_sockfd, tid, TID_SIZE)) != TID_SIZE || strlen(tid) != TID_SIZE)
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

                printf("tid_size = %ld\n", strlen(tid));

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
                if (udp_write(udp_sockfd, vld, (struct sockaddr *) &udp_servaddr, sizeof(udp_servaddr)) == false)
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
                if (udp_write(udp_sockfd, vld, (struct sockaddr *) &udp_servaddr, sizeof(udp_servaddr)) == false)
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
                bzero(command, command_size);
                strcpy(command, PROTOCOL_ERROR);
                strcat(command, "\n");
                tcp_write(user_sockfd, command);
                close(udp_sockfd);
                close(user_sockfd);
                fprintf(stderr, "Error: Invalid command from User.\n");
            }