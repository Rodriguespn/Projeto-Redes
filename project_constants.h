#ifndef PROJECT_CONSTANTS_H
#define PROJECT_CONSTANTS_H

enum {false, true};

#define SIZE 128
#define ERROR -1
#define GN 38 // Group number

#define IP "tejo.tecnico.ulisboa.pt"
#define PDPORT 57000 // Personal Device default IP
#define ASPORT 58000 // Authentication System default IP

/* COMMUNICATION PROTOCOLS SPECIFICATION */
// error
#define PROTOCOL_ERROR "ERR"

// status
#define OK      "OK"
#define NOT_OK  "NOK"

// PD-AS Protocol
#define REGISTRATION "REG"
#define REG_RESPONSE "RRG"
#define VALIDATION "VLC"
#define VAL_RESPONSE "RVC"
#define UNREGISTRATION "UNR"
#define UNR_RESPONSE "RUN"

// User-AS Protocol 
#define LOGIN "LOG"
#define LOG_RESPONSE "RLO"
#define REQUEST "REQ"
#define REQ_RESPONSE "RRQ"
#define AUTHENTICATION "AUT"
#define AUT_RESPONSE "RAU"

// User-AS Protocol 
#define
#define
#define
#define
#define


#endif /* PROJECT_CONSTANTS_H */