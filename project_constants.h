#ifndef PROJECT_CONSTANTS_H
#define PROJECT_CONSTANTS_H

enum {false, true};

#define ERROR   -1
#define GN      38 // Group number

/* APENAS PARA TESTES */
#define SIZE    128
#define IP      "tejo.tecnico.ulisboa.pt" 

#define PDPORT  57000 // Personal Device default Port
#define ASPORT  58000 // Authentication System default Port

/* COMMAND LINE FLAGS */
#define PD_PORT "-d"
#define AS_IP   "-n"
#define AS_PORT "-p"
#define FS_IP   "-m"
#define FS_PORT "-q"
#define VERBOSE "-v"

/* COMMUNICATION PROTOCOLS SPECIFICATION */
// error
#define PROTOCOL_ERROR      "ERR"
#define AS_VALIDATION_ERROR "INV"

// status
#define OK                  "OK"
#define NOT_OK              "NOK"

// PD-AS Protocol
#define REGISTRATION        "REG"
#define REG_RESPONSE        "RRG"
#define VALIDATE_USER       "VLC"
#define VAL_USER_RESPONSE   "RVC"
#define UNREGISTRATION      "UNR"
#define UNR_RESPONSE        "RUN"

// User-AS Protocol 
#define LOGIN               "LOG"
#define LOG_RESPONSE        "RLO"
#define REQUEST             "REQ"
#define REQ_RESPONSE        "RRQ"
#define AUTHENTICATION      "AUT"
#define AUT_RESPONSE        "RAU"

// FS-AS Protocol 
#define VALIDATE_FILE       "VLD"
#define VAL_FILE_RESPONSE   "CNF"

// User-FS Protocol 
#define LIST                "LST"
#define LIS_RESPONSE        "RLS"
#define RETRIVE             "RTV"
#define RET_RESPONSE        "RRT"
#define UPLOAD              "UPL"
#define UPL_RESPONSE        "RUP"
#define DELETE              "DEL"
#define DEL_RESPONSE        "RDL"
#define REMOVE              "REM"
#define REM_RESPONSE        "RRM"

#endif /* PROJECT_CONSTANTS_H */