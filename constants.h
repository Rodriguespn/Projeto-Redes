#ifndef PROJECT_CONSTANTS_H
#define PROJECT_CONSTANTS_H

typedef enum { false, true } Boolean;

#define STDIN           0
#define STDOUT          1
#define STDERR          2


#define EOS             '\0'    // End of String
#define ERROR           -1      // Error code
#define GN              38      // Group number
#define UID_SIZE        6       // Size of the UID
#define PASSWORD_SIZE   9       // Size of the Password
#define VC_SIZE         5       // Size of the Validation Code
#define FOP_SIZE        2       // Size of the File Operation
#define TID_SIZE        5       // Size of the TID

#define LOCALHOST       "127.0.0.1"

/* APENAS PARA TESTES */
#define SIZE    128
#define IP      "tejo.tecnico.ulisboa.pt" 

#define PDPORT  57000 // Personal Device default Port
#define ASPORT  58000 // Authentication System default Port
#define FSPORT  59000 // File Server default Port

/* COMMAND LINE FLAGS */
#define PD_PORT_FLAG        "-d"
#define AS_IP_FLAG          "-n"
#define AS_PORT_FLAG        "-p"
#define FS_IP_FLAG          "-m"
#define FS_PORT_FLAG        "-q"
#define VERBOSE_FLAG        "-v"

/* USER STDIN COMMANDS */
// Personal Device
#define PD_REGISTRATION     "reg"
#define PD_EXIT             "exit"

// User
#define USER_LOGIN          "login"
#define USER_REQUEST        "req"
#define USER_VAL            "val"
#define USER_LIST           "list"
#define USER_LIST_SHORT     "l"
#define USER_RETRIEVE       "retrive"
#define USER_RETRIEVE_SHORT "r"
#define USER_UPLOAD         "upload"
#define USER_UPLOAD_SHORT   "u"
#define USER_DELETE         "delete"
#define USER_DELETE_SHORT   "d"
#define USER_REMOVE         "remove"
#define USER_REMOVE_SHORT   "x"
#define USER_EXIT           "exit"

// Fops
#define FOP_UPLOAD          "U"
#define FOP_REMOVE          "X"
#define FOP_DELETE          "D"
#define FOP_LIST            "L"
#define FOP_RETRIEVE        "R"

/* COMMUNICATION PROTOCOLS SPECIFICATION */
// error
#define PROTOCOL_ERROR      "ERR"
#define AS_VALIDATION_ERROR "INV"

// status
#define OK                  "OK"
#define NOT_OK              "NOK"
#define NOT_LOGGED_IN       "ELOG"
#define PD_NOT_AVAILABLE    "EPD"
#define INVALID_UID         "EUSER"
#define INVALID_FOP         "EFOP"

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