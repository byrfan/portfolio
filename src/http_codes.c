#include "http_codes.h"

inline const char* get_status_message(int code) {
    for (int i = 0; HTTP_STATUS[i].code != 0; i++) {
        if (HTTP_STATUS[i].code == code)
            return HTTP_STATUS[i].message;
    }
    return "Unknown";
}

const char* get_status_page(int code) {
     for (int i = 0; HTTP_STATUS[i].code != 0; i++) {
        if (HTTP_STATUS[i].code == code)
            return HTTP_STATUS[i].page;
    }
    return "Unknown";
    
} 
