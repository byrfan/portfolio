#include "http_codes.h"
#include <string.h>
#include <stdlib.h>

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

char* get_extension(char* fn) {
    if (!fn || !*fn) return NULL;
    
    char* dot = strrchr(fn, '.');
    if (!dot || !*(dot + 1) || dot == fn) return NULL;
    
    return dot + 1;
}

const char* get_mime_from_ext(const char* ext) {
    for (const MimeMap* m = MIME_TYPES; m->ext; m++) {
        if (strcmp(m->ext, ext) == 0) {
            return m->mime;
        }
    }
    
    return "application/octet-stream";
}

const char* get_content_type(char* fn) {
    char* ext = get_extension(fn);
    return get_mime_from_ext(ext);
}
