#ifndef HTTP_CODES_H
#define HTTP_CODES_H

#include <stddef.h>

// Define error pages FIRST as macros
#define ERROR_400 \
    "<!DOCTYPE html>" \
    "<html>" \
    "<head><title>400 Bad Request</title></head>" \
    "<body>" \
    "<h1>400</h1>" \
    "<p>Bad request</p>" \
    "</body>" \
    "</html>"

#define ERROR_401 \
    "<!DOCTYPE html>" \
    "<html>" \
    "<head><title>401 Unauthorized</title></head>" \
    "<body>" \
    "<h1>401</h1>" \
    "<p>Unauthorized</p>" \
    "</body>" \
    "</html>"

#define ERROR_403 \
    "<!DOCTYPE html>" \
    "<html>" \
    "<head><title>403 Forbidden</title></head>" \
    "<body>" \
    "<h1>403</h1>" \
    "<p>Forbidden</p>" \
    "</body>" \
    "</html>"

#define ERROR_404 \
    "<!DOCTYPE html>" \
    "<html>" \
    "<head><title>404 Not Found</title>" \
    "<meta charset=\"UTF-8\">" \
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">" \
    "</head>" \
    "<body>" \
    "<h1>404</h1>" \
    "<p>Page not found</p>" \
    "<hr>" \
    "<small>Web Server</small>" \
    "</body>" \
    "</html>"

#define ERROR_500 \
    "<!DOCTYPE html>" \
    "<html>" \
    "<head><title>500 Internal Server Error</title></head>" \
    "<body>" \
    "<h1>500</h1>" \
    "<p>Something went wrong</p>" \
    "</body>" \
    "</html>"

// Define the struct
typedef struct {
    int code;
    const char* message;
    const char* page;
} HttpStatus;

// Define the array
static const HttpStatus HTTP_STATUS[] = {
    {200, "OK", NULL},
    {400, "Bad Request", ERROR_400},
    {401, "Unauthorized", ERROR_401},
    {403, "Forbidden", ERROR_403},
    {404, "Not Found", ERROR_404},
    {500, "Internal Server Error", ERROR_500},
    {0, NULL, NULL}  // Sentinel
};

const char* get_status_message(int code);
const char* get_status_page(int code);

#endif // HTTP_CODES_H
