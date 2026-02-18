#define _GNU_SOURCE // for accept4 (macro for epoll)

#include "parser.h"
#include "http_codes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_EVENTS 64
#define BUFFER_SIZE 16384

typedef struct response_node {
    char data[8192];
    int len;
    int sent;
    struct response_node *next;
} response_node_t;

typedef struct connection {
    int fd;
    SSL *ssl;
    int state;  // 0=reading, 1=writing, 2=closing
    char buffer[BUFFER_SIZE];
    int bytes_read;
    int bytes_written;
    response_node_t *response_queue;
    response_node_t *current_response;
} connection_t;

// Function declarations


void free_response_queue(connection_t *conn) {
    response_node_t *current = conn->response_queue;
    while (current) {
        response_node_t *next = current->next;
        free(current);
        current = next;
    }
    conn->response_queue = NULL;
    conn->current_response = NULL;
}

void close_connection(connection_t *conn, int epoll_fd) {
    if (!conn) return;
    
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
    
    if (conn->ssl) {
        SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
    }
    
    if (conn->fd >= -1) {
        close(conn->fd);
    }
    
    free_response_queue(conn);
    free(conn);
}

void queue_response(connection_t *conn, int status, const char *type, const char *body) {
    const char* status_message = get_status_message(status);
    
    // Determine response body
    const char* response_body = body;
    if (status != 200 && body == NULL) {
        response_body = get_status_page(status);
    }
    
    // Build full HTTP response
    char response[8192];
    int len = snprintf(response, sizeof(response),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        "%s",
        status,
        status_message,
        type,
        response_body ? strlen(response_body) : 0,
        response_body ? response_body : "");
    
    // Create response node
    response_node_t *node = malloc(sizeof(response_node_t));
    if (!node) return;
    
    memcpy(node->data, response, len);
    node->len = len;
    node->sent = 0;
    node->next = NULL;
    
    // Add to queue
    if (!conn->response_queue) {
        conn->response_queue = node;
        conn->current_response = node;
    } else {
        response_node_t *last = conn->response_queue;
        while (last->next) last = last->next;
        last->next = node;
    }
}

void handle_ssl_accept(connection_t *conn, int epoll_fd) {
    int ret = SSL_accept(conn->ssl);
    
    if (ret == 1) {
        // SSL handshake complete, start reading requests
        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLET;
        ev.data.ptr = conn;
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev);
        return;
    }
    
    int err = SSL_get_error(conn->ssl, ret);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        // Handshake not complete, wait for more data
        struct epoll_event ev;
        ev.events = (err == SSL_ERROR_WANT_READ ? EPOLLIN : EPOLLOUT) | EPOLLET;
        ev.data.ptr = conn;
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev);
        return;
    }
    
    // Real error
    ERR_print_errors_fp(stderr);
    close_connection(conn, epoll_fd);
}

int handle_uri(char* uri, char** content, const char** type) {
    char filepath[512];
    
    printf("\nDEBUG HERE:\n %s\n END DEBUG \n", uri);

    // Remove query parameters if any
    char *qmark = strchr(uri, '?');
    if (qmark) {
        *qmark = '\0';
    }
    
    // Skip leading slashes
    while (*uri == '/') {
        uri++;
    }
    
    // default or landing page
    if (strcmp(uri, "") == 0 || strcmp(uri, "index.html") == 0) {
       snprintf(filepath, sizeof(filepath), "public/index.html"); 
    } else {
        snprintf(filepath, sizeof(filepath), "public/%s", uri);
    }
    
    struct stat st;
    if (stat(filepath, &st) != 0) {
        return 404;
    }
    
    *content = readFile(filepath);
    *type = get_content_type(filepath);
    
    printf("File: %s, Content-Type: %s\n", filepath, *type ? *type : "NULL");
    
    if(*content == NULL) {
        return 500;
    }
    
    return 200;
}

void handle_read(connection_t *conn, int epoll_fd) {
    char buffer[4096];
    int bytes = SSL_read(conn->ssl, buffer, sizeof(buffer) - 1);
    
    if (bytes > 0) {
        buffer[bytes] = '\0';
        
        // Append to connection buffer
        size_t new_size = conn->bytes_read + bytes;
        if (new_size < sizeof(conn->buffer)) {
            memcpy(conn->buffer + conn->bytes_read, buffer, bytes);
            conn->bytes_read = new_size;
            conn->buffer[new_size] = '\0';
        }
        
        // Process all complete requests in buffer
        char *current_pos = conn->buffer;
        char *end_of_request;
        
        while ((end_of_request = strstr(current_pos, "\r\n\r\n")) != NULL) {
            // Found a complete request
            int request_len = end_of_request - current_pos + 4;
            
            // Parse this request
            char method[16], uri[256], version[16];
            sscanf(current_pos, "%s %s %s", method, uri, version);
            
            printf("\n\n\n DEBUG \n\n %s \n\n", uri);
            printf("Processing request: %s %s\n", method, uri);
            
            // Handle this request
            char* content = NULL;
            const char* type = NULL;
            int status = handle_uri(uri, &content, &type);
            
            printf("%d  :   %s\n", status, uri);
            
            // Queue the response
            queue_response(conn, status, type, content);
            
            // Free content if it was allocated
            if (content) {
                free(content);
            }
            
            // Move to next request in buffer
            current_pos = end_of_request + 4;
        }
        
        // Move remaining partial request to start of buffer
        if (current_pos > conn->buffer) {
            int remaining = conn->bytes_read - (current_pos - conn->buffer);
            if (remaining > 0) {
                memmove(conn->buffer, current_pos, remaining);
                conn->bytes_read = remaining;
                conn->buffer[remaining] = '\0';
            } else {
                conn->bytes_read = 0;
                conn->buffer[0] = '\0';
            }
        }
        
        // If we have queued responses, switch to write mode
        if (conn->response_queue) {
            struct epoll_event ev;
            ev.events = EPOLLOUT | EPOLLET;
            ev.data.ptr = conn;
            epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev);
        }
        
        return;
    }
    
    int err = SSL_get_error(conn->ssl, bytes);
    if (err == SSL_ERROR_WANT_READ) {
        // Need more data, stay in EPOLLIN
        return;
    }
    
    if (err == SSL_ERROR_ZERO_RETURN || bytes <= 0) {
        // Connection closed
        close_connection(conn, epoll_fd);
    }
}

void handle_write(connection_t *conn, int epoll_fd) {
    // If no current response, get next from queue
    if (!conn->current_response && conn->response_queue) {
        conn->current_response = conn->response_queue;
        conn->response_queue = conn->response_queue->next;
        conn->current_response->next = NULL;
        conn->bytes_written = 0;
    }
    
    // If no response to write, go back to reading
    if (!conn->current_response) {
        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLET;
        ev.data.ptr = conn;
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev);
        return;
    }
    
    response_node_t *resp = conn->current_response;
    int remaining = resp->len - conn->bytes_written;
    
    if (remaining <= 0) {
        // This response fully sent, move to next
        free(resp);
        conn->current_response = NULL;
        conn->bytes_written = 0;
        
        // Check if more responses queued
        if (conn->response_queue) {
            // Stay in write mode for next response
            return;
        } else {
            // No more responses, go back to reading
            struct epoll_event ev;
            ev.events = EPOLLIN | EPOLLET;
            ev.data.ptr = conn;
            epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev);
        }
        return;
    }
    
    int bytes = SSL_write(conn->ssl, 
                          resp->data + conn->bytes_written, 
                          remaining);
    
    if (bytes > 0) {
        conn->bytes_written += bytes;
        
        if (conn->bytes_written >= resp->len) {
            // Current response fully sent
            free(resp);
            conn->current_response = NULL;
            conn->bytes_written = 0;
            
            // If more responses, we'll get them next time
            // Stay in EPOLLOUT mode
        }
        return;
    }
    
    int err = SSL_get_error(conn->ssl, bytes);
    if (err == SSL_ERROR_WANT_WRITE) {
        // Write buffer full, wait for EPOLLOUT again
        return;
    }
    
    // Real error
    close_connection(conn, epoll_fd);
}

int run_server(SSL_CTX *ctx, int port) {
    // Create socket
    int server_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }
    
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = { INADDR_ANY }
    };
    
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    
    if (listen(server_fd, SOMAXCONN) < 0) {
        perror("listen");
        return 1;
    }
    
    // Create epoll instance
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("epoll_create");
        return 1;
    }
    
    // Add server socket to epoll
    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = server_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev);
    
    printf("HTTPS server running on port %d\n", port);
    
    // Event loop
    while (1) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == server_fd) {
                // New connection
                while (1) {
                    struct sockaddr_in client_addr;
                    socklen_t client_len = sizeof(client_addr);
                    
                    int client_fd = accept4(server_fd, 
                                           (struct sockaddr*)&client_addr,
                                           &client_len,
                                           SOCK_NONBLOCK);
                    
                    if (client_fd < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        perror("accept");
                        continue;
                    }
                    
                    // Create connection object
                    connection_t *conn = calloc(1, sizeof(connection_t));
                    conn->fd = client_fd;
                    conn->ssl = SSL_new(ctx);
                    SSL_set_fd(conn->ssl, client_fd);
                    conn->state = 0;  // SSL handshake
                    
                    // Add to epoll
                    struct epoll_event ev;
                    ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
                    ev.data.ptr = conn;
                    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);
                    
                    // Start SSL handshake
                    handle_ssl_accept(conn, epoll_fd);
                }
            } else {
                // Existing connection
                connection_t *conn = events[i].data.ptr;
                
                if (events[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
                    close_connection(conn, epoll_fd);
                    continue;
                }
                
                if (!conn->ssl) {
                    close_connection(conn, epoll_fd);
                    continue;
                }
                
                if (events[i].events & EPOLLIN) {
                    if (!SSL_is_init_finished(conn->ssl)) {
                        handle_ssl_accept(conn, epoll_fd);
                    } else {
                        handle_read(conn, epoll_fd);
                    }
                }
                
                if (events[i].events & EPOLLOUT) {
                    if (!SSL_is_init_finished(conn->ssl)) {
                        handle_ssl_accept(conn, epoll_fd);
                    } else {
                        handle_write(conn, epoll_fd);
                    }
                }
            }
        }
    }
    
    close(epoll_fd);
    close(server_fd);
    return 0;
}
