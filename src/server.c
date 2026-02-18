#define _GNU_SOURCE // for accept4

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
    int state;  // 0=handshake, 1=connected
    char buffer[BUFFER_SIZE];
    int bytes_read;
    int bytes_written;
    response_node_t *response_queue;
    response_node_t *current_response;
} connection_t;

// --- Helper Functions ---

void free_response_queue(connection_t *conn) {
    response_node_t *current = conn->response_queue;
    while (current) {
        response_node_t *next = current->next;
        free(current);
        current = next;
    }
    if (conn->current_response) {
        free(conn->current_response);
    }
    conn->response_queue = NULL;
    conn->current_response = NULL;
}

void close_connection(connection_t *conn, int epoll_fd) {
    if (!conn) return;
    
    // Remove from epoll first to stop events
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
    
    if (conn->ssl) {
        SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
    }
    
    if (conn->fd >= 0) {
        close(conn->fd);
    }
    
    free_response_queue(conn);
    free(conn);
}

void queue_response(connection_t *conn, int status, const char *type, const char *body) {
    const char* status_message = get_status_message(status);
    
    const char* response_body = body;
    if (status != 200 && body == NULL) {
        response_body = get_status_page(status);
    }
    
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
        type ? type : "text/plain",
        response_body ? strlen(response_body) : 0,
        response_body ? response_body : "");
    
    if (len >= sizeof(response)) len = sizeof(response) - 1;

    response_node_t *node = calloc(1, sizeof(response_node_t));
    if (!node) return;
    
    memcpy(node->data, response, len);
    node->len = len;
    node->sent = 0;
    
    // Add to queue
    if (!conn->response_queue) {
        conn->response_queue = node;
    } else {
        response_node_t *last = conn->response_queue;
        while (last->next) last = last->next;
        last->next = node;
    }
}

// --- Handlers ---

int handle_ssl_accept(connection_t *conn, int epoll_fd) {
    int ret = SSL_accept(conn->ssl);
    
    if (ret == 1) {
        conn->state = 1;
        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
        ev.data.ptr = conn;
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev);
        return 0;
    }
    
    int err = SSL_get_error(conn->ssl, ret);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        struct epoll_event ev;
        ev.events = (err == SSL_ERROR_WANT_READ ? EPOLLIN : EPOLLOUT) | EPOLLET | EPOLLRDHUP;
        ev.data.ptr = conn;
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev);
        return 0;
    }
    
    close_connection(conn, epoll_fd);
    return -1;
}

int handle_uri(char* uri, char** content, const char** type) {
    char filepath[512];
    char *qmark = strchr(uri, '?');
    if (qmark) *qmark = '\0';
    
    while (*uri == '/') uri++;
    
    if (strcmp(uri, "") == 0 || strcmp(uri, "index.html") == 0) {
       snprintf(filepath, sizeof(filepath), "public/index.html"); 
    } else {
        snprintf(filepath, sizeof(filepath), "public/%s", uri);
    }
    
    struct stat st;
    if (stat(filepath, &st) != 0) return 404;
    
    *content = readFile(filepath);
    *type = get_content_type(filepath);
    
    return (*content == NULL) ? 500 : 200;
}

int handle_read(connection_t *conn, int epoll_fd) {
    char buffer[4096];
    int bytes;

    while (1) {
        bytes = SSL_read(conn->ssl, buffer, sizeof(buffer) - 1);
        
        if (bytes <= 0) {
            int err = SSL_get_error(conn->ssl, bytes);
            if (err == SSL_ERROR_WANT_READ) return 0;
            close_connection(conn, epoll_fd);
            return -1;
        }

        buffer[bytes] = '\0';
        
        if ((conn->bytes_read + bytes) < sizeof(conn->buffer)) {
            memcpy(conn->buffer + conn->bytes_read, buffer, bytes);
            conn->bytes_read += bytes;
            conn->buffer[conn->bytes_read] = '\0';
        } else {
            close_connection(conn, epoll_fd);
            return -1;
        }
        
        char *current_pos = conn->buffer;
        char *end_of_request;
        
        while ((end_of_request = strstr(current_pos, "\r\n\r\n")) != NULL) {
            char method[16], uri[256], version[16];
            if (sscanf(current_pos, "%15s %255s %15s", method, uri, version) == 3) {
                char* content = NULL;
                const char* type = NULL;
                int status = handle_uri(uri, &content, &type);
                queue_response(conn, status, type, content);
                if (content) free(content);
            }
            current_pos = end_of_request + 4;
        }
        
        int remaining = conn->bytes_read - (current_pos - conn->buffer);
        if (remaining > 0 && current_pos > conn->buffer) {
            memmove(conn->buffer, current_pos, remaining);
            conn->bytes_read = remaining;
        } else if (remaining == 0) {
            conn->bytes_read = 0;
        }
        
        if (conn->response_queue || conn->current_response) {
            struct epoll_event ev;
            ev.events = EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP;
            ev.data.ptr = conn;
            epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev);
        }
    }
}

int handle_write(connection_t *conn, int epoll_fd) {
    while (1) {
        if (!conn->current_response && conn->response_queue) {
            conn->current_response = conn->response_queue;
            conn->response_queue = conn->response_queue->next;
            conn->current_response->next = NULL;
            conn->bytes_written = 0;
        }
        
        if (!conn->current_response) {
            struct epoll_event ev;
            ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
            ev.data.ptr = conn;
            epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev);
            return 0;
        }
        
        int remaining = conn->current_response->len - conn->bytes_written;
        int bytes = SSL_write(conn->ssl, conn->current_response->data + conn->bytes_written, remaining);
        
        if (bytes > 0) {
            conn->bytes_written += bytes;
            if (conn->bytes_written >= conn->current_response->len) {
                free(conn->current_response);
                conn->current_response = NULL;
                conn->bytes_written = 0;
            }
        } else {
            int err = SSL_get_error(conn->ssl, bytes);
            if (err == SSL_ERROR_WANT_WRITE) return 0;
            close_connection(conn, epoll_fd);
            return -1;
        }
    }
}

// --- Main Loop ---

int run_server(SSL_CTX *ctx, int port) {
    int server_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr = { INADDR_ANY } };
    bind(server_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(server_fd, SOMAXCONN);
    
    int epoll_fd = epoll_create1(0);
    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN;
    ev.data.fd = server_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev);
    
    printf("HTTPS server running on port %d\n", port);
    
    while (1) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == server_fd) {
                struct sockaddr_in c_addr;
                socklen_t c_len = sizeof(c_addr);
                int c_fd = accept4(server_fd, (struct sockaddr*)&c_addr, &c_len, SOCK_NONBLOCK);
                if (c_fd < 0) continue;
                
                connection_t *conn = calloc(1, sizeof(connection_t));
                conn->fd = c_fd;
                conn->ssl = SSL_new(ctx);
                SSL_set_fd(conn->ssl, c_fd);
                
                struct epoll_event sev;
                sev.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
                sev.data.ptr = conn;
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, c_fd, &sev);
                handle_ssl_accept(conn, epoll_fd);
            } else {
                connection_t *conn = (connection_t*)events[i].data.ptr;
                int closed = 0;
                
                if (events[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
                    close_connection(conn, epoll_fd);
                    continue;
                }
                
                if (events[i].events & EPOLLIN) {
                    if (!SSL_is_init_finished(conn->ssl)) {
                        if (handle_ssl_accept(conn, epoll_fd) < 0) closed = 1;
                    } else {
                        if (handle_read(conn, epoll_fd) < 0) closed = 1;
                    }
                }
                
                if (!closed && (events[i].events & EPOLLOUT)) {
                    if (!SSL_is_init_finished(conn->ssl)) {
                        if (handle_ssl_accept(conn, epoll_fd) < 0) closed = 1;
                    } else {
                        if (handle_write(conn, epoll_fd) < 0) closed = 1;
                    }
                }
            }
        }
    }
    return 0;
}
