#define _GNU_SOURCE // for accept4

#include "parser.h"
#include "http_codes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <time.h>

#define MAX_EVENTS 64
#define BUFFER_SIZE 16384
#define MAX_CONNECTIONS 1000
#define RATE_LIMIT 5
#define RATE_LIMIT_WINDOW 1
#define CONNECTION_TIMEOUT 30

typedef struct response_node {
    char data[8192];
    int len;
    int sent;
    struct response_node *next;
} response_node_t;

typedef struct connection {
    int fd;
    SSL *ssl;
    int state;  // 0=handshake, 1=connected, 2=closing
    char buffer[BUFFER_SIZE];
    int bytes_read;
    int bytes_written;
    response_node_t *response_queue;
    response_node_t *current_response;
    time_t connect_time;
    char client_ip[INET_ADDRSTRLEN];
} connection_t;

typedef struct ip_tracker {
    char ip[INET_ADDRSTRLEN];
    time_t last_connection;
    int connection_count;
    struct ip_tracker *next;
} ip_tracker_t;

// Global variables for tracking
static ip_tracker_t *ip_list = NULL;
static int active_connections = 0;

// --- Helper Functions ---

void free_response_queue(connection_t *conn) {
    if (!conn) return;
    
    // Free queued responses
    response_node_t *current = conn->response_queue;
    while (current) {
        response_node_t *next = current->next;
        free(current);
        current = next;
    }
    
    // Check if current_response is already in queue before freeing
    if (conn->current_response) {
        response_node_t *check = conn->response_queue;
        int already_freed = 0;
        while (check) {
            if (check == conn->current_response) {
                already_freed = 1;
                break;
            }
            check = check->next;
        }
        if (!already_freed) {
            free(conn->current_response);
        }
    }
    
    conn->response_queue = NULL;
    conn->current_response = NULL;
}

void close_connection(connection_t *conn, int epoll_fd) {
    if (!conn) return;
    if (conn->state == 2) return;  // Already closing
    
    conn->state = 2;  // Mark as closing
    active_connections--;
    
    // Remove from epoll first to stop events
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
    
    if (conn->ssl) {
        SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }
    
    if (conn->fd >= 0) {
        close(conn->fd);
        conn->fd = -1;
    }
    
    free_response_queue(conn);
    free(conn);
}

int check_rate_limit(const char *ip) {
    time_t now = time(NULL);
    ip_tracker_t *track = ip_list;
    ip_tracker_t *prev = NULL;
    
    // Clean up old entries (older than 60 seconds)
    ip_tracker_t *curr = ip_list;
    while (curr) {
        ip_tracker_t *next = curr->next;
        if (now - curr->last_connection > 60) {
            if (prev) prev->next = next;
            else ip_list = next;
            free(curr);
        } else {
            prev = curr;
        }
        curr = next;
    }
    
    // Check existing IP
    track = ip_list;
    while (track) {
        if (strcmp(track->ip, ip) == 0) {
            if (now - track->last_connection < RATE_LIMIT_WINDOW) {
                track->connection_count++;
                track->last_connection = now;
                return (track->connection_count > RATE_LIMIT) ? -1 : 0;
            } else {
                track->connection_count = 1;
                track->last_connection = now;
                return 0;
            }
        }
        track = track->next;
    }
    
    // New IP
    track = malloc(sizeof(ip_tracker_t));
    if (!track) return 0;
    
    strcpy(track->ip, ip);
    track->last_connection = now;
    track->connection_count = 1;
    track->next = ip_list;
    ip_list = track;
    
    return 0;
}

void queue_response(connection_t *conn, int status, const char *type, const char *body) {
    if (!conn || conn->state == 2) return;
    
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
    node->next = NULL;
    
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
    if (!conn || !conn->ssl) return -1;
    
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
    if (!conn || !conn->ssl || conn->state == 2) return -1;
    
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
    if (!conn || !conn->ssl || conn->state == 2) return -1;
    
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
                conn->current_response = NULL;  // Critical: set to NULL after free
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
    
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("epoll_create");
        return 1;
    }
    
    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN;
    ev.data.fd = server_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev);
    
    printf("HTTPS server running on port %d\n", port);
    
    while (1) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);  // 1 second timeout
        
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == server_fd) {
                // New connection
                while (1) {
                    struct sockaddr_in c_addr;
                    socklen_t c_len = sizeof(c_addr);
                    int c_fd = accept4(server_fd, (struct sockaddr*)&c_addr, &c_len, SOCK_NONBLOCK);
                    
                    if (c_fd < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        perror("accept");
                        continue;
                    }
                    
                    // Check max connections
                    if (active_connections >= MAX_CONNECTIONS) {
                        printf("Max connections reached, rejecting\n");
                        close(c_fd);
                        continue;
                    }
                    
                    char ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(c_addr.sin_addr), ip, INET_ADDRSTRLEN);
                    
                    // Rate limit check
                    if (check_rate_limit(ip) < 0) {
                        printf("Rate limiting %s (too many connections)\n", ip);
                        close(c_fd);
                        continue;
                    }
                    
                    printf("Connection from: %s\n", ip);
                    
                    connection_t *conn = calloc(1, sizeof(connection_t));
                    if (!conn) {
                        close(c_fd);
                        continue;
                    }
                    
                    conn->fd = c_fd;
                    strcpy(conn->client_ip, ip);
                    conn->connect_time = time(NULL);
                    conn->state = 0;
                    active_connections++;
                    
                    conn->ssl = SSL_new(ctx);
                    if (!conn->ssl) {
                        free(conn);
                        close(c_fd);
                        continue;
                    }
                    
                    SSL_set_fd(conn->ssl, c_fd);
                    
                    struct epoll_event sev;
                    sev.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
                    sev.data.ptr = conn;
                    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, c_fd, &sev);
                    
                    handle_ssl_accept(conn, epoll_fd);
                }
            } else {
                connection_t *conn = (connection_t*)events[i].data.ptr;
                
                if (!conn) {
                    printf("WARNING: NULL connection in event loop\n");
                    continue;
                }
                
                // Check connection timeout
                if (time(NULL) - conn->connect_time > CONNECTION_TIMEOUT) {
                    printf("Connection timeout for %s\n", conn->client_ip);
                    close_connection(conn, epoll_fd);
                    continue;
                }
                
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
    
    close(epoll_fd);
    close(server_fd);
    return 0;
}
