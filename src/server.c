#define _GNU_SOURCE // for accept4 (macro for epoll)

#include "server.h"
#include "parser.h"

#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/ssl.h>
#include <openssl/err.h>


#define MAX_EVENTS 64
#define PORT 8443  // Non-root port, use iptables to forward 443 to 8443

typedef struct {
    SSL *ssl;
    int fd;
    char buffer[8192];
    size_t bytes_read;
    size_t bytes_written;
    int state;  
} connection_t;

int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void close_connection(connection_t *conn, int epoll_fd) {
    if (!conn) return;
    
    if (conn->ssl) {
        SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
    }
    
    if (conn->fd > 0) {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
        close(conn->fd);
    }
    
    free(conn);
}

void handle_ssl_accept(connection_t *conn, int epoll_fd) {
    int ret = SSL_accept(conn->ssl);
    
    if (ret == 1) {
        // SSL handshake complete start reading requests
        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLET;  // Edge-triggered
        ev.data.ptr = conn;
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev);
        return;
    }
    
    int err = SSL_get_error(conn->ssl, ret);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        // Handshake not complete wait for more data
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
        
        // Check if we have complete request (ends with \r\n\r\n)
        if (strstr(conn->buffer, "\r\n\r\n")) {
            // Parse request and prepare response
            char method[16], uri[256], version[16];
            sscanf(conn->buffer, "%s %s %s", method, uri, version);
            
            char *html = readFile("public/index.html");
            char response[8192];
            int len = snprintf(response, sizeof(response),
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: %ld\r\n"
                "Connection: close\r\n"
                "\r\n"
                "%s",
                html ? strlen(html) : 0,
                html ? html : "");
            
            free(html);
            
            // Store response in connection buffer for writing
            memcpy(conn->buffer, response, len);
            conn->bytes_read = len;  // Reuse as write offset
            conn->bytes_written = 0;
            conn->state = 1;  // Writing response
            
            // Switch to write mode
            struct epoll_event ev;
            ev.events = EPOLLOUT | EPOLLET;
            ev.data.ptr = conn;
            epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev);
        }
        
        return;
    }
    
    int err = SSL_get_error(conn->ssl, bytes);
    if (err == SSL_ERROR_WANT_READ) {
        // Need more data stay in EPOLLIN
        return;
    }
    
    if (err == SSL_ERROR_ZERO_RETURN || bytes <= 0) {
        // Connection closed
        close_connection(conn, epoll_fd);
    }
}

void handle_write(connection_t *conn, int epoll_fd) {
    int remaining = conn->bytes_read - conn->bytes_written;
    if (remaining <= 0) {
        // Response fully sent
        conn->state = 2;  // Closing
        close_connection(conn, epoll_fd);
        return;
    }
    
    int bytes = SSL_write(conn->ssl, 
                          conn->buffer + conn->bytes_written, 
                          remaining);
    
    if (bytes > 0) {
        conn->bytes_written += bytes;
        
        if (conn->bytes_written >= conn->bytes_read) {
            // Done writing
            close_connection(conn, epoll_fd);
        }
        return;
    }
    
    int err = SSL_get_error(conn->ssl, bytes);
    if (err == SSL_ERROR_WANT_WRITE) {
        // Write buffer full - wait for EPOLLOUT again
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
