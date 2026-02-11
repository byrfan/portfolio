#ifndef SERVER_H
#define SERVER_H

#include <openssl/ssl.h>

int run_server(SSL_CTX *ctx, int port);

#endif
