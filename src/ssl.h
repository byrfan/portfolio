#ifndef PORTFOLIO_SSL
#define PORTFOLIO_SSL
#include <stdio.h>
#include "openssl/ssl.h"
void init_ssl(); 
SSL_CTX *create_context(); 
void config_context(SSL_CTX *ctx, const char *cert_path, const char *key_path);
#endif // PORTFOLIO_SSL
