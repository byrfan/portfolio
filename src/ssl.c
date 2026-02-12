#include "ssl.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <stdio.h>
#include <stdlib.h>

void init_ssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();  
}

SSL_CTX *create_context() {
    const SSL_METHOD *method = TLS_server_method(); 
    SSL_CTX *ctx = SSL_CTX_new(method);
    
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    // Security options
    SSL_CTX_set_options(ctx, 
        SSL_OP_NO_SSLv2 | 
        SSL_OP_NO_SSLv3 | 
        SSL_OP_NO_TLSv1 | 
        SSL_OP_NO_TLSv1_1 |
        SSL_OP_CIPHER_SERVER_PREFERENCE |
        SSL_OP_SINGLE_DH_USE
    );
    
    SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!eNULL:!LOW:!MD5:!EXP:!RC4");
    
    return ctx;
}

void config_context(SSL_CTX *ctx, const char *cert_path, const char *key_path) {
    // Load certificate
    if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    // Load private key
    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    // Verify key matches cert
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match certificate\n");
        exit(EXIT_FAILURE);
    }
    
    printf("SSL context configured with %s and %s\n", cert_path, key_path);
}
