#include "ssl.h"
#include "server.h"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    // Initialize SSL
    init_ssl();
    
    // Create SSL context
    SSL_CTX *ctx = create_context();
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL context\n");
        return EXIT_FAILURE;
    }
    
    // Load certificates
    config_context(ctx, "cert.pem", "key.pem");
    
    printf("Starting HTTPS server on port 8443...\n");
    printf("Make sure to run: sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8443\n");
    
    // Run server (never returns)
    int result = run_server(ctx, 8443);
    
    // Cleanup (only reached on error)
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return result;
}
