#include "ssl.h"
#include "server.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <execinfo.h>
#include <unistd.h>

void crash_handler(int sig) {
    void *array[20];
    size_t size;
    
    fprintf(stderr, "\n=== CRASH DETECTED (signal %d) ===\n", sig);
    
    // Get backtrace addresses
    size = backtrace(array, 20);
    
    // Print backtrace
    fprintf(stderr, "Backtrace:\n");
    backtrace_symbols_fd(array, size, STDERR_FILENO);
    
    exit(1);
}

int main(void) {
    signal(SIGSEGV, crash_handler);  // Segmentation fault
    signal(SIGABRT, crash_handler);  // Abort
    signal(SIGFPE, crash_handler);   // Floating point exception
    signal(SIGILL, crash_handler);   // Illegal instruction
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
    
    // Run server (never returns)
    int result = run_server(ctx, 8443);
    
    // Cleanup (only reached on error)
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return result;
}
