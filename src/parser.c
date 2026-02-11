#include <stdio.h>
#include <stdlib.h>

char* readFile(char* fileName) {
    FILE* fp = fopen(fileName, "rb"); 
    
    if(fp == NULL) {
        perror("Error: @ Opening File");
        return NULL;
    }
    
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    rewind(fp);
    
    char* buffer = malloc(file_size+1);
    
    size_t bytes_read = fread(buffer, 1, file_size, fp);
    
    buffer[file_size] = '\0';

    fclose(fp);

    return buffer;
}
