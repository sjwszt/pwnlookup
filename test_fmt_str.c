#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char buffer[100];
    
    printf("Enter some text: ");
    fgets(buffer, sizeof(buffer), stdin);
    
    // Remove newline character
    buffer[strcspn(buffer, "\n")] = '\0';
    
    // Format string vulnerability
    printf(buffer);
    
    return 0;
} 