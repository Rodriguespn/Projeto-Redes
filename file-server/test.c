#include <string.h>
#include <stdio.h>

int main()
{
    char var[50];
    bzero(var, 50);
    strcpy(var, "ERR");
    strcat(var, "\n");
    fprintf(stdout, "%s", var);
    return 0;
}