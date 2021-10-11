#include <cstdio>
#include <cstring>
#include <cstdlib>

char input[100] = {0};
char enc[100] = "\x86\x8a\x7d\x87\x93\x8b\x4d\x81\x80\x8a\x43\x7f\x86\x4b\x84\x7f\x51\x90\x7f\x62\x2b\x6d\x2c\x91";

void encrypt(unsigned char *dest, char *src){
    int len = strlen(src);
    for(int i = 0;i < len;i ++){
        dest[i] = (src[i] + (32 - i)) ^ i;
    }
}


// flag{s1mpl3_v3x_1r_d3m0}
int main(){
    printf("Please input your flag: ");
    scanf("%s", input);
    if(strlen(input) != 24){
        printf("Wrong length!\n");
        exit(0);
    }
    unsigned char dest[100] = {0};
    encrypt(dest, input);
    if(!memcmp(dest, enc, 24)){
        printf("Congratulations~\n");
    }else{
        printf("Sorry try again.\n");
    }
}
