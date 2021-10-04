#include <cstdio>

int encrypt(int flag){
    flag += 55;
    flag *= 32;
    flag ^= 2333;
    return flag;
}

int main(){
    int flag = 0;
    scanf("%d", &flag);
    flag = encrypt(flag);
    if(flag == 21309){
        printf("Right!\n");
    }else{
        printf("Wrong!\n");
    }
}