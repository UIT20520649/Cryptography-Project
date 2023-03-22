#include <iostream>
#include <unistd.h>
using namespace std;

int main(){
    for(int i = 0 ; i < 3 ; i++){
        fork();
        cout << "hello\n";
    }
    return 0;
}