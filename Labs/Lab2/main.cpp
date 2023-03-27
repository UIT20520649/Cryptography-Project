#include "AES_Program.cpp"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/files.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include <iostream>
using std::cerr;
using std::endl;
using std::wcin;
using std::wcout;


#include <assert.h>

/* Set _setmode()*/
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif
/* Convert string*/
#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;



int main(){
    
}
