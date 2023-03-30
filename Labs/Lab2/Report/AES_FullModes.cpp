// g++ -g2 -O3 -DNDEBUG AES_FullModes.cpp -o AES_FullModes -D_WIN32_WINNT=0x0501 -pthread -lcryptopp -Wall

// ============================     LIBRARY    ====================================//
#include <iostream>
using std::cerr;
using std::endl;
using std::wcerr;
using std::wcin;
using std::wcout;

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;
#include "AES_MODES.cpp"

#include "cryptopp/files.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include <iostream>
using std::cerr;
using std::endl;
using std::wcin;
using std::wcout;
using std::cout;

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
// ============================     FUNCTION    ====================================//

/* convert string to wstring */
wstring string_to_wstring(const std::string &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}

/* convert wstring to string */
string wstring_to_string(const std::wstring &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}

void PrintByte(const SecByteBlock &message)
{
    string encoded;
    StringSource(message, message.size(), true, new HexEncoder(new StringSink(encoded)));
    wcout << string_to_wstring(encoded) << endl;
}
string ToHex(const string &text)
{
    string encoded;
    encoded.clear();
    StringSource(text, true, new HexEncoder(new StringSink(encoded))); // HexEncoder
    return encoded;
}

void Encrypt_Process(AESProgram &prog, MODE CipherMode, string plain, string &_cipher, SecByteBlock _key, SecByteBlock _iv)
{
    SecByteBlock key;
    SecByteBlock iv(AES::BLOCKSIZE);
    string cipher, encoded;
    wcout << string_to_wstring(plain) << endl;
    key = _key;
    if (CipherMode != MODE::ECB)
        iv = _iv;
    cipher = prog.Encryption(plain, CipherMode, key, iv);
    encoded = ToHex(cipher);
    _cipher = ToHex(cipher);
    wcout << "Ciphertext: " << string_to_wstring(encoded) << endl;
}
void Decrypt_Process(AESProgram &prog, MODE CipherMode, string _cipher, SecByteBlock _key, SecByteBlock _iv)
{
    SecByteBlock key;
    SecByteBlock iv(AES::BLOCKSIZE);
    string plain, encoded,cipher;
    encoded = _cipher;
    StringSource(encoded, true, new HexDecoder(new StringSink(cipher)));
    wcout << string_to_wstring(plain) << endl;
    key = _key;
    if (CipherMode != MODE::ECB)
        iv = _iv;
    plain = prog.Decryption(cipher, CipherMode, key, iv);
    if(CipherMode == MODE::XTS){
        cout << "Recover text: " << plain << endl;
        return;
    }
    wcout << "Recover text: " << string_to_wstring(plain) << endl;
}


// ============================     MAIN PROGRAM    ====================================//

int main(){
    setlocale(LC_ALL, "");

    AESProgram prog;
    MODE AES_Mode;

    // Random Key and IV
    AutoSeededRandomPool prng;
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key,key.size());
    SecByteBlock iv(AES::BLOCKSIZE);
    prng.GenerateBlock(iv,iv.size());
    wcout << "KEY : ";
    PrintByte(key);
    wcout << "IV : ";
    PrintByte(iv);

    // ================================== CBC MODE =====================================// 
    wcout << "============================ CBC MODE ============================\n";
    string plaintext = "CBC Mode Test";
    string cipher, recovered, encoded;
    wcout << "Plaintext : " << string_to_wstring(plaintext) << endl;
    AES_Mode = MODE::CBC;
    // Encryption
    Encrypt_Process(prog,AES_Mode,plaintext,cipher,key,iv);
    // Decryption
    Decrypt_Process(prog,AES_Mode,cipher,key,iv);
    wcout << "=================================================================\n\n";

    
    // ================================== ECB MODE =====================================// 
    wcout << "============================ ECB MODE ============================\n";
    plaintext = "ECB Mode Test";
    wcout << "Plaintext : " << string_to_wstring(plaintext) << endl;
    AES_Mode = MODE::ECB;
    // Encryption
    Encrypt_Process(prog,AES_Mode,plaintext,cipher,key,iv);
    // Decryption
    Decrypt_Process(prog,AES_Mode,cipher,key,iv);
    wcout << "=================================================================\n\n";


    // ================================== OFB MODE =====================================// 
    wcout << "============================ OFB MODE ============================\n";
    plaintext = "OFB Mode Test";
    wcout << "Plaintext : " << string_to_wstring(plaintext) << endl;
    AES_Mode = MODE::OFB;
    // Encryption
    Encrypt_Process(prog,AES_Mode,plaintext,cipher,key,iv);
    // Decryption
    Decrypt_Process(prog,AES_Mode,cipher,key,iv);
    wcout << "=================================================================\n\n";

    // ================================== CFB MODE =====================================// 
    wcout << "============================ CFB MODE ============================\n";
    plaintext = "CFB Mode Test";
    wcout << "Plaintext : " << string_to_wstring(plaintext) << endl;
    AES_Mode = MODE::CFB;
    // Encryption
    Encrypt_Process(prog,AES_Mode,plaintext,cipher,key,iv);
    // Decryption
    Decrypt_Process(prog,AES_Mode,cipher,key,iv);
    wcout << "=================================================================\n\n";

    // ================================== CTR MODE =====================================// 
    wcout << "============================ CTR MODE ============================\n";
    plaintext = "CTR Mode Test";
    wcout << "Plaintext : " << string_to_wstring(plaintext) << endl;
    AES_Mode = MODE::CTR;
    // Encryption
    Encrypt_Process(prog,AES_Mode,plaintext,cipher,key,iv);
    // Decryption
    Decrypt_Process(prog,AES_Mode,cipher,key,iv);
    wcout << "=================================================================\n\n";

    // ================================== XTS MODE =====================================// 
    wcout << "============================ XTS MODE ============================\n";
    SecByteBlock xts_key(32);
    prng.GenerateBlock(xts_key,xts_key.size());
    plaintext = "XTS Mode Test";
    wcout << "Plaintext : " << string_to_wstring(plaintext) << endl;
    AES_Mode = MODE::CTR;
    // Encryption
    Encrypt_Process(prog,AES_Mode,plaintext,cipher,xts_key,iv);
    // Decryption
    Decrypt_Process(prog,AES_Mode,cipher,xts_key,iv);
    wcout << "=================================================================\n\n";

    // ================================== CCM MODE =====================================// 
    wcout << "============================ CCM MODE ============================\n";
    plaintext = "CCM Mode Test";
    wcout << "Plaintext : " << string_to_wstring(plaintext) << endl;
    AES_Mode = MODE::CTR;
    // Encryption
    Encrypt_Process(prog,AES_Mode,plaintext,cipher,key,iv);
    // Decryption
    Decrypt_Process(prog,AES_Mode,cipher,key,iv);
    wcout << "=================================================================\n\n";

    // ================================== GCM MODE =====================================// 
    wcout << "============================ GCM MODE ============================\n";
    plaintext = "GCM Mode Test";
    wcout << "Plaintext : " << string_to_wstring(plaintext) << endl;
    AES_Mode = MODE::GCM;
    // Encryption
    Encrypt_Process(prog,AES_Mode,plaintext,cipher,key,iv);
    // Decryption
    Decrypt_Process(prog,AES_Mode,cipher,key,iv);
    wcout << "=================================================================\n\n";
}
