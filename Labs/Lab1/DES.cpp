
#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cerr;
using std::endl;
using std::wcerr;
using std::wcin;
using std::wcout;

#include <string>
using std::string;
using std::wstring;

#include <cstdlib>
using std::exit;

#include <cryptopp/cryptlib.h>
using CryptoPP::Exception;

#include <cryptopp/hex.h>
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include <cryptopp/filters.h>
using CryptoPP::ArraySink;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include <cryptopp/des.h>
using CryptoPP::DES;

#include <cryptopp/modes.h>
using CryptoPP::CBC_Mode;

#include <cryptopp/secblock.h>
using CryptoPP::byte;
using CryptoPP::SecByteBlock;

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

void pause()
{
#ifdef __linux__
    wcout << "Press any key to resume ...";
    wcin.get();
    wcout << endl;
#elif _WIN32
    system("pause");
#else
#endif
}

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
// Only hex format
void PrintByte(const SecByteBlock &message)
{
    string encoded;
    StringSource(message, message.size(), true, new HexEncoder(new StringSink(encoded)));
    wcout << string_to_wstring(encoded) << endl;
}
void PrintByte(const string &message)
{
    try
    {
        wcout << string_to_wstring(message) << endl;
    }
    catch (const std::range_error &e)
    {
        string encoded;
        StringSource(message, true, new HexEncoder(new StringSink(encoded)));
        wcout << string_to_wstring(encoded) << endl;
    }
}
string Encryption_CBC(const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
{
    CBC_Mode<DES>::Encryption CBC_ENC;
    string cipher;
    cipher.clear();
    try
    {
        CBC_ENC.SetKeyWithIV(key, key.size(), iv);
        StringSource(plain, true, 
			new StreamTransformationFilter(CBC_ENC,
				new StringSink(cipher)
			) // StreamTransformationFilter      
		); 
    }
    catch (const CryptoPP::Exception &e)
    {
        wcerr << string_to_wstring(e.what()) << endl;
        exit(1);
    }
    return cipher;
}
string Decryption_CBC(const string &ciphertext, const SecByteBlock &key, const SecByteBlock &iv)
{
    CBC_Mode<DES>::Decryption CBC_DEC;
    string recovered;
    recovered.clear();
    try
    {
        CBC_DEC.SetKeyWithIV(key, key.size(), iv);
        StringSource s(ciphertext, true, 
			new StreamTransformationFilter(CBC_DEC,
				new StringSink(recovered)
			) // StreamTransformationFilter
		);
    }
    catch (const CryptoPP::Exception &e)
    {
        wcerr << string_to_wstring(e.what()) << endl;
        exit(1);
    }
    return recovered;
}
string InputFromScreen()
{
    wstring wplain;
    wcout << "Input text: ";
    getline(wcin, wplain);
    wcin.ignore(10, L'\n');
    if (wplain == L"" || wplain == L"\n" || wplain == L"\r\n")
    {
        wcerr << L"Sussy text!" << endl;
        exit(1);
    }
    return wstring_to_string(wplain);
}
SecByteBlock InputForKey()
{
    string encoded;
    encoded.clear();
    wcout << "********* Choose Key ***********"
          << "\nInput from screen (8 bytes in hex format)\n";

    encoded = InputFromScreen();
    SecByteBlock key(encoded.size() / 2);
    StringSource(encoded, true, new HexDecoder(new ArraySink(key, key.size())));

    return key;
}
SecByteBlock InputForIV()
{
    string encoded;
    encoded.clear();
    wcout << "********* Choose IV ***********"
          << "\nInput from screen (8 bytes in hex format)\n";
    encoded = InputFromScreen();
    SecByteBlock iv(encoded.size() / 2);
    StringSource(encoded, true, new HexDecoder(new ArraySink(iv, iv.size())));
    return iv;
}

int main(int argc, char *argv[])
{
#ifdef __linux__
    setlocale(LC_ALL, "");
#elif _WIN32
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
#else
#endif
    SecByteBlock key;
    SecByteBlock iv;
    try
    {
        do
        {
            key = InputForKey();
        } while (key.size() != DES::KEYLENGTH);
        wcout << "Key: ";
        PrintByte(key);
        do
        {
            iv = InputForIV();
        } while (iv.size() != DES::BLOCKSIZE);
        wcout << "IV: ";
        PrintByte(iv);
    }
    catch (const CryptoPP::Exception &e)
    {
        wcerr << string_to_wstring(e.what()) << endl;
        exit(1);
    }
    string input, output, encoded, choice;
    for (;;)
    {
        output.clear();
        input.clear();
        encoded.clear();
        wcout<< "\n*********************"
             << "\n1. Encrypting Data (Encrypt, Enc, E, e)"
             << "\n2. Decrypting Data (Decrypt, Dec, D, d)";
        wcout << "\nYour choice: ";
        choice = InputFromScreen();

        if (choice == "Encrypt" || choice == "Enc" || choice == "E" || choice == "e")
        {
            wcout << "*************************************"
                  << "\n\tInput your plaintext(in raw string)\n";
            input = InputFromScreen();
            output = Encryption_CBC(input, key, iv);
            wcout << "Cipher text: ";
            PrintByte(output);
        }
        else if (choice == "Decrypt" || choice == "Dec" || choice == "D" || choice == "d")
        {
            wcout << "*************************************"
                  << "\n\tInput your ciphertext(in hex format)\n";
            encoded = InputFromScreen();
            StringSource(encoded, true, new HexDecoder(new StringSink(input)));
            output = Decryption_CBC(input, key, iv);
            wcout << "Recovered text: ";
            PrintByte(output);
        }
        else
        {
            wcout << "\nUnrecognized choice!\n";
            continue;
        }
        break;
    }
    /*********************************\
    \*********************************/
    pause();
    return 0;
}
