
#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

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
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include <cryptopp/filters.h>
using CryptoPP::ArraySink;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformation;

#include <cryptopp/aes.h>
using CryptoPP::AES;

#include <cryptopp/ccm.h>
using CryptoPP::CBC_Mode;

#include "assert.h"

/* Convert string*/
#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;

#include <cryptopp/secblock.h>
using CryptoPP::SecByteBlock;

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
    wcout << "============ Choose Key ============"
          << "\nInput from screen (16 bytes in hex format)\n";

    encoded = InputFromScreen();
    SecByteBlock key(encoded.size() / 2);
    StringSource(encoded, true, new HexDecoder(new ArraySink(key, key.size())));

    return key;
}
SecByteBlock InputForIV()
{
    string encoded;
    encoded.clear();
    wcout << "============ Choose IV ============"
          << "\nInput from screen (16 bytes in hex format)\n";
    encoded = InputFromScreen();
    SecByteBlock iv(encoded.size() / 2);
    StringSource(encoded, true, new HexDecoder(new ArraySink(iv, iv.size())));
    return iv;
}

void PrintByte(const SecByteBlock &message)
{
    string encoded;
    StringSource(message, message.size(), true, new HexEncoder(new StringSink(encoded)));
    wcout << string_to_wstring(encoded) << endl;
}

int main(int argc, char* argv[])
{
    #ifdef __linux__
    setlocale(LC_ALL, "");
    #elif _WIN32
        _setmode(_fileno(stdin), _O_U16TEXT);
        _setmode(_fileno(stdout), _O_U16TEXT);
    #else
    #endif
	// AutoSeededRandomPool prng;

	// byte key[AES::DEFAULT_KEYLENGTH];
	// prng.GenerateBlock(key, sizeof(key));

	// byte iv[AES::BLOCKSIZE];
	// prng.GenerateBlock(iv, sizeof(iv));

	// string plain = "CBC Mode Test";
    SecByteBlock key;
    SecByteBlock iv;
    try
    {
        do
        {
            key = InputForKey();
        } while (key.size() != AES::DEFAULT_KEYLENGTH);
        wcout << "Key: ";
        PrintByte(key);
        do
        {
            iv = InputForIV();
        } while (iv.size() != AES::BLOCKSIZE);
        wcout << "IV: ";
        PrintByte(iv);
    }
    catch (const CryptoPP::Exception &e)
    {
        wcerr << string_to_wstring(e.what()) << endl;
        exit(1);
    }
	string plain ,cipher, encoded, recovered;

	/*********************************\
	\*********************************/

    plain = InputFromScreen();

	/*********************************\
	\*********************************/

	try
	{
		wcout << "Plaintext: " << string_to_wstring(plain) << endl;

		CBC_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, sizeof(key), iv);
		StringSource s(plain, true, new StreamTransformationFilter(e,new StringSink(cipher)));

#if 0
		StreamTransformationFilter filter(e);
		filter.Put((const byte*)plain.data(), plain.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		cipher.resize(ret);
		filter.Get((byte*)cipher.data(), cipher.size());
#endif
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	// Pretty print
	encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "Ciphertext: " << string_to_wstring(encoded) << endl;

	/*********************************\
	\*********************************/

	try
	{
		CBC_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource

#if 0
		StreamTransformationFilter filter(d);
		filter.Put((const byte*)cipher.data(), cipher.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		recovered.resize(ret);
		filter.Get((byte*)recovered.data(), recovered.size());
#endif

		wcout << "Recovered text: " << string_to_wstring(recovered) << endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	return 0;
}

