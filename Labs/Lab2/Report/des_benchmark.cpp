
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
using CryptoPP::StreamTransformation;

#include <cryptopp/des.h>
using CryptoPP::DES;

#include <cryptopp/modes.h>
using CryptoPP::CBC_Mode;

#include <cryptopp/secblock.h>
using CryptoPP::byte;
using CryptoPP::SecByteBlock;
using CryptoPP::RoundUpToMultipleOf;
using CryptoPP::AlignedSecByteBlock;
#include <cryptopp/cryptlib.h>
#include "cryptopp/files.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include <cryptopp/misc.h>
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

#include <chrono>

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

#include <iomanip>
#include <fstream>
#include "cryptopp/hrtimer.h"
using CryptoPP::ThreadUserTimer;



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


string InputFromFile(wstring wfilename)
{
    wcin.ignore();
    string plain, filename;
    filename = wstring_to_string(wfilename);
    FileSource file(filename.data(), true, new StringSink(plain));
    return plain;
}

string ToHex(const string &sour)
{
    string dest;
    StringSource(sour, true, new HexEncoder(new StringSink(dest))); // HexEncoder
    return dest;
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
	AutoSeededRandomPool prng;

    SecByteBlock key(DES::DEFAULT_KEYLENGTH);
	prng.GenerateBlock(key, key.size());

	SecByteBlock iv(DES::BLOCKSIZE);
	prng.GenerateBlock(iv, iv.size());
    
    string plaintext,cipher,encoded, recovered;
    plaintext = "DES CBC Mode";
    // plaintext = InputFromFile(L"UTF16 Input.txt");
    // plaintext = InputFromFile(L"Small Input.txt");
    // plaintext = InputFromFile(L"Large Input.txt");

    // encoded.clear();
	// StringSource(key, key.size(), true,new HexEncoder(new StringSink(encoded))); 

    // wcout << "Key : " << string_to_wstring(encoded) << endl;

    // encoded.clear();
	// StringSource(iv, iv.size(), true,new HexEncoder(new StringSink(encoded)));
    // wcout << "IV : " << string_to_wstring(encoded) << endl;
// =======================================================================//
// Encryption && Decryption
// =======================================================================//

    CBC_Mode<DES>::Encryption e;
    e.SetKeyWithIV(key, key.size(), key);
    StringSource(plaintext,true,new StreamTransformationFilter(e,new StringSink(cipher)));

    encoded.clear();
    StringSource(cipher,true,new HexEncoder(new StringSink(encoded)));
    // wcout << "Ciphertext : " << string_to_wstring(encoded) << endl;

    CBC_Mode<DES>::Decryption d;
    d.SetKeyWithIV(key, key.size(), key);
    StringSource(cipher,true,new StreamTransformationFilter(d,new StringSink(recovered)));
    // wcout << "Recovered : " << string_to_wstring(recovered) << endl;

// =======================================================================//
// Benchmark
// =======================================================================//

    const int BUF_SIZE = RoundUpToMultipleOf(2048U,dynamic_cast<StreamTransformation&>(d).OptimalBlockSize());
    const double runTimeInSeconds = 3.0;
    AlignedSecByteBlock buf(BUF_SIZE);
    prng.GenerateBlock(buf, buf.size());

    double elapsedTimeInSeconds;
    unsigned long i=0, blocks=1;

    ThreadUserTimer timer;
    timer.StartTimer();

    do
    {
        blocks *= 2;
        for (; i<blocks; i++)
            // e.ProcessString(buf, BUF_SIZE);
            d.ProcessString(buf, BUF_SIZE);
        elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
    }
    while (elapsedTimeInSeconds < runTimeInSeconds);
    const double cpuFreq = 3.3 * 1000 * 1000 * 1000;
    const double bytes = static_cast<double>(BUF_SIZE) * blocks;
    const double ghz = cpuFreq / 1000 / 1000 / 1000;
    const double mbs = bytes / elapsedTimeInSeconds / 1024 / 1024;
    const double cpb = elapsedTimeInSeconds * cpuFreq / bytes;
    // wcout << string_to_wstring(e.AlgorithmName()) << " Encryption Benchmark" << endl;
    wcout << string_to_wstring(d.AlgorithmName()) << " Decryption Benchmark" << endl;
    wcout << "  " << ghz << " GHz cpu frequency"  << std::endl;
    wcout << "  " << cpb << " cycles per byte (cpb)" << std::endl;
    wcout << "  " << mbs << " MiB per second (MiB)" << std::endl;


    pause();
    return 0;
}