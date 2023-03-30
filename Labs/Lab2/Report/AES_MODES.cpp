

#ifndef _AES_FULLMODE_CPP
#define _AES_FULLMODE_CPP

#include "cryptopp/osrng.h"
using CryptoPP::byte;
using CryptoPP::SecByteBlock;
#include <iostream>
using std::cerr;
using std::endl;

#include <string>
using std::string;
using std::wstring;

#include <cstdlib>
using std::exit;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "cryptopp/filters.h"
using CryptoPP::ArraySink;
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::Redirector; 
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/ccm.h"
using CryptoPP::CBC_Mode;
using CryptoPP::CCM;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;
#include <cryptopp/xts.h>
using CryptoPP::XTS;
#include <cryptopp/gcm.h>
using CryptoPP::GCM;



// ============================     AES CLASSES    ====================================//

enum class MODE
{
    ECB,
    CBC,
    OFB,
    CFB,
    CTR,
    XTS,
    CCM,
    GCM
};
class AESProgram
{
    ECB_Mode<AES>::Encryption ECB_ENC;
    ECB_Mode<AES>::Decryption ECB_DEC;
    /*********************************/
    CBC_Mode<AES>::Encryption CBC_ENC;
    CBC_Mode<AES>::Decryption CBC_DEC;
    /*********************************/
    OFB_Mode<AES>::Encryption OFB_ENC;
    OFB_Mode<AES>::Decryption OFB_DEC;
    /*********************************/
    CFB_Mode<AES>::Encryption CFB_ENC;
    CFB_Mode<AES>::Encryption CFB_DEC;
    /*********************************/
    CTR_Mode<AES>::Encryption CTR_ENC;
    CTR_Mode<AES>::Encryption CTR_DEC;
    /*********************************/
    XTS<AES>::Encryption XTS_ENC;
    XTS<AES>::Encryption XTS_DEC;
    /*********************************/
    CCM<AES, 16>::Encryption CCM_ENC;
    CCM<AES, 16>::Encryption CCM_DEC;
    /*********************************/
    GCM<AES>::Encryption GCM_ENC;
    GCM<AES>::Decryption GCM_DEC;
public:
    /*********************************\
    \*********************************/
    void Encryption_ECB(string &cipher, const string &plain, const SecByteBlock &key)
    {
        ECB_ENC.SetKey(key, key.size());
        StringSource ss(plain, true, new StreamTransformationFilter(ECB_ENC, new StringSink(cipher)));
    }
    void Decryption_ECB(string &cipher, const string &plain, const SecByteBlock &key)
    {
        ECB_DEC.SetKey(key, key.size());
        StringSource ss(plain, true, new StreamTransformationFilter(ECB_DEC, new StringSink(cipher)));
    }
    /*********************************\
    \*********************************/
    void Encryption_CBC(string &cipher, const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
    {
        CBC_ENC.SetKeyWithIV(key, key.size(), iv);
        StringSource ss(plain, true, new StreamTransformationFilter(CBC_ENC, new StringSink(cipher)));
    }
    void Decryption_CBC(string &cipher, const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
    {
        CBC_DEC.SetKeyWithIV(key, key.size(), iv);
        StringSource ss(plain, true, new StreamTransformationFilter(CBC_DEC, new StringSink(cipher)));
    }
    /*********************************\
    \*********************************/
    void Encryption_OFB(string &cipher, const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
    {
        OFB_ENC.SetKeyWithIV(key, key.size(), iv);
        StringSource ss(plain, true, new StreamTransformationFilter(OFB_ENC, new StringSink(cipher)));
    }
    void Decryption_OFB(string &cipher, const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
    {
        OFB_DEC.SetKeyWithIV(key, key.size(), iv);
        StringSource ss(plain, true, new StreamTransformationFilter(OFB_DEC, new StringSink(cipher)));
    }
    /*********************************\
    \*********************************/
    void Encryption_CFB(string &cipher, const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
    {
        CFB_ENC.SetKeyWithIV(key, key.size(), iv);
        StringSource ss(plain, true, new StreamTransformationFilter(CFB_ENC, new StringSink(cipher)));
    }
    void Decryption_CFB(string &cipher, const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
    {
        CFB_DEC.SetKeyWithIV(key, key.size(), iv);
        StringSource ss(plain, true, new StreamTransformationFilter(CFB_DEC, new StringSink(cipher)));
    }
    /*********************************\
    \*********************************/
    void Encryption_CTR(string &cipher, const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
    {
        CTR_ENC.SetKeyWithIV(key, key.size(), iv);
        StringSource ss(plain, true, new StreamTransformationFilter(CTR_ENC, new StringSink(cipher)));
    }
    void Decryption_CTR(string &cipher, const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
    {
        CTR_DEC.SetKeyWithIV(key, key.size(), iv);
        StringSource ss(plain, true, new StreamTransformationFilter(CTR_DEC, new StringSink(cipher)));
    }
    /*********************************\
    \*********************************/
    void Encryption_XTS(string &cipher, const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
    {
        XTS_ENC.SetKeyWithIV(key, key.size(), iv);
        StringSource ss(plain, true, new StreamTransformationFilter(XTS_ENC, new StringSink(cipher), StreamTransformationFilter::NO_PADDING));
    }
    void Decryption_XTS(string &cipher, const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
    {
        XTS_DEC.SetKeyWithIV(key, key.size(), iv);
        StringSource ss(plain, true, new StreamTransformationFilter(XTS_DEC, new StringSink(cipher), StreamTransformationFilter::NO_PADDING));
    }
    /*********************************\
    \*********************************/
    void Encryption_CCM(string &cipher, const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
    {
        CCM_ENC.SetKeyWithIV(key, key.size(), iv);
        CCM_ENC.SpecifyDataLengths(0, plain.length(), 0);
        StringSource ss(plain, true, new AuthenticatedEncryptionFilter(CCM_ENC, new StringSink(cipher)));
    }
    void Decryption_CCM(string &cipher, const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
    {
        CCM_DEC.SetKeyWithIV(key, key.size(), iv);
        CCM_ENC.SpecifyDataLengths(0, plain.length() - 16, 0);
        StringSource ss(plain, true, new AuthenticatedDecryptionFilter(CCM_DEC, new StringSink(cipher)));
    }
    /*********************************\
    \*********************************/
    void Encryption_GCM(string &cipher, const string &plain, const SecByteBlock &key, const SecByteBlock &iv){
        GCM_ENC.SetKeyWithIV(key,key.size(),iv);
        const int TAG_SIZE = 12;
        GCM_ENC.SpecifyDataLengths(0,plain.length(),0);
        StringSource ss( plain, true,new AuthenticatedEncryptionFilter( GCM_ENC,new StringSink(cipher), false, TAG_SIZE)); 
    }
    void Decryption_GCM(string &cipher, const string &plain, const SecByteBlock &key, const SecByteBlock &iv){
        GCM_DEC.SetKeyWithIV(key,key.size(),iv);
        const int TAG_SIZE = 12;
        AuthenticatedDecryptionFilter df( GCM_DEC,new StringSink(cipher), TAG_SIZE); 
        StringSource ss(plain, true,new Redirector(df)); 
    }

    /*********************************\
    \*********************************/
    string ToHex(const string &text)
    {
        string encoded;
        encoded.clear();
        StringSource(text, true, new HexEncoder(new StringSink(encoded))); // HexEncoder
        return encoded;
    }
    string Encryption(const string &plain, MODE CipherMode, const SecByteBlock &key, const SecByteBlock &iv)
    {
        string cipher;
        try
        {
            switch (CipherMode)
            {
            case MODE::ECB:
                Encryption_ECB(cipher, plain, key);
                break;
            case MODE::CBC:
                Encryption_CBC(cipher, plain, key, iv);
                break;
            case MODE::OFB:
                Encryption_OFB(cipher, plain, key, iv);
                break;
            case MODE::CFB:
                Encryption_CFB(cipher, plain, key, iv);
                break;
            case MODE::CTR:
                Encryption_CTR(cipher, plain, key, iv);
                break;
            case MODE::XTS:
                Encryption_XTS(cipher, plain, key, iv);
                break;
            case MODE::CCM:
                Encryption_CCM(cipher, plain, key, iv);
                break;
            case MODE::GCM:
                Encryption_GCM(cipher, plain, key, iv);
                break;
            default:
                cerr << "Not recognizing this mode!" << endl;
                exit(1); // StringSource
            }
        }
        catch (const CryptoPP::Exception &e)
        {
            cerr << e.what() << endl;
            exit(1);
        }
        return cipher;
    }
    string Decryption(const string &cipher, MODE CipherMode, const SecByteBlock &key, const SecByteBlock &iv)
    {
        string recovered;
        try
        {
            switch (CipherMode)
            {
            case MODE::ECB:
                Decryption_ECB(recovered, cipher, key);
                break;
            case MODE::CBC:
                Decryption_CBC(recovered, cipher, key, iv);
                break;
            case MODE::OFB:
                Decryption_OFB(recovered, cipher, key, iv);
                break;
            case MODE::CFB:
                Decryption_CFB(recovered, cipher, key, iv);
                break;
            case MODE::CTR:
                Decryption_CTR(recovered, cipher, key, iv);
                break;
            case MODE::XTS:
                Decryption_XTS(recovered, cipher, key, iv);
                break;
            case MODE::CCM:
                Decryption_CCM(recovered, cipher, key, iv);
                break;
            case MODE::GCM:
                Decryption_GCM(recovered, cipher, key, iv);
            default:
                cerr << "Not recognizing this mode!" << endl;
                exit(1); // StringSource
            }
        }
        catch (const CryptoPP::Exception &e)
        {
            cerr << e.what() << endl;
            exit(1);
        }
        return recovered;
    }
};

#endif
