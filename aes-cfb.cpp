#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/modes.h"
using CryptoPP::CFB_Mode;

#include "functions.h"

string CFBMode_Encrypt(string text, byte key[], int keySize, byte iv[]) {
    string cipher = "";
    //Encryption
    try
    {
        CFB_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, keySize, iv);
        StringSource(text, true, new StreamTransformationFilter(e, new StringSink(cipher))); // StringSource
    }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    return cipher;
}
string CFBMode_Decrypt(string cipher, byte key[], int keySize, byte iv[]) {
    string recovered = "";
    //Decryption
    try
    {
        CFB_Mode< AES >::Decryption d;
        d.SetKeyWithIV(key, keySize, iv);
        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(cipher, true, new StreamTransformationFilter(d,new StringSink(recovered))); // StringSource
    }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    return recovered;
}


int main(int argc, char* argv[])
{

    //Define the key and iv
    byte key[AES::DEFAULT_KEYLENGTH] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef, 0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x01};
    byte iv[AES::BLOCKSIZE] = {0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef, 0x34,0x56,0x78,0x90,0xab,0xcd,0xef,0x12};

	string plain = "The quick brown fox jumped over the lazy dog’s back";

    string sha1_digest_result, cipher, encoded, recovered;

    //Print Data
    cout << "Key: " << PrettyPrint(key, AES::DEFAULT_KEYLENGTH) << endl;
    cout << "iv: " << PrettyPrint(iv, AES::BLOCKSIZE) << endl;
    cout << "Plain text: " << plain << endl;
    
    //SHA-1 - Plain
    cout << "SHA-1 Plain: " << sha1_digest(plain) << endl;
    
    //MD5 - Plain
    cout << "MD5 Plain: " << md5(plain) << endl;
    
    //HMAC - Plain
    cout << "HMAC Plain: " << HMAC_SHA_1(plain, key, sizeof(key)) << endl;
    
    //Encrypt
    cipher = CFBMode_Encrypt(plain, key, sizeof(key), iv);
    cout << "Cipher Text: " << PrettyPrint(cipher) << endl;
    
    //Decrypt
    recovered = CFBMode_Decrypt(cipher, key, sizeof(key), iv);
    cout << "Recovered text: " << recovered << endl;

    //SHA-1 Recovered
    cout << "SHA-1 Recovered: " << sha1_digest(recovered) << endl;
    
    //MD5 - Recovered
    cout << "MD5 Recovered: " << md5(recovered) << endl;
    
    //HMAC - Recovered
    cout << "HMAC Recovered: " << HMAC_SHA_1(recovered, key, sizeof(key)) << endl;
    
	return 0;
}

