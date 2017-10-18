#include "cryptopp/des.h"
using CryptoPP::DES_EDE3;

#include "cryptopp/modes.h"
using CryptoPP::ECB_Mode;

#include "functions.h"


string ECBMode_Encrypt(string text, byte key[], int keySize) {
    string cipher = "";
    //Encryption
    try
    {
        ECB_Mode<DES_EDE3>::Encryption e;
        e.SetKey(key, keySize);
        // The StreamTransformationFilter adds padding
        //  as required. ECB and CBC Mode must be padded
        //  to the block size of the cipher.
        StringSource(text, true, new StreamTransformationFilter(e, new StringSink(cipher))); // StringSource
    }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    return cipher;
}
string ECBMode_Decrypt(string cipher, byte key[], int keySize) {
    string recovered = "";
    //Decryption
    try
    {
        ECB_Mode< DES_EDE3 >::Decryption d;
        d.SetKey(key, keySize);
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
    byte key[DES_EDE3::DEFAULT_KEYLENGTH] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x01,0x45,0x67,0x89,0xab,0xcd,0xef,0x01,0x23};

	string plain = "The quick brown fox jumped over the lazy dog’s back";
	string sha1_digest_result, cipher, encoded, recovered;

    //Print Data
    cout << "Key: " << PrettyPrint(key, DES_EDE3::DEFAULT_KEYLENGTH) << endl;
    cout << "Plain text: " << plain << endl;
    
    //SHA-1 - Plain
    cout << "SHA-1 Plain: " << sha1_digest(plain) << endl;
    
    //MD5 - Plain
    cout << "MD5 Plain: " << md5(plain) << endl;
    
    //HMAC - Plain
    cout << "HMAC Plain: " << HMAC_SHA_1(plain, key, sizeof(key)) << endl;
    
    //Encrypt
    cipher = ECBMode_Encrypt(plain, key, sizeof(key));
    cout << "Cipher Text: " << PrettyPrint(cipher) << endl;
    
    //Decrypt
    recovered = ECBMode_Decrypt(cipher, key, sizeof(key));
    cout << "Recovered text: " << recovered << endl;

    //SHA-1 Recovered
    cout << "SHA-1 Recovered: " << sha1_digest(recovered) << endl;
    
    //MD5 - Recovered
    cout << "MD5 Recovered: " << md5(recovered) << endl;
    
    //HMAC - Recovered
    cout << "HMAC Recovered: " << HMAC_SHA_1(recovered, key, sizeof(key)) << endl;
    
	return 0;
}

