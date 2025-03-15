#include <iostream>
#include <fstream>
#include <string>
#include <locale>
#include <chrono>

#include "cryptopp/cryptlib.h"
#include "cryptopp/rijndael.h"
#include "cryptopp/modes.h"
#include "cryptopp/ccm.h"
#include "cryptopp/gcm.h"
#include "cryptopp/xts.h"
#include "cryptopp/files.h"
#include "cryptopp/osrng.h"
#include "cryptopp/hex.h"
#include "cryptopp/filters.h"

using namespace CryptoPP;
using namespace std;

#define TAG_SIZE 12

std::chrono::duration<double, std::micro> globalDuration;
// Chọn chế độ mã hóa
string SelectMode()
{
    int choice;
    while (true)
    {
        cout << "Select mode: " << endl;
        cout << "1. ECB\n2. CBC\n3. OFB\n4. CFB\n5. CTR\n6. XTS\n7. CCM\n8. GCM\n";
        cout << "Enter choice: ";
        cin >> choice;
        if (choice >= 1 && choice <= 8)
        {
            switch (choice)
            {
            case 1:
                return "ECB";
            case 2:
                return "CBC";
            case 3:
                return "OFB";
            case 4:
                return "CFB";
            case 5:
                return "CTR";
            case 6:
                return "XTS";
            case 7:
                return "CCM";
            case 8:
                return "GCM";
            }
        }
        else
            cout << "Invalid choice, please try again.\n";
    }
}

std::string SecByteBlockToHex(const SecByteBlock &block)
{
    std::string encoded;
    StringSource ss(block, block.size(), true,
                    new HexEncoder(new StringSink(encoded)));
    return encoded;
}

// Sinh Key và IV
pair<SecByteBlock, SecByteBlock> Key_Generation(string mode)
{
    AutoSeededRandomPool prng;
    SecByteBlock key((mode == "XTS") ? AES::DEFAULT_KEYLENGTH * 2 : AES::DEFAULT_KEYLENGTH);
    SecByteBlock iv((mode == "CCM") ? prng.GenerateWord32() % 7 + 7 : AES::BLOCKSIZE);
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());
    return make_pair(key, iv);
}
string UInt32ToString(uint32_t n) {
    string s(4, '\0');
    s[0] = (n >> 24) & 0xFF;
    s[1] = (n >> 16) & 0xFF;
    s[2] = (n >> 8) & 0xFF;
    s[3] = n & 0xFF;
    return s;
}

// Hàm chuyển chuỗi 4 byte thành uint32_t
uint32_t StringToUInt32(const string &s) {
    if (s.size() < 4)
        throw runtime_error("Invalid length for uint32 conversion");
    return (static_cast<uint32_t>(static_cast<unsigned char>(s[0])) << 24) |
           (static_cast<uint32_t>(static_cast<unsigned char>(s[1])) << 16) |
           (static_cast<uint32_t>(static_cast<unsigned char>(s[2])) << 8) |
           (static_cast<uint32_t>(static_cast<unsigned char>(s[3])));
}

// Hàm mã hóa
string Encrypt(const string &mode, const SecByteBlock &key, const SecByteBlock &iv, const string &plain)
{
    string cipher;
    auto start = std::chrono::high_resolution_clock::now();
    try
    {
        
        if (mode == "ECB")
        {
            ECB_Mode<AES>::Encryption e;
            e.SetKey(key, key.size());
            StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
        }
        else if (mode == "CBC")
        {
            CBC_Mode<AES>::Encryption e;
            e.SetKeyWithIV(key, key.size(), iv);
            StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
        }
        else if (mode == "OFB")
        {
            OFB_Mode<AES>::Encryption e;
            e.SetKeyWithIV(key, key.size(), iv);
            StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
        }
        else if (mode == "CFB")
        {
            CFB_Mode<AES>::Encryption e;
            e.SetKeyWithIV(key, key.size(), iv);
            StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
        }
        else if (mode == "CTR")
        {
            CTR_Mode<AES>::Encryption e;
            e.SetKeyWithIV(key, key.size(), iv);
            StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
        }
        else if (mode == "XTS")
        {
            XTS_Mode<AES>::Encryption e;
            e.SetKeyWithIV(key, key.size(), iv);
            StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
        }
        else if (mode == "GCM")
        {
            GCM<AES>::Encryption e;
            e.SetKeyWithIV(key, key.size(), iv, iv.size());
            StringSource(plain, true, new AuthenticatedEncryptionFilter(e, new StringSink(cipher)));
        }
        else if (mode == "CCM")
        {
            CCM<AES>::Encryption e;
            e.SetKeyWithIV(key, key.size(), iv, iv.size());
            e.SpecifyDataLengths(0, plain.size(), 0);

            StringSource ss(plain, true,
                            new AuthenticatedEncryptionFilter(e,
                                                              new StringSink(cipher)));
            string plantextLength = UInt32ToString(static_cast<uint32_t>(plain.size()));
            cipher = plantextLength + cipher;
        }
    }
    catch (const Exception &e)
    {
        cerr << "Encryption failed: " << e.what() << endl;
    }
    string encoded;
    StringSource ss2(cipher, true,
                     new HexEncoder(
                         new StringSink(encoded)));
    auto end = std::chrono::high_resolution_clock::now();
    globalDuration = end - start;
    return encoded;
}

// Hàm giải mã
string Decrypt(const string &mode, const SecByteBlock &key, const SecByteBlock &iv, string &cipher)
{
    
    string recovered; 
    
    try
    {
        auto start = std::chrono::high_resolution_clock::now();   
        if (mode == "ECB")
        {
            ECB_Mode<AES>::Decryption d;
            d.SetKey(key, key.size());
            StringSource(cipher, true, new StreamTransformationFilter(d, new StringSink(recovered)));
        }
        else if (mode == "CBC")
        {
            CBC_Mode<AES>::Decryption d;
            d.SetKeyWithIV(key, key.size(), iv);
            StringSource(cipher, true, new StreamTransformationFilter(d, new StringSink(recovered)));
        }
        else if (mode == "OFB")
        {
            OFB_Mode<AES>::Decryption d;
            d.SetKeyWithIV(key, key.size(), iv);
            StringSource(cipher, true, new StreamTransformationFilter(d, new StringSink(recovered)));
        }
        else if (mode == "CFB")
        {
            CFB_Mode<AES>::Decryption d;
            d.SetKeyWithIV(key, key.size(), iv);
            StringSource(cipher, true, new StreamTransformationFilter(d, new StringSink(recovered)));
        }
        else if (mode == "CTR")
        {
            CTR_Mode<AES>::Decryption d;
            d.SetKeyWithIV(key, key.size(), iv);
            StringSource(cipher, true, new StreamTransformationFilter(d, new StringSink(recovered)));
        }
        else if (mode == "GCM")
        {
            GCM<AES>::Decryption d;
            d.SetKeyWithIV(key, key.size(), iv, iv.size());
            AuthenticatedDecryptionFilter df(d, new StringSink(recovered));
            StringSource ss2(cipher, true, new Redirector(df));

        }
        else if (mode == "XTS") {
            XTS_Mode<AES>::Decryption d;
            d.SetKeyWithIV(key, key.size(), iv);
            StringSource(cipher, true, new StreamTransformationFilter(d, new StringSink(recovered))
            );
        }
        else if (mode == "CCM")
        {
            CCM<AES>::Decryption d;
            d.SetKeyWithIV(key, key.size(), iv, iv.size());
            string lenStr = cipher.substr(0, 4);
            uint32_t plaintextLen = StringToUInt32(lenStr);
            cipher = cipher.substr(4);

            d.SpecifyDataLengths(0, plaintextLen, 0);
            AuthenticatedDecryptionFilter df(d, new StringSink(recovered));
            StringSource ss2(cipher, true,
                             new Redirector(df));

        }
        auto end = std::chrono::high_resolution_clock::now();
        globalDuration = end - start;
    }
    catch (const Exception &)
    {
        cerr << "Decryption failed! Invalid ciphertext." << endl;
        return "";
    }
    return recovered;
}

int main()
{
    std::locale::global(std::locale("C.utf8"));
    int action;
    cout << "Choose action:\n1. Encrypt\n2. Decrypt\nEnter choice: ";
    cin >> action;
    cin.ignore();
    string mode = SelectMode();

    if (action == 1) // Mã hóa
    {
        auto key_iv = Key_Generation(mode);
        SecByteBlock key = key_iv.first;
        SecByteBlock iv = key_iv.second;

        string plain, cipher;
        cout << "Enter plaintext: ";
        cin.ignore();
        getline(cin, plain);
        cout << "Key: " << SecByteBlockToHex(key) << endl;
        cout << "IV: " << SecByteBlockToHex(iv) << endl;
        cipher = Encrypt(mode, key, iv, plain);
        cout << "Cipher: " << cipher << endl;
        cout << "Execution time: " << globalDuration.count() << "ms" << endl;
        ofstream keyFile("key_iv.txt");
        keyFile << SecByteBlockToHex(key) << endl;
        keyFile << SecByteBlockToHex(iv) << endl;
        keyFile.close();
        ofstream outputFile("output.txt");
        outputFile << cipher << endl;
        outputFile.close();
    }
    else if (action == 2) // Giải mã
    {
        int a;
        string key_hex, iv_hex, cipher_hex;
        ifstream keyFile("key_iv.txt");
        getline(keyFile, key_hex);
        getline(keyFile, iv_hex);
        keyFile.close();
        cout << "Choose action:\n1. On screen\n2. On file\nEnter choice: ";
        cin >> a;
        if (a == 1)
        {
            cout << "Enter ciphertext (Hex): ";
            cin >> cipher_hex;
        }
        else if (a == 2)
        {
            ifstream outputFile("output.txt");
            getline(outputFile, cipher_hex);
        }
        string decoded;
        StringSource(cipher_hex, true, new HexDecoder(new StringSink(decoded)));
        SecByteBlock key((mode == "XTS") ? AES::DEFAULT_KEYLENGTH * 2 : AES::DEFAULT_KEYLENGTH);
        StringSource ssKey(key_hex, true,
                           new HexDecoder(new ArraySink(key, key.size())));
        SecByteBlock iv(iv_hex.size() / 2);
        StringSource ssIV(iv_hex, true,
                          new HexDecoder(new ArraySink(iv, iv.size())));
        string recovered = Decrypt(mode, key, iv, decoded);
        cout << "Key: " << SecByteBlockToHex(key) << endl;
        if (mode != "EBC")
            cout << "IV: " << SecByteBlockToHex(iv) << endl;
        if (!recovered.empty())
            cout << "Recovered text: " << recovered << endl;
        cout << "Execution time: " << globalDuration.count() << "ms" << endl;
    }
    return 0;
}