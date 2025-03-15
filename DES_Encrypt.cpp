#include <iostream>
#include <string>
#include <cstdlib>
#include <utility>
#include <fstream>
#include <tuple>
#include <locale>
#include <bitset>

#include "cryptopp/des.h"
#include "cryptopp/osrng.h"
#include "cryptopp/modes.h" //ECB, CBC, CBC-CTS, CFB, OFB, CTR
#include "cryptopp/hex.h"
#include "cryptopp/xts.h"
#include "cryptopp/base64.h"

#include "cryptopp/xts.h"
#include "cryptopp/ccm.h"
#include "cryptopp/gcm.h"

// using namespace std;

using namespace CryptoPP;

// Hàm chuyển đổi SecByteBlock thành chuỗi hex để hiển thị
std::string SecByteBlockToHex(const SecByteBlock &block)
{
    std::string encoded;
    StringSource ss(block, block.size(), true,
                    new HexEncoder(new StringSink(encoded)));
    return encoded;
}

std::pair<SecByteBlock, SecByteBlock> Key_Generation()
{
    std::pair<SecByteBlock, SecByteBlock> key_iv;
    int choices = 0;
    while (choices <= 0 || choices > 2)
    {
        std::cout << "Do you want generate key random (1) or import key from file (2): ";
        std::cin >> choices;
        if (choices == 1)
        {
            AutoSeededRandomPool prng;
            SecByteBlock key(0x00, DES_EDE2::DEFAULT_KEYLENGTH);
            prng.GenerateBlock(key, key.size());
            key_iv.first = key;

            SecByteBlock iv(0x00, DES_EDE2::DEFAULT_KEYLENGTH);
            prng.GenerateBlock(iv, DES_EDE2::BLOCKSIZE);
            key_iv.second = iv;
        }
        else if (choices == 2)
        {
            while (true)
            {
                std::cout << "Import file name: ";
                std::string filename;
                std::cin >> filename;

                std::ifstream inFile(filename);

                if (!inFile)
                {
                    std::cout << "Cannot open file! Check your file name!\n"
                              << std::endl;
                    continue;
                }

                std::string keyHex, ivHex;
                std::getline(inFile, keyHex);
                std::getline(inFile, ivHex);
                inFile.close();

                // Giải mã key từ hex sang SecByteBlock
                SecByteBlock key(DES_EDE2::DEFAULT_KEYLENGTH);
                StringSource ssKey(keyHex, true,
                                   new HexDecoder(new ArraySink(key, key.size())));
                key_iv.first = key;
                // Đưa cả iv về SetByteBlock không sao, vì SecByteBlock nó bao gồm cả biến Bytes thì phải?
                SecByteBlock iv(DES_EDE2::BLOCKSIZE);
                StringSource ssIV(ivHex, true,
                                  new HexDecoder(new ArraySink(iv, iv.size())));

                key_iv.second = iv;
                break;
            }
        }
    }
    return key_iv;
}
void WriteDecryptToFile(std::string result1) {
    std::string filename;
    std::cout << "Enter filename to save decrypt text: ";
    std::cin >> filename;

    std::ofstream outFile(filename);
    if (!outFile) {
        std::cerr << "Can't not open file " << filename << "\n";
    }
    outFile << result1;
    outFile.close();
    std::cout << "Result has saved in " << filename << "\n";
}
void WriteEncryptToFile(std::string result1, std::string result2, std::string result3) {
    std::string filename;
    std::cout << "Enter filename to save encrypt text: ";
    std::cin >> filename;

    std::ofstream outFile(filename);
    if (!outFile) {
        std::cerr << "Can't not open file " << filename << "\n";
    }
    outFile << result1 << std::endl << result2 << std::endl << result3;
    outFile.close();
    std::cout << "Result has saved in " << filename << "\n";
}

void Encrypt_DES_MODE_EBC(std::string &plaintext)
{
    std::pair<SecByteBlock, SecByteBlock> key_iv;
    key_iv = Key_Generation();

    std::string cipher, encoded;
    try
    {
        std::cout << "Plain text: " << plaintext << std::endl;

        ECB_Mode<DES_EDE2>::Encryption e;
        e.SetKey(key_iv.first, key_iv.first.size());

        StringSource ss1(plaintext, true, new StreamTransformationFilter(e, new StringSink(cipher)));
    }
    catch (const CryptoPP::Exception &ex)
    {
        std::cout << ex.what() << std::endl;
    }
    StringSource ss2(cipher, true,
                     new HexEncoder(
                         new StringSink(encoded)) // HexEncoder
    );

    SecByteBlock iv(0x00, DES_EDE2::BLOCKSIZE);
    std::string binaryStr = "", base64Str, binaryDecode;
    StringSource ss(encoded, true, new HexDecoder(new StringSink(binaryDecode))); // chuyen doi hex - > binary
    StringSource ss1(binaryDecode, true, new Base64Encoder(new StringSink(base64Str)));
    
    
    
    for (unsigned char c : binaryDecode) {
        binaryStr += std::bitset<8>(c).to_string();
    }
    WriteEncryptToFile(encoded, binaryStr, base64Str);
    std::cout << "Cipher text: " << encoded << std::endl;
    std::cout << "Cipher text (Binary): " << binaryStr << std::endl;
    std::cout << "Cipher text (Base64): " << base64Str << std::endl;
    std::cout << "Key (Hex): " << SecByteBlockToHex(key_iv.first) << std::endl;
}
void Encrypt_DES_MODE_IV(std::string &plaintext, int mode)
{
    std::pair<SecByteBlock, SecByteBlock> key_iv;
    key_iv = Key_Generation();

    std::string cipher, encoded;
    try
    {
        std::cout << "Plain text: " << plaintext << std::endl;
        if (mode == 2) {
            CBC_Mode<DES_EDE2>::Encryption e;
            e.SetKeyWithIV(key_iv.first, key_iv.first.size(), key_iv.second);

            StringSource ss1(plaintext, true, new StreamTransformationFilter(e, new StringSink(cipher)));
        }
        else if (mode == 3) {
            OFB_Mode<DES_EDE2>::Encryption e;
            e.SetKeyWithIV(key_iv.first, key_iv.first.size(), key_iv.second);

            StringSource ss1(plaintext, true, new StreamTransformationFilter(e, new StringSink(cipher)));
        }
        else if (mode == 4) {
            CFB_Mode<DES_EDE2>::Encryption e;
            e.SetKeyWithIV(key_iv.first, key_iv.first.size(), key_iv.second);
            StringSource ss3(plaintext, true, new StreamTransformationFilter(e, new StringSink(cipher)));
        }
        else if (mode == 5) {
            CTR_Mode<DES_EDE2>::Encryption e;
            e.SetKeyWithIV(key_iv.first, key_iv.first.size(), key_iv.second);
            StringSource ss3(plaintext, true, new StreamTransformationFilter(e, new StringSink(cipher)));
        }
    }
    catch (const CryptoPP::Exception &ex)
    {
        std::cout << ex.what() << std::endl;
    }
    StringSource ss2(cipher, true,
                     new HexEncoder(
                         new StringSink(encoded)) // HexEncoder
    );
    std::string binaryDecode, base64Str, binaryStr = "";
    StringSource ss(encoded, true, new HexDecoder(new StringSink(binaryDecode)));
    StringSource ss1(binaryDecode, true, new Base64Encoder(new StringSink(base64Str)));
    
    SecByteBlock iv(key_iv.second, DES_EDE2::BLOCKSIZE); 
    for (unsigned char c : binaryDecode) {
        // std::bitset<8>(c) chuyển byte c thành chuỗi 8 bit
        binaryStr += std::bitset<8>(c).to_string();
    }
    WriteEncryptToFile(encoded, binaryStr, base64Str);
    std::cout << "Cipher text (Hex): " << encoded << std::endl;
    std::cout << "Cipher text (Binary): " << binaryStr << std::endl;
    std::cout << "Cipher text (Base64): " << base64Str << std::endl;
    std::cout << "Key (Hex): " << SecByteBlockToHex(key_iv.first) << std::endl;
    std::cout << "IV (Hex): " << SecByteBlockToHex(iv) << std::endl;
}


void Decrypt_DES_EBC_Mode(std::string ciphertext)
{
    std::cout << "This is Decrypt Mode, No Choose Random Key Option!\n";
    std::pair<SecByteBlock, SecByteBlock> key_iv;
    key_iv = Key_Generation();

    std::string rawCipher;
    StringSource ssCipher(ciphertext, true,
                          new HexDecoder(new StringSink(rawCipher)));

    std::string cipher, encoded, decode_cipher;
    try
    {
        ECB_Mode<DES_EDE2>::Decryption d;
        d.SetKey(key_iv.first, key_iv.first.size());
        StringSource ss3(rawCipher, true,
                         new StreamTransformationFilter(d,
                                                        new StringSink(decode_cipher)));
    }
    catch (const CryptoPP::Exception &e)
    {
        std::cout << e.what() << std::endl;
        exit(1);
    }

    // StringSource xx(binaryDecode, true, new BaseN_Encoder(new StringSink(base64Decode)));
    WriteDecryptToFile(decode_cipher);
    SecByteBlock iv(0x00, DES_EDE2::BLOCKSIZE);
    std::cout << "Decrypt text : " << decode_cipher << std::endl;

    // td::cout << "Decrypt text (Binary): " << decode_cipher << std::endl;
    std::cout << "Key (Hex): " << SecByteBlockToHex(key_iv.first) << std::endl;
}
void Decrypt_DES_Mode_IV(std::string ciphertext, int mode)
{
    std::cout << "This is Decrypt Mode, No Choose Random Key Option!\n";
    std::pair<SecByteBlock, SecByteBlock> key_iv;
    key_iv = Key_Generation();

    std::string rawCipher;
    StringSource ssCipher(ciphertext, true,
                          new HexDecoder(new StringSink(rawCipher)));

    std::string cipher, encoded, decode_cipher;
    try
    {
        if (mode == 2) {
            CBC_Mode<DES_EDE2>::Decryption d;
            d.SetKeyWithIV(key_iv.first, key_iv.first.size(), key_iv.second);
            StringSource ss3(rawCipher, true,
                         new StreamTransformationFilter(d,
                                                        new StringSink(decode_cipher)));
        }
        else if (mode == 3) {
            OFB_Mode<DES_EDE2>::Decryption d;
            d.SetKeyWithIV(key_iv.first, key_iv.first.size(), key_iv.second);
            StringSource ss3(rawCipher, true,
                         new StreamTransformationFilter(d,
                                                        new StringSink(decode_cipher)));
        }
        else if (mode == 4) {
            CFB_Mode<DES_EDE2>::Decryption d;
            d.SetKeyWithIV(key_iv.first, key_iv.first.size(), key_iv.second);
            StringSource ss3(rawCipher, true,
                         new StreamTransformationFilter(d,
                                                        new StringSink(decode_cipher)));
        }
        else if (mode == 5) {
            CTR_Mode<DES_EDE2>::Decryption d;
            d.SetKeyWithIV(key_iv.first, key_iv.first.size(), key_iv.second);
            StringSource ss3(rawCipher, true,
                         new StreamTransformationFilter(d,
                                                        new StringSink(decode_cipher)));
        }
    }
    catch (const CryptoPP::Exception &e)
    {
        std::cout << e.what() << std::endl;
        exit(1);
    }
    WriteDecryptToFile(decode_cipher);

    // StringSource xx(binaryDecode, true, new BaseN_Encoder(new StringSink(base64Decode)));
    std::cout << "Key (Hex): " << SecByteBlockToHex(key_iv.first) << std::endl;
    std::cout << "IV (Hex): " << SecByteBlockToHex(key_iv.second) << std::endl;
    //SecByteBlock iv(0x00, DES_EDE2::BLOCKSIZE);
    std::cout << "Decrypt text : " << decode_cipher << std::endl;
}

std::string InputText()
{
    std::string text;
    int choose = 0;
    while (choose <= 0 || choose > 2)
    {
        std::cout << "Input plaintext/ciphertext from screen (1) or file (2): ";
        std::cin >> choose;
        switch (choose)
        {
        case 1:
            std::cout << "Plaintext/Ciphertext: ";
            std::cin.ignore();
            getline(std::cin, text);
            return text;
        case 2:
        {
            std::cout << "Import file name: ";
            std::string filename;
            std::cin >> filename;

            std::ifstream inFile(filename);

            if (!inFile)
            {
                std::cout << "Cannot open file! Check your file name!\n"
                          << std::endl;
                continue;
            }

            std::string line;
            while (std::getline(inFile, line))
            {
                text += line + "\n";
            }

            inFile.close();
            return text;
        }
        default:
            std::cout << "Choose is not valid! Try again.\n";
            break;
        }
    }
    return "";
}

void ChooseEncrypt(int mode)
{
    std::string plaintext = InputText();
    if (mode == 1)
        Encrypt_DES_MODE_EBC(plaintext);
    else
        Encrypt_DES_MODE_IV(plaintext, mode);

}

void ChooseDecrypt(int mode)
{
    std::string ciphertext = InputText();
    if (mode == 1)
        Decrypt_DES_EBC_Mode(ciphertext);
    else 
        Decrypt_DES_Mode_IV(ciphertext, mode);
}

int main()
{

    // Đặt locale cho toàn bộ chương trình
    try {
        std::locale::global(std::locale("C.utf8"));
    } catch (const std::runtime_error& e) {
        std::cerr << "Can't not use C.utf8\n";
    }

    int choose = 0;
    int mode = 0;
    while (choose <= 0 || choose > 2) {
        std::cout << "Enter mode you choose: \n1. Encrypt\n2. Decrypt\n=> Your option: ";
        std::cin >> choose;
        while (mode <= 0 || mode > 6) {
            std::cout << "Enter mode encrypt/decrypt you want: \n1. EBC Mode\n2. CBC Mode\n3. OFB Mode\n4. CFB Mode\n5. CTR Mode\n=> Your option: ";
            std::cin >> mode;
            if (mode <= 0 || mode > 6) {
                std::cout << "Your option is invalid! Try Again\n";
            }
        }
        switch (choose)
        {
        case 1:
            ChooseEncrypt(mode);
            break;
        case 2:
            ChooseDecrypt(mode);
            break;
        default:
            std::cout << "Invalid option! Try again\n";
            break;
        }
    }

    return 0;
}

