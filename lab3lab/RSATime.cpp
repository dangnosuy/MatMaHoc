#include <iostream>
#include <string>
#include <chrono>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>
#include <fstream>
#include <cryptopp/pem.h>

class RSACrypto {
public:
    static bool ends_with(const std::string& str, const std::string& suffix) {
        if (str.length() >= suffix.length()) {
            return str.compare(str.length() - suffix.length(), suffix.length(), suffix) == 0;
        }
        return false;
    }
    // Method to generate RSA key pairs
    static void GenerateKeys(int keySize, const std::string &privFilename, const std::string &pubFilename, const std::string mode) {
        CryptoPP::AutoSeededRandomPool rng;

        // Generate the private key
        CryptoPP::RSA::PrivateKey privateKey;
        privateKey.GenerateRandomWithKeySize(rng, keySize);

        // Generate the public key
        CryptoPP::RSA::PublicKey publicKey;
        publicKey.AssignFrom(privateKey);

        if (mode == "pem") {
            CryptoPP::FileSink privFile(privFilename.c_str());
            CryptoPP::PEM_Save(privFile, privateKey);
            privFile.MessageEnd();

        // Save the public key to a file
            CryptoPP::FileSink pubFile(pubFilename.c_str());
            CryptoPP::PEM_Save(pubFile, publicKey);
            pubFile.MessageEnd();
        }
        else {
            CryptoPP::FileSink privFile(privFilename.c_str());
            privateKey.DEREncode(privFile);
            privFile.MessageEnd();

                // Save the public key in DER format
            CryptoPP::FileSink pubFile(pubFilename.c_str());
            publicKey.DEREncode(pubFile);
            pubFile.MessageEnd();
        }
        // Save the private key to a file
        
        std::cout << "RSA key pair generated and saved to files:" << std::endl;
        std::cout << "Private Key: " << privFilename << std::endl;
        std::cout << "Public Key: " << pubFilename << std::endl;
    }

    // Method to encrypt plaintext with a public key file
    static std::string Encrypt(const std::string &plainText, const std::string &pubFilename) {
        CryptoPP::RSA::PublicKey publicKey;
        CryptoPP::FileSource pubFile(pubFilename.c_str(), true);
        if (ends_with(pubFilename, ".pem")) {
            CryptoPP::PEM_Load(pubFile, publicKey);
        } else {
            publicKey.BERDecode(pubFile);
        }

        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
        std::string cipherText;

        CryptoPP::StringSource ss1(plainText, true,
            new CryptoPP::PK_EncryptorFilter(rng, encryptor,
                new CryptoPP::StringSink(cipherText)
            )
        );
        return cipherText;
    }

    // Method to decrypt ciphertext with a private key file
    static std::string Decrypt(const std::string &cipherText, const std::string &privFilename) {
        CryptoPP::RSA::PrivateKey privateKey;
        CryptoPP::FileSource privFile(privFilename.c_str(), true);
        if (ends_with(privFilename, ".pem")) {
            CryptoPP::PEM_Load(privFile, privateKey);
        } else {
            privateKey.BERDecode(privFile);
        }

        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
        std::string recoveredText;

        CryptoPP::StringSource ss2(cipherText, true,
            new CryptoPP::PK_DecryptorFilter(rng, decryptor,
                new CryptoPP::StringSink(recoveredText)
            )
        );
        return recoveredText;
    }
};

// Main function to handle separate key generation, encryption, and decryption commands
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <command> <args...>" << std::endl;
        std::cerr << "Commands: generate, encrypt, decrypt" << std::endl;
        return 1;
    }

    std::string command = argv[1];

    if (command == "generate") {
        // Generate RSA key pair: <program> generate <key_size> <private_key_file> <public_key_file>
        if (argc != 6 && (argv[5] != "dem" || argv[5] != "pem")) {
            std::cerr << "Usage: " << argv[0] << " generate <key_size> <private_key_file> <public_key_file> der/pem" << std::endl;
            return 1;
        }
        int keySize = std::stoi(argv[2]);
        std::string privFilename = argv[3];
        std::string pubFilename = argv[4];
        std::string usePem = argv[5];
        RSACrypto::GenerateKeys(keySize, privFilename, pubFilename, usePem);

    } // Encrypt text: <program> encrypt <input_file> <public_key_file> <HEX, BASE64>
if (command == "encrypt") {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] << " encrypt <input_file> <public_key_file> <HEX, BASE64>" << std::endl;
        return 1;
    }

    std::string inputFile = argv[2];
    std::ifstream file(inputFile);
    if (!file.is_open()) {
        std::cerr << "Could not open file: " << inputFile << std::endl;
        return 1;
    }

    std::ostringstream ss;
    ss << file.rdbuf();
    std::string plainText = ss.str();
    file.close();

    std::string pubFilename = argv[3];
    std::string format = argv[4];
    if (format != "BASE64" && format != "HEX") {
        std::cerr << "Error: Format must be 'BASE64' or 'HEX'" << std::endl;
        return 1;
    }

    std::string cipherText;
    auto total = std::chrono::duration<double, std::milli>::zero();
    for (int i = 0; i < 10000; ++i) {
        auto start = std::chrono::high_resolution_clock::now();
        cipherText = RSACrypto::Encrypt(plainText, pubFilename);
        auto end = std::chrono::high_resolution_clock::now();
        total += (end - start);
    }

    std::string cipherFormat;
    if (format == "BASE64") {
        CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(cipherFormat), false);
        encoder.Put((const unsigned char*)cipherText.data(), cipherText.size());
        encoder.MessageEnd();
    } else {
        CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(cipherFormat));
        encoder.Put((const unsigned char*)cipherText.data(), cipherText.size());
        encoder.MessageEnd();
    }

    std::ofstream outFile("encrypt.txt");
    outFile << cipherFormat;
    outFile.close();

    std::cout << "Encrypted text saved to encrypt.txt\n";
    std::cout << "Average encryption time: " << total.count() / 10000 << " ms\n";
}
else if (command == "decrypt") {
    // Decrypt text: <program> decrypt <HEX, BASE64> <cipher_text/file_name> <private_key_file>
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] << " decrypt <HEX, BASE64> <cipher_text/file_name> <private_key_file>" << std::endl;
        return 1;
    }

    std::string format = argv[2];
    if (format != "HEX" && format != "BASE64") {
        std::cerr << "Usage: " << argv[0] << " decrypt <HEX, BASE64> <cipher_text/file_name> <private_key_file>" << std::endl;
        return 1;
    }

    std::string input = argv[3];
    std::string cipherText;

        // Check if input is a file
    std::ifstream inputFile(input);
    if (inputFile.is_open()) {
            // Read file content
        std::string line;
        while (std::getline(inputFile, line)) {
            cipherText += line + "\n";
        }
        inputFile.close();
            // Remove trailing newline if present
        if (!cipherText.empty() && cipherText.back() == '\n') {
            cipherText.pop_back();
        }
    } else {
         // Input is cipher text
        cipherText = input;
    }

    std::string cipher;
    if (format == "HEX") {
        CryptoPP::StringSource(cipherText, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(cipher)));
    } else {
        CryptoPP::StringSource(cipherText, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(cipher)));
    }

    std::string privFilename = argv[4];
    std::string decryptedText;
    auto total = std::chrono::duration<double, std::milli>::zero();

    try {
        for (int i = 0; i < 10000; ++i) {
            auto start = std::chrono::high_resolution_clock::now();
            decryptedText = RSACrypto::Decrypt(cipher, privFilename);
            auto end = std::chrono::high_resolution_clock::now();
            total += (end - start);
        }

        std::ofstream outFile("decrypt.txt");
        outFile << decryptedText;
        outFile.close();

        std::cout << "Decrypted Text: " << (decryptedText.length() < 80 ? decryptedText : decryptedText.substr(0, 80) + "...") << std::endl;
        std::cout << "Decrypted result saved to decrypt.txt\n";
        std::cout << "Average decryption time: " << total.count() / 10000 << " ms\n";

    } catch (CryptoPP::Exception &e) {
        std::cerr << "Error during decryption: " << e.what() << std::endl;
    }
}
 else {
        std::cerr << "Invalid command: " << command << std::endl;
        std::cerr << "Commands: generate, encrypt, decrypt" << std::endl;
        return 1;
    }

    return 0;
}