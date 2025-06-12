#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <locale>
#include <codecvt>
#include <stdexcept>
#include <map>

// Initialize OpenSSL
void init_openssl() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

// Clean up OpenSSL
void cleanup_openssl() {
    EVP_cleanup();
    ERR_free_strings();
}

// Read file content into a string (supports UTF-8)
std::string read_file(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file: " + filename);
    }
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    return content;
}

// Write content to a file
void write_file(const std::string& filename, const std::string& content) {
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot write to file: " + filename);
    }
    file << content;
    file.close();
}

// Base64 encode
std::string base64_encode(const unsigned char* data, size_t len) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // No newlines
    BIO_write(b64, data, len);
    BIO_flush(b64);
    BUF_MEM* mem_ptr;
    BIO_get_mem_ptr(mem, &mem_ptr);
    std::string result(mem_ptr->data, mem_ptr->length);
    BIO_free_all(b64);
    return result;
}

// Base64 decode
std::vector<unsigned char> base64_decode(const std::string& encoded) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(encoded.data(), encoded.length());
    b64 = BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // No newlines
    std::vector<unsigned char> decoded(encoded.length());
    int len = BIO_read(b64, decoded.data(), encoded.length());
    decoded.resize(len);
    BIO_free_all(b64);
    return decoded;
}
// Map of curve names to OpenSSL NIDs
const std::map<std::string, int> curve_map = {
    {"secp256r1", NID_X9_62_prime256v1},
    {"secp384r1", NID_secp384r1},
    {"secp521r1", NID_secp521r1},
    {"secp256k1", NID_secp256k1}
};

// Generate ECDSA key pair and save to files
void generate_keys(const std::string& priv_key_file, const std::string& pub_key_file) {
    // Prompt user to select a curve
    std::cout << "Available curves:" << std::endl;
    int index = 1;
    for (const auto& curve : curve_map) {
        std::cout << index++ << ". " << curve.first << std::endl;
    }
    std::cout << "Select a curve (1-" << curve_map.size() << ", default=1): ";
    std::string input;
    std::getline(std::cin, input);
    int choice = 1;
    try {
        if (!input.empty()) {
            choice = std::stoi(input);
        }
        if (choice < 1 || choice > static_cast<int>(curve_map.size())) {
            throw std::out_of_range("Invalid choice");
        }
    } catch (...) {
        choice = 1; // Default to secp256r1
    }

    // Get the selected curve NID
    auto it = curve_map.begin();
    std::advance(it, choice - 1);
    int curve_nid = it->second;
    std::cout << "Using curve: " << it->first << std::endl;

    // Generate key
    EC_KEY* key = EC_KEY_new_by_curve_name(curve_nid);
    if (!key) {
        throw std::runtime_error("Failed to create EC key");
    }

    if (!EC_KEY_generate_key(key)) {
        EC_KEY_free(key);
        throw std::runtime_error("Failed to generate EC key pair");
    }

    // Save private key
    FILE* priv_file = fopen(priv_key_file.c_str(), "w");
    if (!priv_file) {
        EC_KEY_free(key);
        throw std::runtime_error("Cannot open private key file for writing");
    }
    if (!PEM_write_ECPrivateKey(priv_file, key, nullptr, nullptr, 0, nullptr, nullptr)) {
        fclose(priv_file);
        EC_KEY_free(key);
        throw std::runtime_error("Failed to write private key");
    }
    fclose(priv_file);

    // Save public key
    FILE* pub_file = fopen(pub_key_file.c_str(), "w");
    if (!pub_file) {
        EC_KEY_free(key);
        throw std::runtime_error("Cannot open public key file for writing");
    }
    if (!PEM_write_EC_PUBKEY(pub_file, key)) {
        fclose(pub_file);
        EC_KEY_free(key);
        throw std::runtime_error("Failed to write public key");
    }
    fclose(pub_file);

    EC_KEY_free(key);
    std::cout << "Keys generated and saved to " << priv_key_file << " and " << pub_key_file << std::endl;
}

// Sign a message using ECDSA and save as Base64
void sign_message(const std::string& message_file, const std::string& priv_key_file, const std::string& signature_file, const bool isFile) {
    // Read message
    std::string message;
    if (isFile)
        message = read_file(message_file);
    else 
        message = message_file;

    // Read private key
    FILE* priv_file = fopen(priv_key_file.c_str(), "r");
    if (!priv_file) {
        throw std::runtime_error("Cannot open private key file");
    }
    EC_KEY* key = PEM_read_ECPrivateKey(priv_file, nullptr, nullptr, nullptr);
    fclose(priv_file);
    if (!key) {
        throw std::runtime_error("Failed to read private key");
    }

    // Create SHA-256 hash of the message
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(message.c_str()), message.length(), hash);

    // Create signature
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!EVP_PKEY_assign_EC_KEY(pkey, key)) {
        EVP_PKEY_free(pkey);
        EC_KEY_free(key);
        throw std::runtime_error("Failed to assign EC key to EVP");
    }

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestSignInit(md_ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to initialize signing");
    }

    if (EVP_DigestSignUpdate(md_ctx, hash, SHA256_DIGEST_LENGTH) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to update signing");
    }

    size_t sig_len;
    if (EVP_DigestSignFinal(md_ctx, nullptr, &sig_len) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to get signature length");
    }

    std::vector<unsigned char> signature(sig_len);
    if (EVP_DigestSignFinal(md_ctx, signature.data(), &sig_len) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to finalize signature");
    }

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

    // Encode signature to Base64
    std::string base64_sig = base64_encode(signature.data(), sig_len);

    // Save Base64 signature to file
    write_file(signature_file, base64_sig);
    std::cout << "Signature saved to " << signature_file << " (Base64 encoded)" << std::endl;
}

// Verify a Base64-encoded signature using ECDSA
void verify_signature(const std::string& message_file, const std::string& signature_file, const std::string& pub_key_file) {
    // Read message
    std::string message = read_file(message_file);

    // Read public key
    FILE* pub_file = fopen(pub_key_file.c_str(), "r");
    if (!pub_file) {
        throw std::runtime_error("Cannot open public key file");
    }
    EC_KEY* key = PEM_read_EC_PUBKEY(pub_file, nullptr, nullptr, nullptr);
    fclose(pub_file);
    if (!key) {
        throw std::runtime_error("Failed to read public key");
    }

    // Read and decode Base64 signature
    std::string base64_sig = read_file(signature_file);
    std::vector<unsigned char> signature = base64_decode(base64_sig);

    // Create SHA-256 hash of the message
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(message.c_str()), message.length(), hash);

    // Verify signature
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!EVP_PKEY_assign_EC_KEY(pkey, key)) {
        EVP_PKEY_free(pkey);
        EC_KEY_free(key);
        throw std::runtime_error("Failed to assign EC key to EVP");
    }

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestVerifyInit(md_ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to initialize verification");
    }

    if (EVP_DigestVerifyUpdate(md_ctx, hash, SHA256_DIGEST_LENGTH) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to update verification");
    }

    int result = EVP_DigestVerifyFinal(md_ctx, signature.data(), signature.size());
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

    if (result == 1) {
        std::cout << "Signature is VALID" << std::endl;
    } else if (result == 0) {
        std::cout << "Signature is INVALID" << std::endl;
    } else {
        throw std::runtime_error("Error: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }
}

int main(int argc, char* argv[]) {
    init_openssl();
    try {
        if (argc < 2) {
            std::cerr << "Usage: " << argv[0] << " <command> [args]" << std::endl;
            std::cerr << "Commands:" << std::endl;
            std::cerr << "  genkey <private_key_file> <public_key_file>" << std::endl;
            std::cerr << "  sign" << std::endl;
            std::cerr << "  verify <message_file> <signature_file> <public_key_file>" << std::endl;
            return 1;
        }

        std::string command = argv[1];
        if (command == "genkey" && argc == 4) {
            generate_keys(argv[2], argv[3]);
        } else if (command == "sign") {
            int type = 2;
            std::cout << "Input type (Screen [1] | File[2]) (default=2): ";
            std::cin >> type;
            
            if (type == 2) {
                sign_message(argv[2], argv[3], argv[4], true);
            }
            else {
                std::string message = "";
                std::string privateFile, signatureFile;
                std::cout << "Message: ";
                std::cin.ignore();
                getline(std::cin, message);
                std::cout << "Private File: ";
                std::cin >> privateFile;
                std::cout << "Save file: ";
                std::cin >> signatureFile;
                sign_message(message, privateFile, signatureFile, false);
            }
            
        } else if (command == "verify" && argc == 5) {
            verify_signature(argv[2], argv[3], argv[4]);
        } else {
            std::cerr << "Argument is invalid" << std::endl;
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        cleanup_openssl();
        return 1;
    }
    cleanup_openssl();
    return 0;
}