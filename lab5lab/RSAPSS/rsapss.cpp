#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <locale>
#include <codecvt>
#include <stdexcept>

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

// Generate RSA key pair and save to files
void generate_keys(const std::string& priv_key_file, const std::string& pub_key_file, int key_size = 2048) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_PKEY_CTX");
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize key generation");
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, key_size) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to set RSA key size");
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to generate RSA key pair");
    }
    EVP_PKEY_CTX_free(ctx);

    // Save private key
    FILE* priv_file = fopen(priv_key_file.c_str(), "w");
    if (!priv_file) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Cannot open private key file for writing");
    }
    if (!PEM_write_PrivateKey(priv_file, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
        fclose(priv_file);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to write private key");
    }
    fclose(priv_file);

    // Save public key
    FILE* pub_file = fopen(pub_key_file.c_str(), "w");
    if (!pub_file) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Cannot open public key file for writing");
    }
    if (!PEM_write_PUBKEY(pub_file, pkey)) {
        fclose(pub_file);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to write public key");
    }
    fclose(pub_file);

    EVP_PKEY_free(pkey);
    std::cout << "RSA keys (" << key_size << " bits) generated and saved to " 
              << priv_key_file << " and " << pub_key_file << std::endl;
}

// Sign a message using RSA-PSS and save as Base64
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
    EVP_PKEY* pkey = PEM_read_PrivateKey(priv_file, nullptr, nullptr, nullptr);
    fclose(priv_file);
    if (!pkey) {
        throw std::runtime_error("Failed to read private key");
    }

    // Create signing context
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    EVP_PKEY_CTX* pkey_ctx = nullptr;
    if (EVP_DigestSignInit(md_ctx, &pkey_ctx, EVP_sha256(), nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to initialize signing");
    }

    // Set RSA-PSS padding
    if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to set RSA-PSS padding");
    }

    // Set salt length to digest length (recommended)
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to set PSS salt length");
    }

    // Set MGF1 hash function to SHA-256
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha256()) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to set MGF1 hash function");
    }

    // Update with message data
    if (EVP_DigestSignUpdate(md_ctx, message.c_str(), message.length()) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to update signing");
    }

    // Get signature length
    size_t sig_len;
    if (EVP_DigestSignFinal(md_ctx, nullptr, &sig_len) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to get signature length");
    }

    // Create signature
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
    std::cout << "RSA-PSS signature saved to " << signature_file << " (Base64 encoded)" << std::endl;
}

// Verify a Base64-encoded RSA-PSS signature
void verify_signature(const std::string& message_file, const std::string& signature_file, const std::string& pub_key_file) {
    // Read message
    std::string message = read_file(message_file);

    // Read public key
    FILE* pub_file = fopen(pub_key_file.c_str(), "r");
    if (!pub_file) {
        throw std::runtime_error("Cannot open public key file");
    }
    EVP_PKEY* pkey = PEM_read_PUBKEY(pub_file, nullptr, nullptr, nullptr);
    fclose(pub_file);
    if (!pkey) {
        throw std::runtime_error("Failed to read public key");
    }

    // Read and decode Base64 signature
    std::string base64_sig = read_file(signature_file);
    std::vector<unsigned char> signature = base64_decode(base64_sig);

    // Create verification context
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    EVP_PKEY_CTX* pkey_ctx = nullptr;
    if (EVP_DigestVerifyInit(md_ctx, &pkey_ctx, EVP_sha256(), nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to initialize verification");
    }

    // Set RSA-PSS padding
    if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to set RSA-PSS padding");
    }

    // Set salt length to digest length (same as signing)
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to set PSS salt length");
    }

    // Set MGF1 hash function to SHA-256
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha256()) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to set MGF1 hash function");
    }

    // Update with message data
    if (EVP_DigestVerifyUpdate(md_ctx, message.c_str(), message.length()) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to update verification");
    }

    // Verify signature
    int result = EVP_DigestVerifyFinal(md_ctx, signature.data(), signature.size());
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

    if (result == 1) {
        std::cout << "RSA-PSS signature is VALID" << std::endl;
    } else if (result == 0) {
        std::cout << "RSA-PSS signature is INVALID" << std::endl;
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
            std::cerr << "  genkey <private_key_file> <public_key_file> [key_size]" << std::endl;
            std::cerr << "  sign " << std::endl;
            std::cerr << "  verify <message_file> <signature_file> <public_key_file>" << std::endl;
            std::cerr << "Default key size: 2048 bits" << std::endl;
            return 1;
        }

        std::string command = argv[1];
        if (command == "genkey" && (argc == 4 || argc == 5)) {
            int key_size = 2048;
            if (argc == 5) {
                key_size = std::stoi(argv[4]);
                if (key_size < 1024) {
                    std::cerr << "Warning: Key size should be at least 1024 bits for security" << std::endl;
                } 
            }
            generate_keys(argv[2], argv[3], key_size);
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
            std::cerr << "Invalid arguments" << std::endl;
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