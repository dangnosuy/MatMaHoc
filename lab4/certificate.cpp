#include <iostream>
#include <fstream>
#include <string>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <openssl/x509v3.h>

// Hàm chuyển đổi ASN1_TIME thành chuỗi
std::string asn1_time_to_string(const ASN1_TIME* time) {
    if (!time) return "Not specified";
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "Error creating BIO";
    if (!ASN1_TIME_print(bio, time)) {
        BIO_free(bio);
        return "Error printing time";
    }
    char* buffer;
    long len = BIO_get_mem_data(bio, &buffer);
    std::string result(buffer, len);
    BIO_free(bio);
    return result;
}

// Hàm chuyển đổi X509_NAME thành chuỗi
std::string x509_name_to_string(X509_NAME* name) {
    if (!name) return "Not specified";
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "Error creating BIO";
    if (!X509_NAME_print_ex(bio, name, 0, XN_FLAG_ONELINE)) {
        BIO_free(bio);
        return "Error printing name";
    }
    char* buffer;
    long len = BIO_get_mem_data(bio, &buffer);
    std::string result(buffer, len);
    BIO_free(bio);
    return result;
}
void print_signature(X509* cert) {
    const ASN1_BIT_STRING* signature;
    const X509_ALGOR* sig_alg;
    
    X509_get0_signature(&signature, &sig_alg, cert);
    
    if (signature && sig_alg) {
        int sig_nid = OBJ_obj2nid(sig_alg->algorithm);
        
        std::cout << "Signature Value: " << std::endl;
        for (int i = 0; i < signature->length; i++) {
            printf("%02x", signature->data[i]);
            if ((i + 1) % 16 == 0 && i + 1 < signature->length) {
                std::cout << std::endl;
            }
        }
        std::cout << std::endl;
    } else {
        std::cout << "Signature: Not available" << std::endl;
    }
}
// Hàm in thông tin chứng chỉ
void print_certificate_info(X509* cert) {
    // Tên chủ thể
    X509_NAME* subject = X509_get_subject_name(cert);
    std::cout << "Subject: " << x509_name_to_string(subject) << std::endl;

    // Tên nhà phát hành
    X509_NAME* issuer = X509_get_issuer_name(cert);
    std::cout << "Issuer: " << x509_name_to_string(issuer) << std::endl;

    // Ngày hiệu lực
    const ASN1_TIME* not_before = X509_get0_notBefore(cert);
    const ASN1_TIME* not_after = X509_get0_notAfter(cert);
    std::cout << "Valid From: " << asn1_time_to_string(not_before) << std::endl;
    std::cout << "Valid To: " << asn1_time_to_string(not_after) << std::endl;

    // Thuật toán chữ ký
    int sig_nid = X509_get_signature_nid(cert);
    
    const char* sig_name = OBJ_nid2ln(sig_nid);
    std::cout << "Signature Algorithm: " << (sig_name ? sig_name : "Unknown") << std::endl;

    // Khóa công khai
    EVP_PKEY* pubkey = X509_get_pubkey(cert);
    if (pubkey) {
        int key_type = EVP_PKEY_id(pubkey);
        if (key_type == EVP_PKEY_RSA) {
            std::cout << "Public Key: RSA, " << EVP_PKEY_bits(pubkey) << " bits" << std::endl;
        } else if (key_type == EVP_PKEY_EC) {
            std::cout << "Public Key: ECDSA" << std::endl;
        } else {
            std::cout << "Public Key: Unknown type" << std::endl;
        }
        EVP_PKEY_free(pubkey);
    } else {
        std::cout << "Public Key: Not available" << std::endl;
    }

    // Key Usage
    std::cout << "Key Usage: ";
    X509_EXTENSION* ext = X509_get_ext(cert, X509_get_ext_by_NID(cert, NID_key_usage, -1));
    if (ext) {
        ASN1_BIT_STRING* key_usage = nullptr;
        const unsigned char* p = X509_EXTENSION_get_data(ext)->data;
        key_usage = d2i_ASN1_BIT_STRING(nullptr, &p, X509_EXTENSION_get_data(ext)->length);
        if (key_usage) {
            if (ASN1_BIT_STRING_get_bit(key_usage, 0)) std::cout << "Digital Signature, ";
            if (ASN1_BIT_STRING_get_bit(key_usage, 2)) std::cout << "Key Encipherment, ";
            if (ASN1_BIT_STRING_get_bit(key_usage, 3)) std::cout << "Data Encipherment, ";
            if (ASN1_BIT_STRING_get_bit(key_usage, 5)) std::cout << "Key Cert Sign, ";
            ASN1_BIT_STRING_free(key_usage);
        } else {
            std::cout << "Not specified";
        }
    } else {
        std::cout << "Not specified";
    }
    std::cout << std::endl;

    // Extended Key Usage
    std::cout << "Extended Key Usage: ";
    ext = X509_get_ext(cert, X509_get_ext_by_NID(cert, NID_ext_key_usage, -1));
    if (ext) {
        EXTENDED_KEY_USAGE* eku = nullptr;
        const unsigned char* p = X509_EXTENSION_get_data(ext)->data;
        eku = d2i_EXTENDED_KEY_USAGE(nullptr, &p, X509_EXTENSION_get_data(ext)->length);
        if (eku) {
            for (int i = 0; i < sk_ASN1_OBJECT_num(eku); i++) {
                ASN1_OBJECT* obj = sk_ASN1_OBJECT_value(eku, i);
                const char* eku_name = OBJ_nid2ln(OBJ_obj2nid(obj));
                std::cout << (eku_name ? eku_name : "Unknown") << ", ";
            }
            sk_ASN1_OBJECT_pop_free(eku, ASN1_OBJECT_free);
        } else {
            std::cout << "Not specified";
        }
    } else {
        std::cout << "Not specified";
    }
    std::cout << std::endl << std::endl;
    print_signature(cert);
}

// Hàm lưu khóa công khai vào tệp PEM
bool save_public_key(EVP_PKEY* pubkey, const std::string& filename) {
    FILE* fp = fopen(filename.c_str(), "w");
    if (!fp) return false;
    bool success = PEM_write_PUBKEY(fp, pubkey);
    fclose(fp);
    return success;
}

// Hàm xử lý chứng chỉ
EVP_PKEY* process_certificate(const std::string& filename, bool is_pem) {
    FILE* fp = fopen(filename.c_str(), "rb");
    if (!fp) {
        std::cerr << "Cannot open file: " << filename << std::endl;
        return nullptr;
    }

    X509* cert = nullptr;
    if (is_pem) {
        cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    } else {
        cert = d2i_X509_fp(fp, nullptr);
    }
    fclose(fp);

    if (!cert) {
        std::cerr << "Failed to read certificate: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        return nullptr;
    }

    // In thông tin chứng chỉ
    std::cout << "Certificate Info:" << std::endl;
    print_certificate_info(cert);

    // Lấy khóa công khai
    EVP_PKEY* pubkey = X509_get_pubkey(cert);
    if (!pubkey) {
        std::cerr << "Failed to get public key: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        X509_free(cert);
        return nullptr;
    }

    // Kiểm tra chữ ký
    int verify_result = X509_verify(cert, pubkey);
    if (verify_result == 1) {
        std::cout << "Signature: Valid" << std::endl;
        if (save_public_key(pubkey, "pubkey.pem")) {
            std::cout << "Public key saved to pubkey.pem" << std::endl;
        }
        // Tăng refcount và giải phóng cert
        EVP_PKEY_up_ref(pubkey);
        X509_free(cert);
        return pubkey;
    } else {
        std::cerr << "Signature: Invalid (" << ERR_error_string(ERR_get_error(), nullptr) << ")" << std::endl;
        EVP_PKEY_free(pubkey);
        X509_free(cert);
        return nullptr;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <pem|der> <certificate_file>" << std::endl;
        return 1;
    }

    // Khởi tạo OpenSSL (không cần OpenSSL_add_all_algorithms trong OpenSSL 3.x)
    ERR_load_crypto_strings();

    try {
        std::string format = argv[1];
        std::string filename = argv[2];
        bool is_pem = (format == "pem");

        EVP_PKEY* pubkey = process_certificate(filename, is_pem);
        if (!pubkey) {
            std::cerr << "Certificate verification failed or no public key returned" << std::endl;
            return 1;
        }

        // Giải phóng khóa công khai
        EVP_PKEY_free(pubkey);

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    // Dọn dẹp OpenSSL
    ERR_free_strings();

    return 0;
}