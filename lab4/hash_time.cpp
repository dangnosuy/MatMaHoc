#include <iostream>
#include <fstream>
#include <string>
#include <iomanip>
#include <vector>
#include <chrono>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <sstream>


#ifdef _WIN32
#include <windows.h>
#endif

// Hàm chuyển đổi hash thành chuỗi hex
std::string to_hex(const unsigned char* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << (int)data[i];
    }
    return ss.str();
}

// Hàm tính hash chung bằng EVP (hỗ trợ nhiều thuật toán băm)
std::string compute_hash(const std::string& algo, const std::string& input, int output_length = 0) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create EVP context");

    const EVP_MD* md = nullptr;

    if (algo == "SHA224") md = EVP_sha224();
    else if (algo == "SHA256") md = EVP_sha256();
    else if (algo == "SHA384") md = EVP_sha384();
    else if (algo == "SHA512") md = EVP_sha512();
    else if (algo == "SHA3-224") md = EVP_sha3_224();
    else if (algo == "SHA3-256") md = EVP_sha3_256();
    else if (algo == "SHA3-384") md = EVP_sha3_384();
    else if (algo == "SHA3-512") md = EVP_sha3_512();
    else if (algo == "SHAKE128") md = EVP_shake128();
    else if (algo == "SHAKE256") md = EVP_shake256();
    else {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Unsupported algorithm: " + algo);
    }

    if (!EVP_DigestInit_ex(ctx, md, nullptr)) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Digest initialization failed");
    }

    if (!EVP_DigestUpdate(ctx, input.c_str(), input.size())) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Digest update failed");
    }

    std::vector<unsigned char> hash;
    if (algo == "SHAKE128" || algo == "SHAKE256") {
        if (output_length <= 0 || output_length % 8 != 0) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("Output length for SHAKE must be positive and multiple of 8");
        }
        size_t len_bytes = output_length / 8;
        hash.resize(len_bytes);
        if (!EVP_DigestFinalXOF(ctx, hash.data(), len_bytes)) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("Digest finalization failed");
        }
    } else {
        size_t len_bytes = EVP_MD_size(md);
        hash.resize(len_bytes);
        if (!EVP_DigestFinal_ex(ctx, hash.data(), nullptr)) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("Digest finalization failed");
        }
    }

    EVP_MD_CTX_free(ctx);
    return to_hex(hash.data(), hash.size());
}

// Hàm đo hiệu suất trung bình (ms)
double measure_performance(const std::string& algo, const std::string& input, int output_length, int iterations) {
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < iterations; ++i) {
        compute_hash(algo, input, output_length);
    }

    auto end = std::chrono::high_resolution_clock::now();
    double total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    return total_ms / iterations;
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    // Thiết lập console Windows UTF-8
    SetConsoleOutputCP(CP_UTF8);
#endif

    // Khởi tạo OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <algorithm> <input_type> <input> [output_length] [output_file]\n";
        std::cerr << "Algorithms: SHA224, SHA256, SHA384, SHA512, SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256\n";
        std::cerr << "Input type: file, text\n";
        EVP_cleanup();
        ERR_free_strings();
        return 1;
    }

    try {
        std::string algo = argv[1];
        std::string input_type = argv[2];
        std::string input_data;
        int output_length = 0;

        // Đọc dữ liệu đầu vào
        if (input_type == "file") {
            std::ifstream file(argv[3], std::ios::binary);
            if (!file) throw std::runtime_error("Cannot open file: " + std::string(argv[3]));
            input_data.assign((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        } else if (input_type == "text") {
            input_data = argv[3];
        } else {
            throw std::runtime_error("Invalid input type. Use 'file' or 'text'.");
        }

        // Xử lý output_length nếu dùng SHAKE
        if ((algo == "SHAKE128" || algo == "SHAKE256")) {
            if (argc >= 5) {
                output_length = std::stoi(argv[4]);
                if (output_length <= 0 || output_length % 8 != 0)
                    throw std::runtime_error("Output length must be positive and multiple of 8");
            } else {
                throw std::runtime_error("Output length required for SHAKE algorithms");
            }
        }

        // Tính hash
        std::string hash = compute_hash(algo, input_data, output_length);
        std::cout << "Hash: " << hash << std::endl;

        // Lưu ra file nếu có tham số
        if (argc >= 6) {
            std::ofstream out(argv[5]);
            if (!out) throw std::runtime_error("Cannot open output file: " + std::string(argv[5]));
            out << hash;
        }

        // Đo hiệu suất 1000 lần
        double avg_time = measure_performance(algo, input_data, output_length, 1000);
        std::cout << "Average time (1000 runs): " << avg_time << " ms" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_cleanup();
        ERR_free_strings();
        return 1;
    }

    EVP_cleanup();
    ERR_free_strings();

    return 0;
}