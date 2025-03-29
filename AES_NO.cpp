#include <iostream>
#include <vector>
#include <stdexcept>
#include <cstring>   // cho memcpy
#include <iomanip>   // cho std::hex, std::setw
#include <algorithm> // cho std::copy

class AES
{
public:
    //===========================================================
    // Hằng số S-Box
    //===========================================================
    static const unsigned char S_BOX[256];
    // Bảng nghịch đảo S-Box (nếu bạn cần dùng cho giải mã)
    static const unsigned char INV_S_BOX[256];

    //===========================================================
    // Rcon (chỉ dùng byte đầu, 3 byte sau = 0)
    // Dành cho quá trình KeyExpansion
    //===========================================================
    static const unsigned char RCON[10][4];

    //===========================================================
    // Constructor: Nhận key (mặc định 128-bit)
    //===========================================================
    AES(const std::vector<unsigned char> &keyBytes)
    {
        setKey(keyBytes);
    }

    //===========================================================
    // Đặt (hoặc đổi) key
    //===========================================================
    void setKey(const std::vector<unsigned char> &keyBytes)
    {
        if(keyBytes.size() != 16 && keyBytes.size() != 24 && keyBytes.size() != 32)
        {
            throw std::runtime_error("Key length must be 128, 192, or 256 bits.");
        }
        key_ = keyBytes;
        // Tạo roundKeys
        keyExpansion(key_);
    }

    //===========================================================
    // CBC Encrypt
    //===========================================================
    std::vector<unsigned char> cbc_encrypt(const std::vector<unsigned char> &plaintext, 
                                           const std::vector<unsigned char> &iv)
    {
        // 1) PKCS#7 padding
        std::vector<unsigned char> padded = pkcs7_padding(plaintext);

        // 2) Chia dữ liệu thành từng block 16 byte
        size_t blockCount = padded.size() / 16;

        // 3) Kết quả sau mã hoá
        std::vector<unsigned char> ciphertext;
        ciphertext.resize(padded.size() + 16); // 16 byte đầu sẽ chứa IV

        // Sao chép IV vào đầu kết quả (như cách bạn nêu trong mã Python)
        std::copy(iv.begin(), iv.end(), ciphertext.begin());

        // Biến tạm để xử lý XOR
        std::vector<unsigned char> prevBlock(iv.begin(), iv.end());

        // 4) Mã hoá từng block
        for(size_t i = 0; i < blockCount; ++i)
        {
            // Lấy block i
            std::vector<unsigned char> block(padded.begin() + i*16, padded.begin() + (i+1)*16);

            // XOR với previous block (hoặc IV cho block đầu)
            for(int j = 0; j < 16; ++j)
            {
                block[j] ^= prevBlock[j]; // P0 = P0 ^ IV 
            }

            // Mã hoá block
            // Sau khi xor xong ta thuc hien ma hoa luon cai block do
            std::vector<unsigned char> enc = encryptBlock(block); 

            // Ghi kết quả vào ciphertext (bắt đầu từ vị trí 16 + i*16)
            std::copy(enc.begin(), enc.end(), ciphertext.begin() + 16 + i*16);

            prevBlock = enc;
        }
        return ciphertext;
    }

    std::vector<unsigned char> cbc_decrypt(const std::vector<unsigned char> &ciphertext)
    {
        // Kiểm tra độ dài ciphertext
        if(ciphertext.size() < 16 || ciphertext.size() % 16 != 0)
        {
            throw std::runtime_error("Ciphertext length must be a multiple of 16 bytes for CBC mode.");
        }

        // Tách IV từ ciphertext
        std::vector<unsigned char> iv(ciphertext.begin(), ciphertext.begin() + 16);

        // Phần còn lại là dữ liệu mã hoá
        std::vector<unsigned char> data(ciphertext.begin() + 16, ciphertext.end());

        size_t blockCount = data.size() / 16;
        std::vector<unsigned char> decrypted;
        decrypted.resize(data.size());

        std::vector<unsigned char> previousBlock(iv);

        for(size_t i = 0; i < blockCount; ++i)
        {
            // Lấy block mã hoá
            std::vector<unsigned char> block(data.begin() + i*16, data.begin() + (i+1)*16);

            // Giải mã block
            std::vector<unsigned char> dec = decryptBlock(block);

            // XOR với previousBlock
            for(int j = 0; j < 16; ++j)
            {
                dec[j] ^= previousBlock[j];
            }

            // Ghi vào output
            std::copy(dec.begin(), dec.end(), decrypted.begin() + i*16);

            // Cập nhật previousBlock
            previousBlock = block;
        }

        // Gỡ bỏ padding
        decrypted = pkcs7_unpadding(decrypted);
        return decrypted;
    }

private:
    std::vector<unsigned char> key_; // Lưu key gốc
    std::vector<std::vector<unsigned char>> roundKeys_; // Mảng roundKeys

    //===========================================================
    // PKCS#7 padding
    //===========================================================
    std::vector<unsigned char> pkcs7_padding(const std::vector<unsigned char> &data)
    {
        // Tính toán số byte cần padding
        size_t paddingLength = 16 - (data.size() % 16);
        if (paddingLength == 0) paddingLength = 16; // nếu vừa khít, vẫn phải padding thêm 16

        // Tạo 1 vector dữ liệu mới
        std::vector<unsigned char> padded(data);
        padded.resize(data.size() + paddingLength, static_cast<unsigned char>(paddingLength));
        return padded;
    }

    //===========================================================
    // PKCS#7 unpadding
    //===========================================================
    std::vector<unsigned char> pkcs7_unpadding(const std::vector<unsigned char> &data)
    {
        if(data.empty()) 
        {
            throw std::runtime_error("Data is empty. Cannot unpad.");
        }
        unsigned char paddingLength = data.back(); // Byte cuối
        if(paddingLength < 1 || paddingLength > 16)
        {
            throw std::runtime_error("Invalid padding.");
        }
        // Kiểm tra các byte padding
        for(size_t i = data.size() - paddingLength; i < data.size(); ++i)
        {
            if(data[i] != paddingLength)
            {
                throw std::runtime_error("Invalid PKCS#7 padding.");
            }
        }
        // Tạo vector kết quả, bỏ padding
        std::vector<unsigned char> unpadded(data.begin(), data.end() - paddingLength);
        return unpadded;
    }

    //===========================================================
    // Mã hoá 1 block (16 bytes)
    //===========================================================
    std::vector<unsigned char> encryptBlock(const std::vector<unsigned char> &block)
    {
        // Sao chép block đầu vào vào state (4x4)
        std::vector<unsigned char> state(block);

        int Nr = 0; // Số vòng lặp (10 / 12 / 14)
        int Nk = key_.size() / 4; // 4 words = 16 bytes => Nk = 4 (AES-128), 6 (AES-192), 8 (AES-256)
        if(key_.size() == 16) Nr = 10;
        else if(key_.size() == 24) Nr = 12;
        else if(key_.size() == 32) Nr = 14;

        addRoundKey(state, 0);

        for(int round = 1; round < Nr; ++round)
        {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, round);
        }

        // Vòng cuối
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, Nr);

        return state;
    }
    std::vector<unsigned char> decryptBlock(const std::vector<unsigned char> &block)
    {
        std::vector<unsigned char> state(block);

        int Nr = 0;
        if(key_.size() == 16) Nr = 10;
        else if(key_.size() == 24) Nr = 12;
        else if(key_.size() == 32) Nr = 14;

        addRoundKey(state, Nr);

        for(int round = Nr - 1; round >= 1; --round)
        {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, round);
            invMixColumns(state);
        }

        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, 0);

        return state;
    }

    void keyExpansion(const std::vector<unsigned char> &key)
    {
        // Xác định số words
        int Nk = key.size() / 4; // 4 bytes = 1 word
        int Nr = 0;
        if(key.size() == 16)      Nr = 10; // AES-128
        else if(key.size() == 24) Nr = 12; // AES-192
        else if(key.size() == 32) Nr = 14; // AES-256

        // Tổng số từ cần cho tất cả roundKeys
        int Nb = 4;               // AES block size = 4 words
        int totalWords = (Nr + 1) * Nb; // (10+1)*4 = 44 (AES-128)

        // roundKeys_ sẽ là (Nr+1) mảng, mỗi mảng 16 bytes (4 words)
        roundKeys_.resize(Nr + 1, std::vector<unsigned char>(16, 0));

        // Mảng tạm để chứa các word (mỗi word 4 byte)
        std::vector<unsigned char> words(totalWords * 4, 0);

        // Copy key ban đầu vào đầu
        for(int i = 0; i < (int)key.size(); ++i)
        {
            words[i] = key[i];
        }

        // Expand
        int i = Nk;
        std::vector<unsigned char> temp(4);

        while(i < totalWords)
        {
            // copy word trước đó
            for(int j = 0; j < 4; ++j)
            {
                temp[j] = words[(i - 1)*4 + j];
            }

            if(i % Nk == 0)
            {
                // rot_word
                unsigned char t = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = t;
                // sub_word
                for(int j = 0; j < 4; ++j)
                {
                    temp[j] = S_BOX[temp[j]];
                }
                // RCON
                temp[0] = temp[0] ^ RCON[(i/Nk)-1][0];
                temp[1] = temp[1] ^ RCON[(i/Nk)-1][1];
                temp[2] = temp[2] ^ RCON[(i/Nk)-1][2];
                temp[3] = temp[3] ^ RCON[(i/Nk)-1][3];
            }
            else if(Nk > 6 && (i % Nk == 4))
            {
                // sub_word
                for(int j = 0; j < 4; ++j)
                {
                    temp[j] = S_BOX[temp[j]];
                }
            }

            // XOR với word cách Nk word
            for(int j = 0; j < 4; ++j)
            {
                words[i*4 + j] = words[(i - Nk)*4 + j] ^ temp[j];
            }
            i++;
        }

        // Chuyển mảng words => roundKeys_
        // Mỗi roundKey có 16 byte => round = 0..Nr
        for(int round = 0; round <= Nr; ++round)
        {
            for(int col = 0; col < 4; ++col)
            {
                for(int row = 0; row < 4; ++row)
                {
                    roundKeys_[round][col*4 + row] = words[(round*4 + col)*4 + row];
                }
            }
        }
    }

    void addRoundKey(std::vector<unsigned char> &state, int round)
    {
        for(int i = 0; i < 16; ++i)
        {
            state[i] ^= roundKeys_[round][i];
        }
    }
    void subBytes(std::vector<unsigned char> &state)
    {
        for(int i = 0; i < 16; ++i)
        {
            state[i] = S_BOX[state[i]];
        }
    }

    void invSubBytes(std::vector<unsigned char> &state)
    {
        for(int i = 0; i < 16; ++i)
        {
            state[i] = INV_S_BOX[state[i]];
        }
    }

    void shiftRows(std::vector<unsigned char> &state)
    {
        unsigned char t = state[4];
        state[4] = state[5];
        state[5] = state[6];
        state[6] = state[7];
        state[7] = t;

        // Row 2 shift left 2
        unsigned char t1 = state[8];
        unsigned char t2 = state[9];
        state[8] = state[10];
        state[9] = state[11];
        state[10] = t1;
        state[11] = t2;

        // Row 3 shift left 3
        t = state[15];
        state[15] = state[14];
        state[14] = state[13];
        state[13] = state[12];
        state[12] = t;
    }

    void invShiftRows(std::vector<unsigned char> &state)
    {
        unsigned char t = state[7];
        state[7] = state[6];
        state[6] = state[5];
        state[5] = state[4];
        state[4] = t;

        // Row 2 shift right 2
        unsigned char t1 = state[8];
        unsigned char t2 = state[9];
        state[8] = state[10];
        state[9] = state[11];
        state[10] = t1;
        state[11] = t2;

        // Row 3 shift right 3
        t = state[12];
        state[12] = state[13];
        state[13] = state[14];
        state[14] = state[15];
        state[15] = t;
    }

    void mixColumns(std::vector<unsigned char> &state)
    {
        for(int c = 0; c < 4; ++c)
        {
            int idx = c*4;
            unsigned char a0 = state[idx+0];
            unsigned char a1 = state[idx+1];
            unsigned char a2 = state[idx+2];
            unsigned char a3 = state[idx+3];

            state[idx+0] = (unsigned char)(gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3);
            state[idx+1] = (unsigned char)(a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3);
            state[idx+2] = (unsigned char)(a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3));
            state[idx+3] = (unsigned char)(gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2));
        }
    }
    void invMixColumns(std::vector<unsigned char> &state)
    {
        for(int c = 0; c < 4; ++c)
        {
            int idx = c*4;
            unsigned char a0 = state[idx+0];
            unsigned char a1 = state[idx+1];
            unsigned char a2 = state[idx+2];
            unsigned char a3 = state[idx+3];

            state[idx+0] = (unsigned char)(gmul(a0, 0x0e) ^ gmul(a1, 0x0b) ^ gmul(a2, 0x0d) ^ gmul(a3, 0x09));
            state[idx+1] = (unsigned char)(gmul(a0, 0x09) ^ gmul(a1, 0x0e) ^ gmul(a2, 0x0b) ^ gmul(a3, 0x0d));
            state[idx+2] = (unsigned char)(gmul(a0, 0x0d) ^ gmul(a1, 0x09) ^ gmul(a2, 0x0e) ^ gmul(a3, 0x0b));
            state[idx+3] = (unsigned char)(gmul(a0, 0x0b) ^ gmul(a1, 0x0d) ^ gmul(a2, 0x09) ^ gmul(a3, 0x0e));
        }
    }

    unsigned char gmul(unsigned char a, unsigned char b)
    {
        unsigned char p = 0;
        unsigned char hi_bit_set;
        for(int i = 0; i < 8; i++)
        {
            if((b & 1) == 1)
                p ^= a;
            hi_bit_set = (unsigned char)(a & 0x80);
            a <<= 1;
            if(hi_bit_set == 0x80)
                a ^= 0x1b; // x^4 + x^3 + x + 1
            b >>= 1;
        }
        return p;
    }
};
const unsigned char AES::S_BOX[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
const unsigned char AES::INV_S_BOX[256] = {
  0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
  0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
  0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
  0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
  0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
  0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
  0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
  0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
  0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
  0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
  0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
  0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
  0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
  0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
  0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
  0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
};
const unsigned char AES::RCON[10][4] = {
    {0x01, 0x00, 0x00, 0x00},
    {0x02, 0x00, 0x00, 0x00},
    {0x04, 0x00, 0x00, 0x00},
    {0x08, 0x00, 0x00, 0x00},
    {0x10, 0x00, 0x00, 0x00},
    {0x20, 0x00, 0x00, 0x00},
    {0x40, 0x00, 0x00, 0x00},
    {0x80, 0x00, 0x00, 0x00},
    {0x1B, 0x00, 0x00, 0x00},
    {0x36, 0x00, 0x00, 0x00}
};
std::vector<unsigned char> hexStringToBytes(const std::string &hex)
{
    // Mỗi 2 ký tự hex tương ứng 1 byte
    // Nếu độ dài không chẵn, ta có thể xử lý lỗi hoặc tự động thêm '0' ở đầu.
    if (hex.size() % 2 != 0)
    {
        throw std::runtime_error("Hex string length must be even!");
    }

    std::vector<unsigned char> bytes;
    bytes.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2)
    {
        // Lấy 2 ký tự
        std::string byteString = hex.substr(i, 2);
        // Chuyển thành số (base 16)
        unsigned char byteValue = static_cast<unsigned char>(std::stoul(byteString, nullptr, 16));
        bytes.push_back(byteValue);
    }
    return bytes;
}

int main()
{
    try
    {
        // 1) Nhập plaintext
        std::cout << "Enter plaintext: ";
        std::string plainStr;
        std::getline(std::cin, plainStr);

        // 2) Nhập Key 128-bit dưới dạng hex (32 ký tự hex)
        std::cout << "Enter 128-bit key in hex (32 hex characters): ";
        std::string keyHex;
        std::getline(std::cin, keyHex);
        
        // Chuyển keyHex -> mảng 16 byte
        std::vector<unsigned char> key = hexStringToBytes(keyHex);
        if (key.size() != 16) {
            throw std::runtime_error("Key must be 16 bytes for AES-128!");
        }

        // 3) Nhập IV 128-bit dưới dạng hex (32 ký tự hex)
        std::cout << "Enter 128-bit IV in hex (32 hex characters): ";
        std::string ivHex;
        std::getline(std::cin, ivHex);

        // Chuyển ivHex -> mảng 16 byte
        std::vector<unsigned char> iv = hexStringToBytes(ivHex);
        if (iv.size() != 16) {
            throw std::runtime_error("IV must be 16 bytes (128-bit)!");
        }

        // 4) Chuyển plaintext sang vector unsigned char
        std::vector<unsigned char> plaintext(plainStr.begin(), plainStr.end());

        // 5) Khởi tạo AES và mã hoá CBC
        AES aes(key);
        auto cipher = aes.cbc_encrypt(plaintext, iv);

        // In ra ciphertext dưới dạng hex
        std::cout << "Ciphertext (hex) = ";
        for (auto c : cipher) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(c);
        }
        std::cout << std::dec << std::endl;

        // 6) Giải mã lại để kiểm tra
        auto decrypted = aes.cbc_decrypt(cipher);
        std::string recovered(decrypted.begin(), decrypted.end());
        std::cout << "Recovered plaintext = " << recovered << std::endl;
    }
    catch(const std::exception &ex)
    {
        std::cerr << "Error: " << ex.what() << std::endl;
    }
    return 0;
}
