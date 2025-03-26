#include <iostream>
#include <cstdint>
#include <array>
#include <vector>
#include <iomanip>
#include <string>
#include <cstddef> 
#include <cstring> 

using namespace std;
using myByte = uint8_t;
using word = uint32_t;

string key = "2b7e151628aed2a6abf7158809cf4f3c";
string iv = "000102030405060708090a0b0c0d0e0f";
myByte* iv_myByte = nullptr;
myByte* key_myByte = nullptr;

const myByte sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};
const myByte columnTable[4][4] = {
    {0x02, 0x03, 0x01, 0x01},
    {0x01, 0x02, 0x03, 0x01},
    {0x01, 0x01, 0x02, 0x03},
    {0x03, 0x01, 0x01, 0x02}
};
const word Rcon[11] = {
    0x00000000, // Không sử dụng
    0x01000000,
    0x02000000,
    0x04000000,
    0x08000000,
    0x10000000,
    0x20000000,
    0x40000000,
    0x80000000,
    0x1B000000,
    0x36000000
};

void hexStringToBytes(const string& hexStr, myByte* output) {
    for (size_t i = 0; i < hexStr.length(); i += 2) {
        string byteString = hexStr.substr(i, 2);
        output[i/2] = static_cast<myByte>(stoi(byteString, nullptr, 16));
    }
}

word RotWord(word w) {
    return (w << 8) | (w >> 24);
}

word SubWord(word w) {
    word result = 0;
    for (int i = 0; i < 4; i++) {
        myByte byteVal = (w >> (24 - i * 8)) & 0xFF;
        myByte subByteVal = sbox[byteVal];
        result |= (static_cast<word>(subByteVal) << (24 - i * 8));
    }
    return result;
}

void KeyExpansion(const myByte key[16], word expandedKey[44]) {
    // Khởi tạo 4 từ đầu từ khóa chính
    for (int i = 0; i < 4; i++) {
        expandedKey[i] = (static_cast<word>(key[4*i]) << 24) |
                         (static_cast<word>(key[4*i+1]) << 16) |
                         (static_cast<word>(key[4*i+2]) << 8) |
                         (static_cast<word>(key[4*i+3]));
    }
    
    // Tính các từ còn lại
    for (int i = 4; i < 44; i++) {
        word temp = expandedKey[i - 1];
        if (i % 4 == 0) {
            temp = SubWord(RotWord(temp)) ^ Rcon[i / 4];
        }
        expandedKey[i] = expandedKey[i - 4] ^ temp;
    }
}   
// tach ra 4 byte mot lan xong sau do mixcolumn voi bang
int hexCharToDecimal(char c) {
    if(c >= '0' && c <= '9')
        return c - '0';
    else if(c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    else if(c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return 0; // Nếu không hợp lệ
}

myByte SubByte(myByte input) {
    stringstream ss;
    ss << hex << setw(2) << setfill('0') << static_cast<int>(input);
    string hexStr = ss.str();

    int highNibble = hexCharToDecimal(hexStr[0]);
    int lowNibble = hexCharToDecimal(hexStr[1]);

    int index = highNibble * 16 + lowNibble;
    return sbox[index];
}

myByte hexStringTomyByte(string hexStr) { // chi string 2 myByte
    unsigned int value = 0;
    stringstream ss;
    ss << hex << hexStr;
    ss >> value;

    return static_cast<myByte> (value);
}

myByte* pkcs7_pad(string data, int &dataLength) {
    size_t blockSize = 16;
    size_t dataLen = data.length();
    size_t paddLength = blockSize - (data.length() % blockSize);
    if (paddLength == 0) {
        paddLength = 16;
    }
    size_t newLength = dataLen + paddLength;
    dataLength = newLength;
    myByte* paddingData = new myByte [newLength];

    for (size_t i = 0; i < data.length(); i++) {
        paddingData[i] = static_cast<myByte> (data[i]);
    }
    for (size_t i = dataLen; i < newLength; i++) {
        paddingData[i] = static_cast<myByte> (paddLength);
    }
    return paddingData;
}
string StringtoHex(const string& data) {
    stringstream ss;
    for (unsigned char c : data) {
        ss << hex << setw(2) << setfill('0') << static_cast<int>(c);
    }
    return ss.str();
}
string ByteToHexToString(const myByte* data, size_t length) {
    stringstream ss;
    // Đặt chế độ hiển thị ở dạng hex, đảm bảo mỗi byte có 2 chữ số (đệm số 0 nếu cần)
    for (size_t i = 0; i < length; i++) {
        ss << hex << setw(2) << setfill('0') << static_cast<int>(data[i]);
    }
    return ss.str();
}

myByte* XOR_16Bytes(myByte* s1, myByte* s2) {
    myByte* result = new myByte [16];
    for (size_t i = 0; i < 16; i++) {
        result[i] = s1[i] ^ s2[i];
    }
    return result;
}

myByte* CombineWithIV(string plaintext, int &data_length) {
    int dataLength = 0;
    myByte* paddedPlaintext = pkcs7_pad(plaintext, dataLength);
    myByte* result = new myByte [dataLength];
    data_length = dataLength;
    myByte* block_truoc = new myByte [16];
    myByte* block_sau = XOR_16Bytes(block_truoc, iv_myByte); // C0 = P0 ^ IV
    memcpy(result, block_sau, 16);
    delete [] block_truoc;

    block_truoc = new myByte[16]; // Cấp phát lại block_truoc cho các lần sử dụng sau này
    for (size_t i = 16; i < dataLength; i+=16) {
        memcpy(block_truoc, paddedPlaintext + i, 16);
        myByte* new_block = XOR_16Bytes(block_sau, block_truoc);
        delete[] block_sau;  // Giải phóng block_sau cũ
        block_sau = new_block; // Cập nhật block_sau mới
        memcpy(result + i, block_sau, 16);
    }
    delete [] block_sau;
    delete [] block_truoc;
    delete [] paddedPlaintext;
    return result;
}


void SubBytesAllData(myByte* &data, int data_length) {
    for (size_t i = 0; i < data_length; i++) {
        data[i] = SubByte(data[i]);
    }
}
void ShiftRows(myByte* data) {
    myByte tmp = data[4] ;
    data[4] = data[5]; 
    data[5] = data[6];
    data[6] = data[7];
    data[7] = tmp; 
    // 8 9 10 11 -> 10 11 8 9
    tmp = data[8];
    data[8] = data[10];
    data[10] = tmp;
    tmp = data[9];
    data[9] = data[11];
    data[11] = tmp;

    tmp = data[12];
    data[12] = data[15];
    data[15] = data[14];
    data[14] = data[13];
    data[13] = tmp;
}

void ShiftAllRows(myByte* &data, int data_length) {
    myByte* tmp = new myByte[16];

    for (int i = 0; i < data_length; i += 16) {
        memcpy(tmp, data + i, 16);
        ShiftRows(tmp);
        memcpy(data + i, tmp, 16);
    }
    delete [] tmp;
}

myByte xtime(myByte x) {
    return (x << 1) ^ ((x & 0x80) ? 0x1B : 0x00);
}
myByte multiply(myByte a, myByte b) {
    switch(b) {
        case 0x01: return a;
        case 0x02: return xtime(a);
        case 0x03: return xtime(a) ^ a;
        default: return 0; // hoặc xử lý thêm nếu cần
    }
}

myByte* Mix_4Bytes_Column(myByte* data) {
    myByte* result = new myByte[4];
    // Sử dụng ma trận mixColumn như trên
    for (int row = 0; row < 4; row++) {
        myByte sum = 0;
        for (int k = 0; k < 4; k++) {
            sum ^= multiply(data[k], columnTable[row][k]);
        }
        result[row] = sum;
    }
    return result;
}
void MixColumn(myByte* &data, int data_length) {
    for (size_t i = 0; i < data_length; i += 4) {
        myByte* tmpIn = new myByte[4];
        memcpy(tmpIn, data + i, 4);
        myByte* tmpOut = Mix_4Bytes_Column(tmpIn);
        memcpy(data + i, tmpOut, 4);
        delete[] tmpIn;
        delete[] tmpOut;
    }
}
void AddRoundKey(myByte* data, size_t data_length, myByte* key) {
    key = key_myByte;
    size_t k = 0;
    for (size_t i = 0; i < data_length; i++) {
        data[i] ^= key[k++];
        if (k == 16) 
            k = 0;
    }
}

void AES_Encrypt(myByte* &data, int data_length, myByte roundKeys[][16], int numRounds) {

    AddRoundKey(data, 16, roundKeys[0]);

    for (int i = 1; i < numRounds; i++) {
        SubBytesAllData(data, data_length);

        ShiftAllRows(data, data_length);
        if (i < numRounds - 1) {
            MixColumn(data, data_length);
        }
        AddRoundKey(data, data_length, roundKeys[i]);
    }
}
int main()
{
    iv_myByte = new myByte[16];
    key_myByte = new myByte[16];
    hexStringToBytes(key, key_myByte);
    hexStringToBytes(iv, iv_myByte);

    word expandedKey[44];
    KeyExpansion(key_myByte, expandedKey);
    
    // Nếu cần, bạn có thể chuyển expandedKey thành một mảng 2 chiều:
    myByte roundKeys[11][16];
    for (int r = 0; r < 11; r++) {
        for (int i = 0; i < 4; i++) {
            word w = expandedKey[r * 4 + i];
            roundKeys[r][i * 4]     = (w >> 24) & 0xFF;
            roundKeys[r][i * 4 + 1] = (w >> 16) & 0xFF;
            roundKeys[r][i * 4 + 2] = (w >> 8) & 0xFF;
            roundKeys[r][i * 4 + 3] = w & 0xFF;
        }
    }
    string plaintext;
    
    cout << "Enter to plaintext: ";

    getline(cin, plaintext);
    int data_length = 0;
    myByte* plaintext_byte = CombineWithIV(plaintext, data_length);
    AES_Encrypt(plaintext_byte, data_length, roundKeys, 11);
    cout << "Decrypt (hex): " << ByteToHexToString(plaintext_byte, data_length) << endl;

    delete[] iv_myByte;
    delete[] key_myByte;
    return 0;
}