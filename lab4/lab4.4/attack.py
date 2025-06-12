from Crypto.Hash import SHA256
import struct
import sys

def sha256_pad(msg_len):
    pad = b'\x80' # padding 0x80 vào ngay sau đó
    pad += b'\x00' * ((56 - (msg_len + 1) % 64) % 64) # padding 0x00 cho đến khi nó đến được 56 byte
    pad += struct.pack('>Q', msg_len * 8) # padding 8 byte cuối dựa vào độ dài
    return pad

def sha256_state_from_hash(h): # Khởi tạo lại SHA256 từ hash, trả về mảng các mã hex
    return [int(h[i:i+8], 16) for i in range(0, 64, 8)]

def length_extension_attack(original_hash, original_msg, key_len, extension):
    # Tổng độ dài giả định key || message
    total_len = key_len + len(original_msg)

    # Tính padding cho key || message
    padding = sha256_pad(total_len)

    # Tạo forged message gửi tới server
    forged_msg = original_msg + padding + extension

    # Lấy internal state từ hash gốc
    h = sha256_state_from_hash(original_hash)
    print("h: ", h)
    # Tạo SHA256 object từ trạng thái đó, tức là hash tiếp sau khi update extension??
    sha = SHA256.new()
    sha._h = tuple(h) # cập nhật các đoạn hash trước vào đây để tiếp tục hash cho phần sau
    sha._count = (total_len + len(padding)) * 8  # số bit đã hash, tức là đã hash xong đoạn đầ tiên key || original_msg || padding
    sha.update(extension) # chỉ việc hash tiếp phần extension, đúng logic của thuật toán SHA256
    forged_hash = sha.hexdigest()

    return forged_msg, forged_hash
def main():
    if len(sys.argv) != 5:
        print(f"Usage: {sys.argv[0]} <original_hash> <original_msg> <key_len> <extension>")
        return

    original_hash = sys.argv[1]
    original_msg = sys.argv[2].encode()
    key_len = int(sys.argv[3])
    extension = sys.argv[4].encode()

    forged_msg, forged_hash = length_extension_attack(original_hash, original_msg, key_len, extension)

    print(f"Forged message (ASCII): {forged_msg}")
    print(f"Forged message (hex): {forged_msg.hex()}")
    print(f"Forged hash: {forged_hash}")
if __name__ == "__main__":
    main()
