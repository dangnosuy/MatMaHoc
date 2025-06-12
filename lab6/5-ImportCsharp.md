### 2. RSA Encryption

Perform RSA encryption using a public key with Crypto++.

This function reads a public key from a specified file, detects its format (either PEM or DER), and uses it to encrypt an input file. The encrypted data is then saved to an output file. This functionality provides a practical example of asymmetric encryption.

### RSA Encryption Class

Command-Line Class for RSA Encryption: A reusable class for encrypting files using RSA public keys from the command line, with options for specifying key format, input, and output files.

#### Code Example:
```cpp
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/base64.h>
#include <cryptopp/queue.h>
#include <cryptopp/cryptlib.h>
#include <iostream>
#include <fstream>
#include <string>

using namespace CryptoPP;

class RSAEncryptor {
public:
    static void Encrypt(const std::string& pubKeyFile, const std::string& fileInput, const std::string& cipherFileOutput) {
        try {
            // Load public key from file
            RSA::PublicKey publicKey;
            if (IsPEMFormat(pubKeyFile)) {
                // Load PEM public key
                LoadPEMPublicKey(pubKeyFile, publicKey);
            } else {
                // Assume DER format
                FileSource file(pubKeyFile.c_str(), true);
                publicKey.Load(file);
            }

            AutoSeededRandomPool rng;

            // Perform RSA encryption
            RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
            FileSource(fileInput.c_str(), true, 
                new PK_EncryptorFilter(rng, encryptor, 
                new FileSink(cipherFileOutput.c_str())));
        } catch (const CryptoPP::Exception& e) {
            std::cerr << "Crypto++ Error: " << e.what() << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
        }
    }

private:
    // Function to detect if the key file is in PEM format
    static bool IsPEMFormat(const std::string& fileName) {
        std::ifstream file(fileName);
        std::string line;
        if (file.is_open()) {
            std::getline(file, line);
            file.close();
            return line.find("-----BEGIN PUBLIC KEY-----") != std::string::npos;
        }
        return false;
    }

    // Function to load a PEM-encoded key
    static void LoadPEMPublicKey(const std::string& fileName, RSA::PublicKey& publicKey) {
        try {
            FileSource file(fileName.c_str(), true);
            PEM_Load(file, publicKey);
        } catch (const CryptoPP::Exception& e) {
            throw std::runtime_error("Failed to load PEM public key: " + std::string(e.what()));
        }
    }

    static void PEM_Load(FileSource& source, RSA::PublicKey& publicKey) {
        ByteQueue queue;
        Base64Decoder decoder(new Redirector(queue));
        source.Pump(26); // Skip the header line
        source.TransferTo(decoder);
        decoder.MessageEnd();
        publicKey.BERDecode(queue);
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <pubKeyFile> <fileInput> <cipherFileOutput>" << std::endl;
        return 1;
    }

    std::string pubKeyFile = argv[1];
    std::string fileInput = argv[2];
    std::string cipherFileOutput = argv[3];

    RSAEncryptor::Encrypt(pubKeyFile, fileInput, cipherFileOutput);

    return 0;
}
```

### Explanation

The `RSAEncryptor` class provides a simple interface to encrypt data using RSA with a specified public key. It can read both PEM and DER formats, enabling compatibility with different key storage methods. The key format is automatically detected by examining the file content.

- **Detecting Key Format**: The function `IsPEMFormat` checks if the public key file contains the PEM header (`-----BEGIN PUBLIC KEY-----`). If found, it loads the key as a PEM key; otherwise, it defaults to DER format.
- **PEM Key Handling**: The `LoadPEMPublicKey` function reads the PEM-encoded public key and loads it into the `RSA::PublicKey` object.
- **Encryption**: The `Encrypt` function uses the RSAES_OAEP_SHA_Encryptor to encrypt the input data and save it to the output file.

### Usage Instructions
- Use the following command to compile the program:
  ```sh
  g++ -g2 -O3 -Wall -I /path/to/cryptopp/include RSAEncryption.cpp -L /path/to/cryptopp/lib -lcryptopp -o RSAEncryption
  ```
- **Command to Encrypt**:
  ```sh
  ./RSAEncryption <public_key_file> <input_file> <cipher_output_file>
  ```

### Importing RSAKeyGen DLL/SO into Python

To use the RSAKeyGen shared library (DLL/SO) in Python, you can use the `ctypes` library to load the compiled shared object and call its functions.

#### Python Code Example:
```python
import ctypes
import os

# Load the RSAKeyGen shared library
if os.name == "nt":
    rsa_lib = ctypes.CDLL("./RSAKeygen.dll")
else:
    rsa_lib = ctypes.CDLL("./RSAKeygen.so")

# Define the argument types for the Generate function
rsa_lib.Generate.argtypes = [
    ctypes.c_int,              # key size
    ctypes.c_char_p,           # format (PEM or DER)
    ctypes.c_char_p,           # output public key file
    ctypes.c_char_p            # output private key file
]

# Define the function to generate RSA keys from Python
def generate_rsa_keys(size, format, output_pub, output_priv):
    rsa_lib.Generate(
        size,
        format.encode('utf-8'),
        output_pub.encode('utf-8'),
        output_priv.encode('utf-8')
    )

# Example usage
generate_rsa_keys(2048, "PEM", "public_key.pem", "private_key.pem")
```

### Importing RSAKeyGen DLL/SO into C#

To use the RSAKeyGen shared library (DLL/SO) in C#, you can use the `DllImport` attribute to load the compiled shared object and call its functions.

#### C# Code Example:
```csharp
using System;
using System.Runtime.InteropServices;

class Program
{
    // Import the RSAKeyGen shared library
    [DllImport("RSAKeygen.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void Generate(int size, string format, string outputFilePub, string outputFilePrivate);

    static void Main(string[] args)
    {
        if (args.Length != 4)
        {
            Console.WriteLine("Usage: <key_size> <format (PEM or DER)> <output_public_key_file> <output_private_key_file>");
            return;
        }

        int size = int.Parse(args[0]);
        string format = args[1];
        string outputFilePub = args[2];
        string outputFilePrivate = args[3];

        try
        {
            Generate(size, format, outputFilePub, outputFilePrivate);
            Console.WriteLine("RSA keys generated successfully.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }
}
```

### Example OpenSSL Commands to Verify the Key
To verify the public key format:
```sh
openssl rsa -inform PEM -in public_key.pem -pubin -text -noout
```
To verify encryption, use the corresponding decryption with the private key.

