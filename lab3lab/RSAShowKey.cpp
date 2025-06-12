#include "cryptopp/osrng.h"
#include "cryptopp/rsa.h"
#include "cryptopp/base64.h"
#include "cryptopp/hex.h"
#include "cryptopp/files.h"
#include "cryptopp/cryptlib.h"
#include <iostream>

using namespace CryptoPP;

int main() {


    // Load the private key
    RSA::PrivateKey loadedPrivateKey;
    FileSource privFileIn("private.key", true);
    loadedPrivateKey.BERDecode(privFileIn);

    // Load the public key
    RSA::PublicKey loadedPublicKey;
    FileSource pubFileIn("public.key", true);
    loadedPublicKey.BERDecode(pubFileIn);

    std::cout << "RSA keys loaded successfully." << std::endl;

    // Extract and print RSA parameters
    Integer modul = loadedPrivateKey.GetModulus();       // n
    Integer prime1 = loadedPrivateKey.GetPrime1();       // p
    Integer prime2 = loadedPrivateKey.GetPrime2();       // q
    Integer SK = loadedPrivateKey.GetPrivateExponent();  // d
    Integer PK = loadedPublicKey.GetPublicExponent();    // e

    std::cout << "Modulus (n): " << modul << std::endl;
    std::cout << "Prime1 (p): " << prime1 << std::endl;
    std::cout << "Prime2 (q): " << prime2 << std::endl;
    std::cout << "Private Exponent (d): " << SK << std::endl;
    std::cout << "Public Exponent (e): " << PK << std::endl;

    return 0;
}
