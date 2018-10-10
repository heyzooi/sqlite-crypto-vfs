#include <iostream>
#include "sqlite-crypto-tools.hpp"

int main (int argc, char *argv[])
{
    if (argc != 4) {
        std::cerr << "Usage:" << std::endl;
        std::cerr << argv[0] << " <encrypted input file> <unencrypted output file> <key>" << std::endl;
        return EXIT_FAILURE;
    }
    
    return run(argv, AES_ECB_decrypt, "Decrypted file: ");
}
