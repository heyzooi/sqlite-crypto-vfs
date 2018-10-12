#include <iostream>
#include "sqlite-crypto-tools.hpp"

int main (int argc, char *argv[])
{
    if (argc != 4) {
        std::cerr << "Usage:" << std::endl;
        std::cerr << argv[0] << " <uncrypted input file> <encrypted output file> <key>" << std::endl;
        return EXIT_FAILURE;
    }
    
    return run(args(argc, argv), AES_ECB_encrypt, "Encrypted file: ");
}
