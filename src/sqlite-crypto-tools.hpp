#include <fstream>
#include <cstdlib>
#include <string>
#include <vector>

#define AES256 1

#include "aes.hpp"

#if AES_KEYLEN != 32
    #error "#define AES256 1" is missing
#endif

void read_hex(uint8_t* dest, int size, std::string str)
{
    for (int i = 0, p = 0; i < size; i++, p += 2) {
        dest[i] = strtol(str.substr(p, 2).c_str(), NULL, 16);
    }
}

std::vector<const std::string> args(int argc, char *argv[])
{
    std::vector<const std::string> args;
    args.reserve(argc);
    for (int i = 0; i < argc; i++) {
        args.push_back(argv[i]);
    }
    return args;
}

int run(std::vector<const std::string> args, void (*crypto)(struct AES_ctx* ctx, uint8_t* buf), std::string output_message)
{
    const std::string input = args.at(1);
    const std::string output = args.at(2);
    const std::string key_str = args.at(3);
    
    if (key_str.length() != 64) {
        std::cerr << "Argument <key> must have 32 bytes (64 hexadecimal characters). For example: 43616E20796F75206B6565702061207365637265743F205B595D65732F6E6F3F" << std::endl;
        return EXIT_FAILURE;
    }
    
    uint8_t key[32];
    read_hex(key, 32, key_str);
    
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    
    std::ofstream ofs(output, std::ofstream::binary);
    std::ifstream ifs(input, std::ifstream::binary);
    const size_t buffer_size = AES_BLOCKLEN;
    char buffer[buffer_size];
    while (ifs.read(buffer, buffer_size)) {
        crypto(&ctx, (uint8_t*) buffer);
        ofs.write(buffer, buffer_size);
    }
    ifs.close();
    ofs.close();
    
    std::cout << output_message << output << std::endl;
    
    return EXIT_SUCCESS;
}
