#include <iostream>
#include <string>
#include <sstream>

#include "crypt.h"
#include "split_recover.h"

std::string recover_mode = "recover";
std::string split_mode = "split";
std::string empty_token = "empty";
std::string new_point_token = "|";

std::string program_mode;

int main(int argc, char *argv[]) {
    if (argc != 2) {  // console params
        std::cout << "wrong count of params" << std::endl;
        return 1;
    }
    program_mode = argv[1];

    if ((program_mode != "split") && (program_mode != "recover")) {
        std::cout << "wrong mode" << std::endl;
        return 1;
    }


    EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);  // generation key for example
    const BIGNUM *private_key = create_Secp256k1_private_key(key);
    BIO *outbio;  // output key
    outbio = BIO_new_fp(stdout, BIO_NOCLOSE);
    BN_print(outbio, private_key);
    std::cout << std::endl;

    uint32_t n = 0;
    uint32_t t = 0;

    if (program_mode == split_mode) {  // split
        std::string p_key;
        std::cout << "Enter private key:" << std::endl;
        std::getline(std::cin, p_key);

        BIGNUM *bn = NULL;
        BN_hex2bn(&bn, p_key.c_str());
        char *p_key_bn = BN_bn2dec(bn);

        std::cout << "Enter 'n' and 't' for spliting:" << std::endl;
        std::cin >> n >> t;
        if ((t <= 2) || (t > n) || (n >= 100)) {
            std::cout << "wrong input values" << std::endl;
            return 1;
        }

        std::vector<Share> shares = split(p_key_bn, n, t);

        for (auto& it : shares) {
            std::cout << it.x << " " << it.y << " | ";
        }

        EC_KEY_free(key);
        return 0;
    }

    if (program_mode == recover_mode) {  // recover
        std::string p_key;
        std::cout << "Enter 't' or more string for recovering:" << std::endl;
        std::getline(std::cin, p_key);
        std::string word;

        std::stringstream iss(p_key);

        std::vector<Share> shares;
        int x = 0;
        std::string y = empty_token;

        while (iss >> word) {
            if (word == new_point_token) {
                continue;
            }
            if (word.size() < 3) {
                x = std::stoi(word);
                std::cout << x << std::endl;
            } else {
                y = word;
            }
            if ((x != 0) && (y != empty_token)) {
                shares.push_back({y, x});
                x = 0;
                y = empty_token;
            }
        }

        std::string recover_private_key = recover(n, shares);
        std::cout << recover_private_key << std::endl;
        EC_KEY_free(key);
        return 0;
    }
    EC_KEY_free(key);
    return 0;
}
