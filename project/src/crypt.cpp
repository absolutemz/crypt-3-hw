#include <iostream>

#include <openssl/ec.h>

#include "crypt.h"

const BIGNUM* create_Secp256k1_private_key(EC_KEY* key) {
    if (!key) {
        std::cerr << "Error creating curve key" << '\n';
        return nullptr;
    }

    if (!EC_KEY_generate_key(key)) {
        std::cerr << "Error generating curve key" << '\n';
        EC_KEY_free(key);
        return nullptr;
    }

    BIGNUM const* prv = EC_KEY_get0_private_key(key);
    if (!prv) {
        std::cerr << "Error getting private key" << '\n';
        EC_KEY_free(key);
        return nullptr;
    }

    std::cout << "Private key: " << prv << '\n';

    return prv;
}

