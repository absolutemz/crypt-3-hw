#pragma once

#include <iostream>
#include <openssl/pem.h>

const BIGNUM* create_Secp256k1_private_key(EC_KEY* key);  // private key generation