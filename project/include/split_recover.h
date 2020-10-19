#pragma once

#include <vector>
#include <openssl/bn.h>

struct Share {  // struct for points
    std::string y;
    int x;
};

std::vector<Share> split(char *secret, uint32_t n, uint32_t t);  // spliting private key

std::string recover(int n, std::vector<Share> const & shares);  // recover private key
