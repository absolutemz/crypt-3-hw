#include <iostream>
#include <cmath>

#include <openssl/bn.h>

#include "split_recover.h"

std::string polynom(int x, std::vector<std::string> coefs) {
    std::string result_str;
    BIGNUM *sumbn = NULL;
    BN_dec2bn(&sumbn, "0");
    for (size_t i = 0; i < coefs.size(); ++i) {

        BIGNUM *bn1 = NULL;
        BIGNUM *bn2 = NULL;

        BN_CTX *ctx = BN_CTX_new();

        BN_dec2bn(&bn1, coefs[i].c_str());
        BN_dec2bn(&bn2, (std::to_string(pow(x, i))).c_str());

        BN_mul(bn1, bn1, bn2, ctx);

        BN_add(sumbn, sumbn, bn1);

        BN_free(bn1);
        BN_free(bn2);
        BN_CTX_free(ctx);
    }
    result_str = BN_bn2hex(sumbn);
    BN_free(sumbn);
    return result_str;
}

std::vector<Share> split(char *secret, uint32_t n, uint32_t t) {
    srand ( time(NULL) );

    std::vector<Share> shares;
    std::vector<std::string> coefs;

    coefs.push_back(secret);

    for (auto i = 1; i < t; i++) {
        int coef = (std::rand() % 1000) - 500;
        coefs.push_back(std::to_string(coef));
    }

    for (auto i = 0; i < n; i++)
        shares.push_back({ polynom(i + 1, coefs), i + 1});
    return shares;
}

std::string recover(int n, std::vector<Share> const & shares) {
    BIGNUM *recover_result = NULL;
    BN_dec2bn(&recover_result, "0");

    auto l = [shares](int64_t i) -> double {
        double res = 1.;
        for (auto j = 0; j < shares.size(); j++)
            if (i != shares[j].x)
                res *= (double)shares[j].x / ((double)shares[j].x - (double)i);
        return res;
    };

    for (auto i = 0; i < shares.size(); i++) {
        BIGNUM *bn1 = NULL;
        BIGNUM *bn2 = NULL;

        BN_CTX *ctx = BN_CTX_new();

        BN_hex2bn(&bn1, shares[i].y.c_str());

        BN_dec2bn(&bn2, std::to_string(l(shares[i].x)).c_str());

        BN_mul(bn1, bn1, bn2, ctx);

        BN_add(recover_result, recover_result, bn1);

        BN_free(bn1);
        BN_free(bn2);
        BN_CTX_free(ctx);
    }

    std::string recover_result_str = BN_bn2hex(recover_result);
    BN_free(recover_result);
    return recover_result_str;
}
