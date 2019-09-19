#include "base58.hpp"
#include <assert.h>

// returns true if addr is a valid elastos address
bool is_valid_address(const char *addr) {
    uint8_t data[42];
    assert(addr != NULL);
    return Base58CheckDecode(data, sizeof(data), addr) == 21;
}
