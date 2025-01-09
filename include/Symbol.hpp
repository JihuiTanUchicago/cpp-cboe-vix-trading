#pragma once

#include <cstdint>
#include <cstring>
#include <functional>

struct Symbol
{
    Symbol(uint8_t* symb)
    {
        std::memcpy(symbol, symb, 6);
    }
    Symbol(const char* symb)
    {
        std::memcpy(symbol, symb, 6);
    }
    bool operator==(const Symbol& other) const 
    {
        // Check that the two byte arrays are equal
        return std::memcmp(symbol, other.symbol, 6) == 0;
    }

    uint8_t symbol[6];
};

// Specialize std::hash for Symbol
namespace std 
{
    template <>
    struct hash<Symbol> 
    {
        std::size_t operator()(const Symbol& symb) const 
        {
            std::size_t hash = 0;
            // Could make even faster since first 3 char are 0 ?
            for (int i = 0; i < 6; ++i) 
            {
                hash += symb.symbol[i] << i;
            }
            return hash;
        }
    };
}
