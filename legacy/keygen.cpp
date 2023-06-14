#include <iostream>
#include <cstdlib>
#include <vector>
#include <bitset>

int bitsListToInt (std::vector<bool> digits) {
    int value = 0;
    int position = 0;
    while (position < digits.size())
        value |= (digits[position] << (digits.size() - (++position)));
    return value;
}

int randomOddBits (int bits) {
    std::vector<bool> digits(bits, 0);
    digits[0] = digits[bits-1] = 1;
    for (int i=1; i < bits-2; i++)
        digits[i] = rand() % 2;
    return bitsListToInt(digits);
}

int main () {
    srand(time(NULL));
    std::bitset<16> value(randomOddBits(16));
    std::cout << value;
    return 0;
}