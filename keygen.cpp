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

std::vector<bool> randomExpandedOdd (int bits) {
    std::vector<bool> digits(bits, 0);
    digits[0] = digits[bits-1] = 1;
    for (int i=1; i < bits-2; i++)
        digits[i] = rand() % 2;
    return digits;
}

int main () {
    srand(time(NULL));
    std::vector<bool> digits = randomExpandedOdd(16);
    for (auto digit: digits)
        std::cout << digit;
    std::bitset<16> value(bitsListToInt(digits));
    std::cout << std::endl << value;
    return 0;
}