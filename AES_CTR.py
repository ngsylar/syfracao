import math
import secrets
import conversions as cvt
import modarith as gf

__sBox = [
    [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
    [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
    [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
    [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
    [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
    [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
    [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
    [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
    [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
    [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
    [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
    [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
    [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
    [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
    [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
    [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]]

__roundCon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

__ivByteCount = 12

# string message, bytearray mainKey
def Decipher (cipher, mainKey):
    cipherText = cvt.str_to_bytearray(cipher)
    iv = cipherText[0:__ivByteCount]

    cipherText = cipherText[__ivByteCount:]
    cipherTextSize = len(cipherText)
    blockCount = math.ceil(cipherTextSize / 16)

    message = str()
    for counter in range(1, blockCount+1):
        nonce = GetNonce(cvt.bytearray_to_int(iv), counter)
        blockKey = CipherBlock(nonce, mainKey)

        cipherTextBlock = TextBlock(cipherTextSize, cipherText, counter)
        message += cvt.bytearray_to_str(XorBlock(cipherTextBlock, blockKey))

    return message

# string message
def Cipher (message, mainKey):
    iv = bytearray(secrets.token_bytes(__ivByteCount))

    plainText = cvt.str_to_bytearray(message)
    plainTextSize = len(plainText)
    blockCount = math.ceil(plainTextSize / 16)

    ivInt = cvt.bytearray_to_int(iv)
    blockKey_0 = CipherBlock(GetNonce(ivInt, 0), mainKey)

    cipher = str()
    for counter in range(1, blockCount+1):
        nonce = GetNonce(ivInt, counter)
        blockKey = CipherBlock(nonce, mainKey)

        plainTextBlock = TextBlock(plainTextSize, plainText, counter)
        cipher += cvt.bytearray_to_str(XorBlock(plainTextBlock, blockKey))
    
    cipherText = cvt.str_to_bytearray(cipher)
    hashkey = CipherBlock(bytearray(16), mainKey)
    # authBlock = 

    ivStr = cvt.bytearray_to_str(iv)
    iv_cipher = ivStr + cipher
    return iv_cipher

# int textSize, bytearray text, int counter
def TextBlock (textSize, text, counter):
    blockBegin = (counter - 1) * 16
    likelySize = blockBegin + 16
    blockEnd = likelySize if (likelySize < textSize) else textSize
    textBlock = text[blockBegin:blockEnd]
    return textBlock

# int iv, int counter
def GetNonce (iv, counter) :
    nonce = (iv << (16 - __ivByteCount)) | counter
    return cvt.int_to_bytearray(nonce, 16)

# bytearray mainKey, list<bytearray> roundKey
def KeyExpansion (mainKey, roundKeys):
    roundKeys[0] = AddRoundKey(0, mainKey)
    for i in range(1, 10):
        roundKeys[i] = AddRoundKey(i, roundKeys[i-1])

# int round, bytearray prevKey
def AddRoundKey (round, prevKey):
    rotWord = [prevKey[7], prevKey[11], prevKey[15], prevKey[3]]
    subBytes = SubBytes(rotWord)
    roundKey = bytearray(16)

    roundKey[0] = prevKey[0] ^ subBytes[0] ^ __roundCon[round]
    for i in range(1, 4):
        roundKey[i<<2] = prevKey[i<<2] ^ subBytes[i]
    for j in range(1, 4):
        for i in range(j, 16, 4):
            roundKey[i] = prevKey[i] ^ roundKey[i-1]

    return roundKey

# bytearray nonce, bytearray mainKey
def CipherBlock (nonce, mainKey):
    state = bytearray(16)
    for i in range(16):
        state[i] = mainKey[i] ^ nonce[i]

    roundKeys = list()
    for i in range(10):
        roundKeys.append(bytearray(16))
    KeyExpansion(mainKey, roundKeys)

    for i in range(9):
        state = MixCols(ShiftRows(SubBytes(state)))
        for j in range(16):
            state[j] ^= roundKeys[i][j]

    state = ShiftRows(SubBytes(state))
    for j in range(16):
        state[j] ^= roundKeys[9][j]

    return state

# bytearray state
def SubBytes (state):
    for i in range(len(state)):
        row = state[i] >> 4
        col = state[i] & 0x0f
        state[i] = __sBox[row][col]
    return state

# bytearray state
def ShiftRows (state):
    state = [
        state[0], state[1], state[2], state[3],
        state[5], state[6], state[7], state[4],
        state[10], state[11], state[8], state[9],
        state[15], state[12], state[13], state[14]]
    return state

# bytearray state
def MixCols (state):
    mixTable = bytearray(16)
    for i in range(4):
        mixTable[i] = gf.gmul(2, state[i], 8) ^ gf.gmul(3, state[i+4], 8) ^ state[i+8] ^ state[i+12]
        mixTable[i+4] = state[i] ^ gf.gmul(2, state[i+4], 8) ^ gf.gmul(3, state[i+8], 8) ^ state[i+12]
        mixTable[i+8] = state[i] ^ state[i+4] ^ gf.gmul(2, state[i+8], 8) ^ gf.gmul(3, state[i+12], 8)
        mixTable[i+12] = gf.gmul(3, state[i], 8) ^ state[i+4] ^ state[i+8] ^ gf.gmul(2, state[i+12], 8)
    return mixTable

# string textBlock, bytearray blockKey
def XorBlock (textBlock, blockKey):
    xorBlock = bytearray(len(textBlock))
    for i in range(len(xorBlock)):
        xorBlock[i] = textBlock[i] ^ blockKey[i]
    return xorBlock

# teste
authData = "Gabriel F., 27at2301"

message = "A \"Hello, World!\" program is generally a computer program that ignores any input, and outputs or displays a message similar to \"Hello, World!\". A small piece of code in most general-purpose programming languages, this program is used to illustrate a language's basic syntax. \"Hello, World!\" programs are often the first a student learns to write in a given language,[1] and they can also be used as a sanity check to ensure computer software intended to compile or run source code is correctly installed, and that its operator understands how to use it."

mainKey = bytearray(secrets.token_bytes(16))

cipher = Cipher(message, mainKey)
print(cipher)

decipher = Decipher(cipher, mainKey)
print(decipher)