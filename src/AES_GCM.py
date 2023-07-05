import math
from byteblock import *
from modarith import gmul
from utilities import Conversions as convert, PseudoRandom as random

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

# BLOCK_BYTE_COUNT = 16
IV_BYTE_COUNT = 12
AD_SIZE_BLOCK_COUNT = 16 - IV_BYTE_COUNT
COUNTER_BYTE_COUNT = 16 - IV_BYTE_COUNT

def GCM (ivInt: int, authData: str, textSize: int, blockCount: int, cipher: str, mainKey: bytearray) -> tuple[str, bytearray]:
    authDataText = convert.str_to_bytearray(authData)
    cipherText = convert.str_to_bytearray(cipher)
    hashkey = convert.bytearray_to_int(CipherBlock(bytearray(16), mainKey))

    # blockKey[0] and gmul(ad)
    blockKey_0 = CipherBlock(GetNonce(ivInt, 0), mainKey)
    tagInt = gmul(convert.bytearray_to_int(authDataText), hashkey, 128)
    tagText = bytearray(16)

    # gmul(cipherBlock[counter])
    for counter in range(blockCount):
        cipherTextBlock = GetBlock16(textSize, cipherText, counter)
        tagText = XorBlocks(cipherTextBlock, convert.int_to_bytearray(tagInt, 16))
        tagInt = gmul(convert.bytearray_to_int(tagText), hashkey, 128)

    # gmul(adcSize)
    adSize = convert.int_to_bytestr(len(authDataText), AD_SIZE_BLOCK_COUNT)
    adcSize = (len(authDataText) << 8) | len(cipherText)
    tagText = XorBlocks(convert.int_to_bytearray(tagInt, 16), convert.int_to_bytearray(adcSize, 16))

    # tag
    tagInt = gmul(convert.bytearray_to_int(tagText), hashkey, 128)
    tag = XorBlocks(convert.int_to_bytearray(tagInt, 16), blockKey_0)
    return (adSize, tag)

def Decipher (ivadctag: str, mainKey: bytearray) -> str:
    ivadctagText = convert.str_to_bytearray(ivadctag)
    byte_begin, byte_end = 0, IV_BYTE_COUNT

    # get iv
    iv = ivadctagText[byte_begin:byte_end]
    ivInt = convert.bytearray_to_int(iv)
    byte_begin, byte_end = byte_end, byte_end + AD_SIZE_BLOCK_COUNT

    # get ad
    adSize = convert.bytearray_to_int(ivadctagText[byte_begin:byte_end])
    byte_begin, byte_end = byte_end, byte_end + adSize
    authData = convert.bytearray_to_str(ivadctagText[byte_begin:byte_end])

    # get cipher
    byte_begin, byte_end = byte_end, len(ivadctag) - 16
    cipherText = ivadctagText[byte_begin:byte_end]
    cipher = convert.bytearray_to_str(cipherText)

    # get tag
    byte_begin, byte_end = byte_end, byte_end + 16
    tag = ivadctagText[byte_begin:byte_end]

    # compute tag
    cipherTextSize = len(cipherText)
    blockCount = math.ceil(cipherTextSize / 16)
    (_, computedTag) = GCM(ivInt, authData, cipherTextSize, blockCount, cipher, mainKey)

    # verify authenticity
    if (computedTag != tag):
        print("GCM Tag Error: message is corrupted")
        return str()

    # decipher
    message = str()
    for counter in range(1, blockCount+1):
        nonce = GetNonce(convert.bytearray_to_int(iv), counter)
        blockKey = CipherBlock(nonce, mainKey)

        cipherTextBlock = GetBlock16(cipherTextSize, cipherText, counter-1)
        message += convert.bytearray_to_str(XorBlocks(cipherTextBlock, blockKey))

    return message

def Cipher (authData: str, message: str, mainKey: bytearray) -> str:
    iv = random.bytearray_with_byte_count(IV_BYTE_COUNT)
    ivInt = convert.bytearray_to_int(iv)

    plainText = convert.str_to_bytearray(message)
    plainTextSize = len(plainText)
    blockCount = math.ceil(plainTextSize / 16)

    cipher = str()
    for counter in range(1, blockCount+1):
        nonce = GetNonce(ivInt, counter)
        blockKey = CipherBlock(nonce, mainKey)

        plainTextBlock = GetBlock16(plainTextSize, plainText, counter-1)
        cipher += convert.bytearray_to_str(XorBlocks(plainTextBlock, blockKey))
    
    (adSize, tag) = GCM(ivInt, authData, len(cipher), blockCount, cipher, mainKey)

    ivadctag = convert.bytearray_to_str(iv) + adSize + authData + cipher + convert.bytearray_to_str(tag)
    return ivadctag

def GenerateKey ():
    return random.bytearray_with_byte_count(16)

def GetNonce (iv: int, counter: int) -> bytearray:
    nonce = (iv << COUNTER_BYTE_COUNT) | counter
    return convert.int_to_bytearray(nonce, 16)

def KeyExpansion (mainKey: bytearray, roundKeys: list):
    roundKeys[0] = AddRoundKey(0, mainKey)
    for i in range(1, 10):
        roundKeys[i] = AddRoundKey(i, roundKeys[i-1])

def AddRoundKey (round: int, prevKey: bytearray) -> bytearray:
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

def CipherBlock (nonce: bytearray, mainKey: bytearray) -> bytearray:
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

def SubBytes (state: bytearray) -> bytearray:
    for i in range(len(state)):
        row = state[i] >> 4
        col = state[i] & 0x0f
        state[i] = __sBox[row][col]
    return state

def ShiftRows (state: bytearray) -> bytearray:
    state = bytearray([
        state[0], state[1], state[2], state[3],
        state[5], state[6], state[7], state[4],
        state[10], state[11], state[8], state[9],
        state[15], state[12], state[13], state[14]])
    return state

def MixCols (state: bytearray) -> bytearray:
    mixTable = bytearray(16)
    for i in range(4):
        mixTable[i] = gmul(2, state[i], 8) ^ gmul(3, state[i+4], 8) ^ state[i+8] ^ state[i+12]
        mixTable[i+4] = state[i] ^ gmul(2, state[i+4], 8) ^ gmul(3, state[i+8], 8) ^ state[i+12]
        mixTable[i+8] = state[i] ^ state[i+4] ^ gmul(2, state[i+8], 8) ^ gmul(3, state[i+12], 8)
        mixTable[i+12] = gmul(3, state[i], 8) ^ state[i+4] ^ state[i+8] ^ gmul(2, state[i+12], 8)
    return mixTable