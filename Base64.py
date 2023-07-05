from utilities import Conversions as convert

__encTable = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def Ngrams (message: str, n: int) -> list[str]:
    charCount = len(message)
    trigrams = list()
    for i in range(0, charCount, n):
        trigrams.append(message[i:i+n])
    return trigrams

def EncondeTrigramValue (triValue: int, byteCount: int) -> str:
    trigram24 = triValue << (6 - 2 * byteCount)
    bitCount = 6 * (byteCount + 1)
    encTrigram = str()

    for i in range(byteCount+1):
        value6 = (trigram24 >> (bitCount-(i+1)*6)) & 0x3f
        encTrigram += __encTable[value6]
    for i in range(3-byteCount):
        encTrigram += '='

    return encTrigram

def Encode (message: str) -> str:
    trigrams = Ngrams(message, 3)
    encText = str()
    for trigram in trigrams:
        value = convert.str_to_int(trigram)
        encText += EncondeTrigramValue(value, len(trigram))
    return encText

def Decode (codedMsg: str, dec: int=0) -> str:
    suffixCount = codedMsg[-2:].count('=')
    lastChar = len(codedMsg) - suffixCount
    for codedChar in codedMsg[:lastChar]:
        dec = (dec << 6) | __encTable.index(codedChar)
    dec >>= suffixCount * 2
    return convert.int_to_bytestr(dec)

# messageT = "Man is distinguished, not only by his reason, but by this singular passion from other animals, which is a lust of the mind, that by a perseverance of delight in the continued and indefatigable generation of knowledge, exceeds the short vehemence of any carnal pleasure."

# encT = Encode(messageT)
# decT = Decode(encT)
# print(encT)
# print(decT)