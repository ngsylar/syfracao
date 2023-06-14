import math
import secrets

coisa = bytearray(secrets.token_bytes(16))
# for coisita in coisa:
#     print(hex(coisita))
coisa = int.from_bytes(coisa, 'big')
print(hex(coisa))

coisa = bytearray(coisa.to_bytes(16, 'big'))
# for coisita in coisa:
#     print(hex(coisita))

plainText = "A \"Hello, World!\" program is generally a computer program that ignores any input, and outputs or displays a message similar to \"Hello, World!\". A small piece of code in most general-purpose programming languages, this program is used to illustrate a language's basic syntax. \"Hello, World!\" programs are often the first a student learns to write in a given language,[1] and they can also be used as a sanity check to ensure computer software intended to compile or run source code is correctly installed, and that its operator understands how to use it."

coiso = bytearray(bytes(plainText, 'ISO-8859-1'))
coiso[1] ^= 0xdf
print(hex(coiso[1]))
print(bin(0x20), bin(0xdf))
print(len(coiso))

msgSize = len(plainText)
blockCount = math.ceil(len(plainText)/16)
print(type(blockCount))

pedacos = ""
for i in range(blockCount):
    blockBegin = i*16
    likelySize = blockBegin+16
    blockEnd = likelySize if likelySize < msgSize else msgSize
    # print(blockBegin, blockEnd)
    pedacos += bytes(coiso[blockBegin:blockEnd]).decode('ISO-8859-1')
print(pedacos)
print("fim")








