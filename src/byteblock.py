def XorBlocks (dominantBlock: bytearray, recessiveBlock: bytearray) -> bytearray:
    xoredBlock = bytearray(len(dominantBlock))
    for i in range(len(xoredBlock)):
        xoredBlock[i] = dominantBlock[i] ^ recessiveBlock[i]
    return xoredBlock

def GetBlock16 (textSize: int, text: bytearray, counter: int) -> bytearray:
    blockBegin = counter * 16
    likelySize = blockBegin + 16
    blockEnd = likelySize if (likelySize < textSize) else textSize
    return text[blockBegin:blockEnd]

def PrintBlock16 (block: bytearray):
    for i in range(4):
        print(hex(block[4*i+0]), hex(block[4*i+1]), hex(block[4*i+2]), hex(block[4*i+3]))
    print()