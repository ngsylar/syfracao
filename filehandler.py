import BASE64
from utilities import Conversions as convert

def write (content: str, filename: str, extension: str, coded: bool):
    file = open(filename + extension, 'w')
    file.write(BASE64.Encode(content)) if coded else file.write(content)
    file.close()

def read (filename: str, extension: str, coded: bool) -> str:
    file = open(filename + extension, 'r')
    content = BASE64.Decode(file.read()) if coded else file.read()
    file.close()
    return content

def writeh (content: tuple[str, list[int]], filename: str):
    symbols, integers = content
    file = open(filename + ".enc.txt", 'w')
    file.write(BASE64.Encode(symbols))
    for integer in integers:
        file.write("\n" + str(integer))
    file.close()

def readh (filename: str) -> tuple[str, list[int]]:
    file = open(filename + ".enc.txt", 'r')
    symbols = BASE64.Decode(file.readline()[:-1])
    integers = list()
    while True:
        integer = file.readline()
        if not integer:
            break
        integers.append(int(integer))
    return (symbols, integers)

def writepk (publicKey: tuple[int, int], filename: str):
    (n, e) = publicKey
    file = open(filename + ".pub.k3y", 'w')
    file.write(str(n)+"\n"+str(e))
    file.close

def readpk (filename: str) -> tuple[int, int]:
    file = open(filename + ".pub.k3y", 'r')
    n = int(file.readline())
    e = int(file.readline())
    file.close
    return (n, e)

def writesk (privateKey: int, filename: str):
    write(str(privateKey), filename, ".sec.k3y", False)

def readsk (filename: str) -> int:
    return int(read(filename, ".sec.k3y", False))

def writekey (key: bytearray, filename: str):
    write(convert.bytearray_to_str(key), filename, ".k3y", True)

def readkey (filename: str) -> bytearray:
    return convert.str_to_bytearray(read(filename, ".k3y", True))

def writeac (content: int, filename: str):
    write(str(content), filename, ".enc.txt", False)

def readac (filename: str) -> int:
    return int(read(filename, ".enc.txt", False))

def writesc (content: str, filename: str):
    write(content, filename, ".enc.txt", True)

def readsc (filename: str) -> str:
    return read(filename, ".enc.txt", True)

def writemsg (content: str, filename: str):
    write(content, filename, ".dec.txt", False)

def readmsg (filename: str) -> str:
    return read(filename, ".txt", False)