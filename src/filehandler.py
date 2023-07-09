import BASE64
from utilities import Conversions as convert

# editar: usar modos 'wb' e 'rb' e trocar entradas str() por bytes() para aceitar qualquer tipo de arquivo

FILE_WRITE = 'w'
FILE_READ = 'r'
FORMAT_TEXT = ".txt"
FORMAT_KEY = ".k3y"
TYPE_PUBLIC = ".pub"
TYPE_SECRET = ".sec"
MODE_ENCRYPT = ".enc"
MODE_DECRYPT = ".dec"

def __writeFile (content: str, filename: str, extension: str, coded: bool):
    file = open(filename + extension, FILE_WRITE)
    file.write(BASE64.Encode(content)) if coded else file.write(content)
    file.close()

def __readFile (filename: str, extension: str, coded: bool) -> str:
    file = open(filename + extension, FILE_READ)
    content = BASE64.Decode(file.read()) if coded else file.read()
    file.close()
    return content

def __writeAsymKey (asymKey: tuple[int, int], filename: str, visibility: str):
    (modulus, exponent) = asymKey
    file = open(filename + visibility + FORMAT_KEY, FILE_WRITE)
    file.write(str(modulus)+"\n"+str(exponent))
    file.close

def __readAsymKey (filename: str, visibility: str) -> tuple[int, int]:
    file = open(filename + visibility + FORMAT_KEY, FILE_READ)
    modulus = int(file.readline())
    exponent = int(file.readline())
    file.close
    return (modulus, exponent)

def writeHybridCipher (content: tuple[str, list[int]], filename: str):
    symbols, integers = content
    file = open(filename + MODE_ENCRYPT + FORMAT_TEXT, FILE_WRITE)
    file.write(BASE64.Encode(symbols))
    for integer in integers:
        file.write("\n" + str(integer))
    file.close()

def readHybridCipher (filename: str) -> tuple[str, list[int]]:
    file = open(filename + MODE_ENCRYPT + FORMAT_TEXT, FILE_READ)
    symbols = BASE64.Decode(file.readline()[:-1])
    integers = list()
    while True:
        integer = file.readline()
        if not integer:
            break
        integers.append(int(integer))
    return (symbols, integers)

def writeSecretKey (secretKey: tuple[int, int], filename: str):
    __writeAsymKey(secretKey, filename, TYPE_SECRET)

def readSecretKey (filename: str) -> tuple[int, int]:
    return __readAsymKey(filename, TYPE_SECRET)

def writePublicKey (publicKey: tuple[int, int], filename: str):
    __writeAsymKey(publicKey, filename, TYPE_PUBLIC)

def readPublicKey (filename: str) -> tuple[int, int]:
    return __readAsymKey(filename, TYPE_PUBLIC)

def writeKey (key: bytearray, filename: str):
    __writeFile(convert.bytearray_to_str(key), filename, FORMAT_KEY, True)

def readKey (filename: str) -> bytearray:
    return convert.str_to_bytearray(__readFile(filename, FORMAT_KEY, True))

def writeAsymCipher (cipher: int, filename: str):
    __writeFile(str(cipher), filename, MODE_ENCRYPT + FORMAT_TEXT, False)

def readAsymCipher (filename: str) -> int:
    return int(__readFile(filename, MODE_ENCRYPT + FORMAT_TEXT, False))

def writeCipher (cipher: str, filename: str):
    __writeFile(cipher, filename, MODE_ENCRYPT + FORMAT_TEXT, True)

def readCipher (filename: str) -> str:
    return __readFile(filename, MODE_ENCRYPT + FORMAT_TEXT, True)

def writeMessage (content: str, filename: str):
    __writeFile(content, filename, MODE_DECRYPT + FORMAT_TEXT, False)

def readMessage (filename: str) -> str:
    return __readFile(filename, FORMAT_TEXT, False)