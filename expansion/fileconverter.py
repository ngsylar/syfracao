# Enpansao do criptossistema hibrido com geracao e verificacao de assinaturas
# Com este modulo eh possivel cifrar ou decifrar qualquer tipo de arquivos
# Extensoes de arquivo nao limitadas a .txt
# Deve ser executado em paralelo ao programa principal

import sys
from os import path
sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))

from src import BASE64
from src.utilities import Qualities as quality, Conversions as convert

print("\n--- Converter arquivo *.* para *.txt ---\n")
filename = input("Digite o nome do arquivo com extensao: ")

# le um arquivo A.* de extensao qualquer
file = open(filename, 'rb')
content = convert.bytes_to_str(file.read())
file.close()

# cria um arquivo A.*.txt
file = open(filename + ".txt", 'w')
file.write(BASE64.Encode(content))
file.close()

print("Arquivo convertido!")
input("Aperte [Enter] para desconverter...")

# le o arquivo decifrado A.*.dec.txt
extension_begin = quality.reversed_index_of('.', filename)
file = open(filename + ".dec.txt", 'r')
content = BASE64.Decode(file.read())
file.close()

# cria um arquivo A.dec.* com a extensao original
file = open(filename[:extension_begin] + ".dec" + filename[extension_begin:], 'wb')
file.write(convert.str_to_bytes(content))
file.close()