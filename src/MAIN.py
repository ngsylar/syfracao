import AES_GCM
import RSA
import filehandler as file
from utilities import Quality as quality, Conversion as convert, Hash as makeHash

__atil = convert.int_to_bytestr(195)
__cced = convert.int_to_bytestr(199)

def main ():
    opt = "99"
    while int(opt) != 0:
        print("\n---- SYFRA"+__cced+__atil+"O ----\n")
        print("01 Geracao de chave e cifracao simetrica (AES_GCM)")
        print("02 Geracao de chaves assimetricas (RSA_OAEP)")
        print("03 Cifracao assimetrica (RSA_OAEP)")
        print("04 Cifracao hibrida (AES_GCM, RSA_OAEP)")
        print("05 Cifracao hibrida autenticada (AES_GCM, RSA_OAEP_ECB)")
        print("06 Cifracao hibrida e geracao de assinatura (AES_GCM, RSA_OAEP)")
        print("07 Decifracao simetrica (AES_GCM)")
        print("08 Decifracao assimetrica (RSA_OAEP)")
        print("09 Decifracao hibrida (AES_GCM, RSA_OAEP)")
        print("10 Decifracao hibrida autenticada (AES_GCM, RSA_OAEP_ECB)")
        print("11 Verificacao de assinatura e decifracao hibrida (AES_GCM, RSA_OAEP)")
        print("00 Encerrar aplicacao")
        opt = input("\nEscolha uma opcao: ")
        if int(opt) > 0:
            optList[int(opt)]()

def opt1 ():
    print("\n---- in: M; gen: k; out: k; out: AESenc(M,k) ----\n")
    fileName = input("\".txt\" contendo a mensagem: ")

    key = AES_GCM.GenerateKey()
    file.writeKey(key, fileName)
    message = file.readMessage(fileName)
    cipher = AES_GCM.Cipher(fileName, message, key)
    file.writeCipher(cipher, fileName)

def opt2 ():
    print("\n---- gen: Apk, Ask; out: Apk, Ask ----\n")
    fileName = input("Nome do par de chaves a ser criado: ")
    msgSize = input("Tamanho maximo das mensagens a cifrar: ")

    myPublicKey, mySecretKey = RSA.GenerateKeys(int(msgSize))
    file.writePublicKey(myPublicKey, fileName)
    file.writeSecretKey(mySecretKey, fileName)

def opt3 ():
    print("\n---- in: M, Bpk; gen: k; out: RSAenc(M,Bpk) ----\n")
    fileName = input("\".txt\" contendo a mensagem: ")
    otherPublicKeyName = input("\".pub.k3y\" contendo a chave publica do destinatario: ")

    otherPublicKey = file.readPublicKey(otherPublicKeyName)
    message = file.readMessage(fileName)
    cipher = RSA.Cipher(otherPublicKey, message)
    file.writeAsymCipher(cipher, fileName)

def opt4 ():
    print("\n---- in: M, Bpk; gen: k; out: AESenc(M,k), RSAenc(k,Bpk) ----\n")
    fileName = input("\".txt\" contendo a mensagem: ")
    otherPublicKeyName = input("\".pub.k3y\" contendo a chave publica do destinatario: ")

    key = AES_GCM.GenerateKey()
    message = file.readMessage(fileName)
    cipher = AES_GCM.Cipher(fileName, message, key)

    otherPublicKey = file.readPublicKey(otherPublicKeyName)
    cipherKey = RSA.Cipher(otherPublicKey, convert.bytearray_to_str(key))
    file.writeHybridCipher((cipher, [cipherKey]), fileName)

def opt5 ():
    print("\n---- in: M, Ask, Apk, Bpk; gen: k; out: AESenc(M,k), RSAenc(RSAenc(k,Bpk),Ask), Apk ----\n")
    fileName = input("\".txt\" contendo a mensagem: ")
    my_KeyName = input("Par \".*.k3y\" contendo as suas chaves assimetricas: ")
    otherPublicKeyName = input("\".k3y\" contendo a chave publica do destinatario: ")

    key = AES_GCM.GenerateKey()
    message = file.readMessage(fileName)
    cipher = AES_GCM.Cipher(fileName, message, key)

    otherPublicKey = file.readPublicKey(otherPublicKeyName)
    cipherKey = convert.int_to_bytestr(RSA.Cipher(otherPublicKey, convert.bytearray_to_str(key)))
    mySecretKey = file.readSecretKey(my_KeyName)
    myPublicKey = list(file.readPublicKey(my_KeyName))

    authKey = list()
    cipherKeySize = len(cipherKey)
    blockSize = quality.byte_count_of_int(mySecretKey[0]) - 2*RSA.OAEP.HASH_BYTE_COUNT - 2

    for i in range(0, cipherKeySize, blockSize):
        authKey.append(RSA.Cipher(mySecretKey, cipherKey[i:i+blockSize]))
    file.writeHybridCipher((cipher, authKey + myPublicKey), fileName)

def opt6 ():
    print("\n---- in: M, Ask, Apk, Bpk; gen: k; out: AESenc(M,k), RSAenc(k,Bpk), RSAenc(H(AESenc(M,k)),Ask), Apk ----\n")
    fileName = input("\".txt\" contendo a mensagem: ")
    my_KeyName = input("Par \".*.k3y\" contendo as suas chaves assimetricas: ")
    otherPublicKeyName = input("\".pub.k3y\" contendo a chave publica do destinatario: ")

    key = AES_GCM.GenerateKey()
    message = file.readMessage(fileName)
    cipher = AES_GCM.Cipher(fileName, message, key)

    otherPublicKey = file.readPublicKey(otherPublicKeyName)
    cipherKey = RSA.Cipher(otherPublicKey, convert.bytearray_to_str(key))
    mySecretKey = file.readSecretKey(my_KeyName)
    myPublicKey = list(file.readPublicKey(my_KeyName))

    hashCipher = makeHash.SHA3_256(cipher)
    sign = RSA.Cipher(mySecretKey, convert.bytes_to_str(hashCipher))
    file.writeHybridCipher((cipher, [cipherKey, sign] + myPublicKey), fileName)

def opt7 ():
    print("\n---- in: C, k; out: AESdec(C,k) ----\n")
    fileName = input("\".enc.txt\" contendo a cifra: ")

    cipher = file.readCipher(fileName)
    key = file.readKey(fileName)
    message = AES_GCM.Decipher(cipher, key)
    file.writeMessage(message, fileName)

def opt8 ():
    print("\n---- in: C, Ask; out: RSAdec(C,Ask) ----\n")
    fileName = input("\".enc.txt\" contendo a cifra: ")
    mySecretKeyName = input("\".sec.k3y\" contendo a sua chave secreta: ")

    mySecretKey = file.readSecretKey(mySecretKeyName)
    cipher = file.readAsymCipher(fileName)
    message = RSA.Decipher(mySecretKey, cipher)
    file.writeMessage(message, fileName)

def opt9 ():
    print("\n---- in: C, Ask; out: AESdec(C,RSAdec(k(C),Ask)) ----\n")
    fileName = input("\".enc.txt\" contendo a cifra: ")
    mySecretKeyName = input("\".sec.k3y\" contendo a sua chave secreta: ")

    mySecretKey = file.readSecretKey(mySecretKeyName)
    cipher, [cipherKey] = file.readHybridCipher(fileName)
    key = RSA.Decipher(mySecretKey, cipherKey)
    message = AES_GCM.Decipher(cipher, convert.str_to_bytearray(key))
    file.writeMessage(message, fileName)

def opt10 ():
    print("\n---- in: C, Ask; out: AESdec(C,RSAdec(RSAdec(k(C),Ask),Bpk(C))) ----\n")
    fileName = input("\".enc.txt\" contendo a cifra: ")
    mySecretKeyName = input("\".sec.k3y\" contendo a sua chave secreta: ")

    symbols, integers = file.readHybridCipher(fileName)
    cipher, authKey, otherPublicKey = symbols, integers[:-2], (integers[-2], integers[-1])

    cipherKey = str()
    for authKeyBlock in authKey:
        cipherKey += RSA.Decipher(otherPublicKey, authKeyBlock)

    mySecretKey = file.readSecretKey(mySecretKeyName)
    key = RSA.Decipher(mySecretKey, convert.str_to_int(cipherKey))
    message = AES_GCM.Decipher(cipher, convert.str_to_bytearray(key))
    file.writeMessage(message, fileName)

def opt11 ():
    print("\n---- in: C, Ask; out: AESdec(C,RSAdec(k(C),Ask)) ----\n")
    fileName = input("\".enc.txt\" contendo a cifra: ")
    mySecretKeyName = input("\".sec.k3y\" contendo a sua chave secreta: ")

    symbols, integers = file.readHybridCipher(fileName)
    cipher, cipherKey, sign, otherPublicKey = symbols, integers[0], integers[1], (integers[2], integers[3])
    hashCipher = makeHash.SHA3_256(cipher)
    givenHash = RSA.Decipher(otherPublicKey, sign)
    
    if hashCipher != convert.str_to_bytes(givenHash):
        print("\nAviso: a assinatura nao corresponde")
        input("Pressione [Enter] para continuar...")
        return
    
    mySecretKey = file.readSecretKey(mySecretKeyName)
    key = RSA.Decipher(mySecretKey, cipherKey)
    message = AES_GCM.Decipher(cipher, convert.str_to_bytearray(key))
    file.writeMessage(message, fileName)

optList = [0,opt1,opt2,opt3,opt4,opt5,opt6,opt7,opt8,opt9,opt10,opt11]
if __name__ == "__main__":
    main()