import hashlib
import AES_GCM
import RSA
import filehandler as file
from utilities import Conversions as convert

__atil = convert.int_to_bytestr(195)
__cced = convert.int_to_bytestr(199)

def main ():
    opt = "99"
    while int(opt) != 0:
        print("\n---- SYFRA"+__cced+__atil+"O ----\n")
        print("1 Geracao de chave e cifracao simetrica")
        print("2 Geracao de chaves assimetricas")
        print("3 Cifracao assimetrica")
        print("4 Cifracao hibrida")
        # print("05 Cifracao hibrida autenticada")
        print("5 Cifracao hibrida e geracao de assinatura")
        print("6 Decifracao simetrica")
        print("7 Decifracao assimetrica")
        print("8 Decifracao hibrida")
        # print("10 Decifracao hibrida autenticada")
        print("9 Verificacao de assinatura e decifracao hibrida")
        print("0 Encerrar aplicacao")
        opt = input("\nEscolha uma opcao: ")
        if int(opt) > 0:
            optList[int(opt)]()

def opt1 ():
    print("\n---- in: M; gen: k; out: k; out: AESenc(M,k) ----\n")
    fileName = input("\".txt\" contendo a mensagem: ")

    key = AES_GCM.GenerateKey()
    file.writekey(key, fileName)
    message = file.readmsg(fileName)
    cipher = AES_GCM.Cipher(fileName, message, key)
    file.writesc(cipher, fileName)

def opt2 ():
    print("\n---- gen: Apk, Ask; out: Apk, Ask ----\n")
    fileName = input("Nome do par de chaves a ser criado: ")
    msgSize = input("Tamanho maximo das mensagens a cifrar: ")

    (publicKey, secretKey) = RSA.GenerateKeys(int(msgSize))
    file.writepk(publicKey, fileName)
    file.writesk(secretKey, fileName)

def opt3 ():
    print("\n---- in: M, Bpk; gen: k; out: RSAenc(M,Bpk) ----\n")
    fileName = input("\".txt\" contendo a mensagem: ")
    bpkName = input("\".pub.k3y\" contendo a chave publica do destinatario: ")

    publicKey = file.readpk(bpkName)
    message = file.readmsg(fileName)
    cipher = RSA.Cipher(publicKey, message)
    file.writeac(cipher, fileName)

def opt4 ():
    print("\n---- in: M, Bpk; gen: k; out: AESenc(M,k), RSAenc(k,Bpk) ----\n")
    fileName = input("\".txt\" contendo a mensagem: ")
    bpkName = input("\".pub.k3y\" contendo a chave publica do destinatario: ")

    key = AES_GCM.GenerateKey()
    message = file.readmsg(fileName)
    cipher = AES_GCM.Cipher(fileName, message, key)

    publicKey = file.readpk(bpkName)
    cipherKey = RSA.Cipher(publicKey, convert.bytearray_to_str(key))
    file.writeh((cipher, [cipherKey]), fileName)

# # funcao problematica da especificacao (caso de uso 3)
# def opt5 ():
#     print("\n---- in: M, Ask, Apk, Bpk; gen: k; out: AESenc(M,k), RSAenc(RSAenc(k,Bpk),Ask), Apk ----\n")
#     fileName = input("\".txt\" contendo a mensagem: ")
#     a_kName = input("Par \".*.k3y\" contendo as suas chaves assimetricas: ")
#     bpkName = input("\".k3y\" contendo a chave publica do destinatario: ")

#     key = AES_GCM.GenerateKey()
#     message = file.readmsg(fileName)
#     cipher = AES_GCM.Cipher(fileName, message, key)

#     bpublicKey = file.readpk(bpkName)
#     cipherKey = RSA.Cipher(bpublicKey, convert.bytearray_to_str(key))

#     asecretKey = file.readsk(a_kName)
#     apublicKey = file.readpk(a_kName)
#     (an, ae), ad = apublicKey, asecretKey # mnemonicas retiradas diretamente da especificacao!!!

#     authKey = RSA.Cipher((ad, ae), cipherKey) # erro: cipherKey > 190 bytes
#     file.writeh(cipher, [authKey, an, ae], fileName)

def opt5 ():
    print("\n---- in: M, Ask, Apk, Bpk; gen: k; out: AESenc(M,k), RSAenc(k,Bpk), RSAenc(H(AESenc(M,k)),Ask), Apk ----\n")
    fileName = input("\".txt\" contendo a mensagem: ")
    a_kName = input("Par \".*.k3y\" contendo as suas chaves assimetricas: ")
    bpkName = input("\".pub.k3y\" contendo a chave publica do destinatario: ")

    key = AES_GCM.GenerateKey()
    message = file.readmsg(fileName)
    cipher = AES_GCM.Cipher(fileName, message, key)

    bpublicKey = file.readpk(bpkName)
    cipherKey = RSA.Cipher(bpublicKey, convert.bytearray_to_str(key))

    asecretKey = file.readsk(a_kName)
    apublicKey = file.readpk(a_kName)
    (an, ae), ad = apublicKey, asecretKey

    hashCipher = hashlib.sha3_256(convert.str_to_bytes(cipher)).digest()
    sign = RSA.Cipher((an, ad), convert.bytes_to_str(hashCipher))
    file.writeh((cipher, [cipherKey, sign, an, ae]), fileName)

def opt6 ():
    print("\n---- in: C, k; out: AESdec(C,k) ----\n")
    fileName = input("\".txt\" contendo a cifra: ")

    cipher = file.readsc(fileName)
    key = file.readkey(fileName)
    message = AES_GCM.Decipher(cipher, key)
    file.writemsg(message, fileName)

def opt7 ():
    print("\n---- in: C, Ask, Apk; out: RSAdec(C,Ask) ----\n")
    fileName = input("\".txt\" contendo a cifra: ")
    a_kName = input("Par \".*.k3y\" contendo as suas chaves assimetricas: ")

    secretKey = file.readsk(a_kName)
    publicKey = file.readpk(a_kName)
    cipher = file.readac(fileName)

    message = RSA.Decipher(secretKey, publicKey, cipher)
    file.writemsg(message, fileName)

def opt8 ():
    print("\n---- in: C, Ask, Apk; out: AESdec(C,RSAdec(ck,Ask)) ----\n")
    fileName = input("\".txt\" contendo a cifra: ")
    a_kName = input("Par \".*.k3y\" contendo as suas chaves assimetricas: ")

    secretKey = file.readsk(a_kName)
    publicKey = file.readpk(a_kName)
    cipher, [cipherKey] = file.readh(fileName)

    key = RSA.Decipher(secretKey, publicKey, cipherKey)
    message = AES_GCM.Decipher(cipher, convert.str_to_bytearray(key))
    file.writemsg(message, fileName)

def opt9 ():
    print("\n---- in: C, Ask, Apk; out: AESdec(C,RSAdec(ck,Ask)) ----\n")
    fileName = input("\".txt\" contendo a cifra: ")
    a_kName = input("Par \".*.k3y\" contendo as suas chaves assimetricas: ")

    cipher, [cipherKey, sign, bn, be] = file.readh(fileName)
    hashCipher = hashlib.sha3_256(convert.str_to_bytes(cipher)).digest()
    givenHash = RSA.Decipher(be, (bn, be), sign)
    
    if hashCipher != convert.str_to_bytes(givenHash):
        print("\nAviso: a assinatura nao corresponde")
        input("Pressione [Enter] para continuar...")
        return
    
    secretKey = file.readsk(a_kName)
    publicKey = file.readpk(a_kName)

    key = RSA.Decipher(secretKey, publicKey, cipherKey)
    message = AES_GCM.Decipher(cipher, convert.str_to_bytearray(key))
    file.writemsg(message, fileName)

optList = [0,opt1,opt2,opt3,opt4,opt5,opt6,opt7,opt8,opt9]
if __name__ == "__main__":
    main()