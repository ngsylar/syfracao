import conversions as cvt

__stringEncoding = 'ISO-8859-1'

iv = bytearray([0x68,0x65,0x6C,0x6C,0x6F,0x20,0x77,0x6F,0x72,0x6C,0x64,0x21])
coisa = bytes(iv).decode(__stringEncoding)

print(coisa)

coiso = "Hello World!"
coiso = cvt.str_to_bytearray(coiso)
coiso[4] = 0x78
coiso = cvt.bytearray_to_str(coiso)
print(coiso)