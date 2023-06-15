__stringEncoding = 'ISO-8859-1'
__numberEncoding = 'big'

def str_to_bytearray (strVar):
    return bytearray(bytes(strVar, __stringEncoding))

def bytearray_to_str (arrayVar):
    return bytes(arrayVar).decode(__stringEncoding)

def int_to_bytearray (intVar, byteCount):
    return bytearray(intVar.to_bytes(byteCount, __numberEncoding))

def bytearray_to_int (arrayVar):
    return int.from_bytes(arrayVar, __numberEncoding)