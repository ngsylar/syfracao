import secrets

class EncodingType:
    string = 'ISO-8859-1'
    integer = 'big'

class Qualities:
    def count_bytes_of_int (value: int) -> int:
        return ((value.bit_length() + 7) // 8)

class Conversions:
    def bytearray_to_str (value: bytearray) -> str:
        return bytes(value).decode(EncodingType.string)

    def bytearray_to_int (value: bytearray) -> int:
        return int.from_bytes(value, EncodingType.integer)

    def bytes_to_str (value: bytes) -> str:
        return value.decode(EncodingType.string)

    def str_to_bytearray (value: str) -> bytearray:
        return bytearray(bytes(value, EncodingType.string))
    
    def str_to_bytes (value: str) -> bytes:
        return bytes(value, EncodingType.string)

    def int_to_bytearray (value: int, byteCount: int=0) -> bytearray:
        return bytearray(Conversions.int_to_bytes(value, byteCount))

    def int_to_bytes (value: int, byteCount: int=0) -> bytes:
        sourceByteCount = Qualities.count_bytes_of_int(value)
        byteCount = sourceByteCount if (byteCount < sourceByteCount) else byteCount
        return value.to_bytes(byteCount, EncodingType.integer)

    def int_to_bytestr (value: int, byteCount: int=0) -> str:
        return Conversions.int_to_bytes(value, byteCount).decode(EncodingType.string)

class PseudoRandom:
    def bytearray_with_byte_count (byteCount: int) -> bytearray:
        return bytearray(secrets.token_bytes(byteCount))

    def int_in_range (startval: int, stopval: int) -> int:
        rangeval = stopval - startval
        return (secrets.randbelow(rangeval) + startval)

    def int_with_full_bit_count (bitCount: int) -> int:
        startval = 1 << (bitCount - 1)
        rangeval = (startval << 1) - startval
        return (secrets.randbelow(rangeval) + startval)