#PDF Fuzzer
import random
import sys
from enum import Enum

##########################################
#
#   CONSTANTS
#
##########################################
class FuzzAction(Enum):
    SWITCH_R_VALUE = 0
    SWAP_RANDOM_OBJ = 1
    SET_RANDOM_CHARS_PDF_VERSION = 2
    SWAP_EOF_RANDOM_BYTES = 3
    RANDOMIZE_RANDOM_KEY_VALUE = 4
    RANDOMIZE_RANDOM_KEY = 5
##########################################

# Integer boundary values
INT_BOUNDARIES = [
    b"0",
    b"-1",
    b"1",
    b"2147483647",   # INT_MAX
    b"2147483648",   # INT_MAX + 1
    b"-2147483648",  # INT_MIN
    b"-2147483649",  # INT_MIN - 1
    b"4294967295",   # UINT_MAX
    b"4294967296",   # UINT_MAX + 1
    b"9999999999",   # overflow bait
    b"99999999999999999999",  # very large
]

# Float boundary values
FLOAT_BOUNDARIES = [
    b"0.0",
    b"-0.0",
    b"1.0",
    b"-1.0",
    b"0.00000001",
    b"99999999.9",
    b"1e308",        # near float max
    b"-1e308",
    b"1e-308",       # near float min
    b"1.7976931348623157e+308",  # DBL_MAX
    b"inf",
    b"-inf",
    b"nan",
]

# Malformed / unexpected types
WRONG_TYPES = [
    b"null",
    b"true",
    b"false",
    b"(string)",         # string where number expected
    b"[0 0 0 0]",        # array where scalar expected
    b"<<>>",             # empty dict where scalar expected
    b"/Name",            # name where number expected
]

# Malformed arrays — target /Kids, /Rect, /MediaBox, /Widths etc.
MALFORMED_ARRAYS = [
    b"[]",                       # empty
    b"[0]",                      # too few elements
    b"[0 0 0 0 0 0 0 0]",        # too many elements
    b"[-1 -1 -1 -1]",            # all negative
    b"[2147483647 2147483647 2147483647 2147483647]",  # all INT_MAX
    b"[null null null null]",     # nulls
    b"[/Name /Name /Name /Name]", # names instead of numbers
    b"[(str) (str) (str) (str)]", # strings instead of numbers
]

# Dangerous string values — target /JS, /URI, /Author etc.
DANGEROUS_STRINGS = [
    b"()",                        # empty string
    b"(" + b"A" * 10000 + b")",  # very long string
    b"(\x00\x00\x00\x00)",       # null bytes
    b"(\xff\xfe\xfd\xfc)",       # high bytes
    b"(%%EOF)",                   # EOF marker inside string
    b"(endobj)",                  # keyword inside string
    b"(endstream)",               # keyword inside string
    b"(\\\n)",                    # escaped newline
    b"(\253\254\255)",            # octal escapes
]

# Dangerous name values — target /Filter, /ColorSpace, /Type etc.
DANGEROUS_NAMES = [
    b"/",                         # empty name
    b"/" + b"A" * 10000,         # very long name
    b"/\x00",                     # null byte in name
    b"/#00",                      # null via hex escape
    b"/#ff#fe#fd",                # high bytes via hex escape
    b"/FakeName",                 # unknown name
]

# Dangerous reference values — target /Contents, /Parent, /Root etc.
DANGEROUS_REFS = [
    b"0 0 R",                     # null object reference
    b"-1 0 R",                    # negative object number
    b"99999999 0 R",              # non-existent object
    b"0 99999999 R",              # huge generation number
    b"1 1 R",                     # non-zero generation
]

KEYS = [
    # Structural
    b"/Root ", b"/Info ", b"/Size ", b"/Prev ", b"/XRefStm ", b"/Encrypt ",
    # Page & Layout
    b"/MediaBox ", b"/CropBox ", b"/BleedBox ", b"/TrimBox ", b"/ArtBox ",
    b"/Rotate ", b"/Contents ", b"/Resources ", b"/Parent ", b"/Kids ", b"/Count ",
    # Font
    b"/BaseFont ", b"/Encoding ", b"/FirstChar ", b"/LastChar ", b"/Widths ",
    b"/FontBBox ", b"/FontMatrix ", b"/FontFile ", b"/FontFile2 ", b"/FontFile3 ",
    b"/StemV ", b"/Flags ", b"/Ascent ", b"/Descent ", b"/CapHeight ",
    b"/ToUnicode ", b"/DW ", b"/W ",
    # Color & Graphics
    b"/ColorSpace ", b"/BitsPerComponent ", b"/ImageMask ", b"/Decode ",
    b"/DecodeParms ", b"/Width ", b"/Height ", b"/SMask ",
    # Encryption
    b"/V ", b"/R ", b"/O ", b"/U ", b"/P ", b"/KeyLength ", b"/StmF ", b"/StrF ",
    # Actions & Annotations
    b"/S ", b"/URI ", b"/JS ", b"/JavaScript ", b"/Rect ", b"/Border ",
    b"/AP ", b"/AA ",
    # Metadata
    b"/Author ", b"/Title ", b"/CreationDate ", b"/ModDate ",
]
KEY_VALUE_MAP = {
    # Numeric keys → int boundaries or floats
    b"/Length ":          INT_BOUNDARIES,
    b"/Width ":           INT_BOUNDARIES,
    b"/Height ":          INT_BOUNDARIES,
    b"/BitsPerComponent ": INT_BOUNDARIES,
    b"/FirstChar ":       INT_BOUNDARIES,
    b"/LastChar ":        INT_BOUNDARIES,
    b"/Rotate ":          INT_BOUNDARIES,
    b"/Count ":           INT_BOUNDARIES,
    b"/StemV ":           FLOAT_BOUNDARIES,
    b"/Ascent ":          FLOAT_BOUNDARIES,
    b"/Descent ":         FLOAT_BOUNDARIES,
    b"/ItalicAngle ":     FLOAT_BOUNDARIES,

    # Array keys → malformed arrays
    b"/MediaBox ":        MALFORMED_ARRAYS,
    b"/CropBox ":         MALFORMED_ARRAYS,
    b"/Rect ":            MALFORMED_ARRAYS,
    b"/Kids ":            MALFORMED_ARRAYS,
    b"/Widths ":          MALFORMED_ARRAYS,
    b"/FontBBox ":        MALFORMED_ARRAYS,

    # String keys → dangerous strings
    b"/JS ":              DANGEROUS_STRINGS,
    b"/JavaScript ":      DANGEROUS_STRINGS,
    b"/URI ":             DANGEROUS_STRINGS,
    b"/Author ":          DANGEROUS_STRINGS,
    b"/Title ":           DANGEROUS_STRINGS,
    b"/CreationDate ":    DANGEROUS_STRINGS,

    # Name keys → dangerous names
    b"/Filter ":          DANGEROUS_NAMES,
    b"/ColorSpace ":      DANGEROUS_NAMES,
    b"/Type ":            DANGEROUS_NAMES,
    b"/Encoding ":        DANGEROUS_NAMES,
    b"/BaseFont ":        DANGEROUS_NAMES,

    # Reference keys → dangerous refs
    b"/Root ":            DANGEROUS_REFS,
    b"/Parent ":          DANGEROUS_REFS,
    b"/Contents ":        DANGEROUS_REFS,
    b"/Info ":            DANGEROUS_REFS,
}
GENERIC_DANGEROUS_VALUES = [
    # Integer boundaries
    b"0",
    b"-1",
    b"1",
    b"2147483647",
    b"2147483648",
    b"-2147483648",
    b"-2147483649",
    b"4294967295",
    b"4294967296",
    b"9999999999",
    b"99999999999999999999",
    # Float boundaries
    b"0.0",
    b"-0.0",
    b"1.0",
    b"-1.0",
    b"0.00000001",
    b"99999999.9",
    b"1e308",
    b"-1e308",
    b"1e-308",
    b"inf",
    b"-inf",
    b"nan",
    # Wrong types
    b"null",
    b"true",
    b"false",
    b"(string)",
    b"[0 0 0 0]",
    b"<<>>",
    b"/Name",
    # Malformed arrays
    b"[]",
    b"[0]",
    b"[0 0 0 0 0 0 0 0]",
    b"[-1 -1 -1 -1]",
    b"[2147483647 2147483647 2147483647 2147483647]",
    b"[null null null null]",
    b"[/Name /Name /Name /Name]",
    b"[(str) (str) (str) (str)]",
    # Dangerous strings
    b"()",
    b"(" + b"A" * 10000 + b")",
    b"(\x00\x00\x00\x00)",
    b"(\xff\xfe\xfd\xfc)",
    b"(%%EOF)",
    b"(endobj)",
    b"(endstream)",
    b"(\\\n)",
    b"(\253\254\255)",
    # Dangerous names
    b"/",
    b"/" + b"A" * 10000,
    b"/\x00",
    b"/#00",
    b"/#ff#fe#fd",
    b"/FakeName",
    # Dangerous references
    b"0 0 R",
    b"-1 0 R",
    b"99999999 0 R",
    b"0 99999999 R",
    b"1 1 R"
]
PDF_DELIMITERS = b" \t\n\r/><[]()%"
NOT_FOUND = -1
GENERIC_ERROR = -2
##########################################
#
#   AFL interfaces
#
##########################################
def init(seed):
    random.seed(seed)

def fuzz(buf, add_buf, max_size):
    mutated_data = bytearray(buf)

    match FuzzAction(random.randint(0,5)):
        case FuzzAction.SWITCH_R_VALUE:
            #print("R switch")
            target = b'0 R'
            idx = mutated_data.find(target)
            if idx == NOT_FOUND:
                return buf
            
            mutated_data[idx:idx+3] = b'-1 R'
            if len(mutated_data) <= max_size:
                return mutated_data

            return buf
        case FuzzAction.SWAP_RANDOM_OBJ:
            #print("Random obj switch")
            (start1,end1) = __find_random_object(mutated_data)
            (start2,end2) = __find_random_object(mutated_data)
            if(start1 == NOT_FOUND or start2 == NOT_FOUND):
                return buf
            swapped = __swap_obj(start1,end1,start2,end2,mutated_data)
            return swapped

        case FuzzAction.SET_RANDOM_CHARS_PDF_VERSION:
            #print("Random pdf version")
            return __set_random_pdf_version(mutated_data)
        case FuzzAction.SWAP_EOF_RANDOM_BYTES:
            #print("Random EOF and bytes swap")
            __swap_EOF_with_random_bytes(mutated_data)
            return mutated_data
        case FuzzAction.RANDOMIZE_RANDOM_KEY_VALUE:
            #print("Randomize random key VALUE")
            __randomize_random_key_value(mutated_data)
            return mutated_data
        case FuzzAction.RANDOMIZE_RANDOM_KEY:
            #print("Randomize random KEY")
            __randomize_random_key(mutated_data)
            return mutated_data
        case DEFAULT:
            pass
            #print("wtf?")
    
##########################################
#
#   Helper functions
#
##########################################
def __set_random_pdf_version(buf):
    start = buf.find(b"%PDF-")
    if start == NOT_FOUND:
        start = 0
    end = buf.find(b"\n",start)
    if end == NOT_FOUND:
        end = len(buf)
    #print(f"Found: {buf[start:end]}")
    #print("attempting random pdf versions")
    mutated_buf = (buf[:start] + b"%PDF-" + __random_chars(random.randint(0, 15)) + b"."+ __random_chars(random.randint(0, 15)) + b"\n" + buf[end:])
    return mutated_buf


def __random_chars(amount):
    return bytes([random.randint(0, 127) for _ in range(amount)])
   

def __find_random_object(buf):
    if buf.find(b"obj") == NOT_FOUND:
        return (-1,-1)
    
    random_offset = random.randint(0,len(buf))
    idx = buf.find(b" obj",random_offset)
    #Hopefully it finds something...
    while idx == NOT_FOUND:
        idx = buf.find(b"obj",random.randint(0,len(buf)))
    
    idx_end = buf.find(b"endobj",idx+1)

    return (idx,idx_end)

def __swap_obj(start1,end1,start2,end2,buf):
    bytes_data = (
        buf[:start1] + buf[start2:end2] + buf[start1:end1] + buf[end2:]

    )
    return bytes_data

def __swap_bytes(start1,end1,start2,end2,buf):
    assert (end1 - start1) == (end2 - start2)
    assert end1 >= start1 and end2 >= start2    
    temp = buf[start1:end1]
    buf[start1:end1] = buf[start2:end2]
    buf[start2:end2] = temp


def __swap_EOF_with_random_bytes(buf):
    eof_string = b"%%EOF"
    start_eof = buf.find(eof_string)
    if start_eof == NOT_FOUND:
        return buf
    end_eof = start_eof + len(eof_string)
    rnd_start = random.randint(0,len(buf)-(end_eof-start_eof))
    rnd_end = rnd_start + len(eof_string)
    while not (rnd_start > end_eof or rnd_end < start_eof):
        rnd_start = random.randint(0,len(buf)-(end_eof-start_eof))
        rnd_end = rnd_start + len(eof_string) 
    __swap_bytes(start_eof,end_eof,rnd_start,rnd_end,buf)

def __replace_bytes(start,end,bytes,buf):
    buf[start:end] = bytes


def __find_end_token_index(start,buf):
    idx = start
    if idx >= len(buf):
        return GENERIC_ERROR
    while buf[idx] not in PDF_DELIMITERS and idx + 1 != len(buf):
        idx = idx + 1
    return idx

def __randomize_random_key_value(buf):
    random_offset = random.randint(0,len(buf))
    random_key = random.choice(KEYS)
    #print(f"Selected random key: {random_key}")
    idx = buf.find(random_key,random_offset)
    #Hopefully it finds something...
    retries = 10
    while idx == NOT_FOUND and retries > 0:
        idx = buf.find(random_key,random.randint(0,len(buf)))
        retries = retries - 1
    
    idx_start = idx + len(random_key)
    idx_end = __find_end_token_index(idx_start,buf)
    if idx_end == GENERIC_ERROR:
        return buf
    #If the random key is in the mapping then randomly try a dangerous value for that field or try something generic
    if random_key in KEY_VALUE_MAP:
        if random.randint(0,3) == 0:
            replacement = random.choice(KEY_VALUE_MAP[random_key])
        else:
            if random.randint(0,1) == 0:
                replacement = random.choice(GENERIC_DANGEROUS_VALUES)
            else:
                replacement = __random_chars(random.randint(0,20))
    else:
        if random.randint(0,1) == 0:
                replacement = random.choice(GENERIC_DANGEROUS_VALUES)
        else:
                replacement = __random_chars(random.randint(0,20))
    #print(f"replacing with: {replacement}")
    __replace_bytes(idx_start,idx_end,replacement,buf)

def __randomize_random_key(buf):
    random_offset = random.randint(0,len(buf))
    random_key = random.choice(KEYS)
    #print(f"Selected random key: {random_key}")
    idx = buf.find(random_key,random_offset)
    #Hopefully it finds something...
    retries = 10
    while idx == NOT_FOUND and retries > 0:
        idx = buf.find(random_key,random.randint(0,len(buf)))
        retries = retries - 1

    idx_end = __find_end_token_index(idx,buf)
    if idx_end == GENERIC_ERROR:
        return buf
    #If the random key is in the mapping then randomly try swapping it with another key, generic dangerous value or just some random chars
    if random_key in KEY_VALUE_MAP:
        if random.randint(0,3) == 0:
            replacement = random.choice(list(KEY_VALUE_MAP.keys()))
        else:
            if random.randint(0,1) == 0:
                replacement = random.choice(GENERIC_DANGEROUS_VALUES)
            else:
                replacement = __random_chars(random.randint(0,20))
    else:
        if random.randint(0,1) == 0:
                replacement = random.choice(GENERIC_DANGEROUS_VALUES)
        else:
                replacement = __random_chars(random.randint(0,20))
    #print(f"replacing with: {replacement}")
    __replace_bytes(idx,idx_end,replacement,buf)
    



    



