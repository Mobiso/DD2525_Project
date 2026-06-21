import random
from  crc import Calculator, Crc32
from enum import Enum
import zlib

class Chunk:
    def __init__(self,chunk_type,data,crc):
        self.chunk_type = chunk_type
        self.data = bytearray(data)
        self.length =  len(self.data)
        self.crc=crc


class FuzzAction(Enum):
    FUZZ_IHDR = 0
    FUZZ_GENERIC = 1
    SHUFFLE_BLOCKS = 2
    DELETE_RANDOM_BLOCK = 3
    INSERT_RANDOM = 4
    CORRUPT_RANDOM_CRC = 5
    RANDOM_BYTE_OVERWRITE = 6
    
FUZZ_ACTIONS = list(FuzzAction)
def init(seed):
    random.seed(seed)

PNG_HEADER = b"\x89PNG\r\n\x1a\n"
CHUNK_LENGTH_LENGTH = 4
CHUNK_TYPE_LENGTH = 4
CHUNK_CRC_LENGTH = 4
CHUNK_DATA_START_OFFSET = 8
FILE_HEADER_LENGTH = 8
IHDR_DATA_LENGTH = 13
ENDIAN_TYPE_BIG = "big"

IHDR_BIT_DEPTHS = [1,2,4,8,16]
IHDR_COLOR_TYPE = [0,2,3,4,6]
MAX_INT32 = 2**31 - 1

CHUNK_TYPES = [b"IATx", b"sTER", b"hIST", b"sPLT", b"mkBF", b"mkBS", b"mkTS", b"prVW",
    b"oFFs", b"iDOT", b"zTXt", b"mkBT", b"acTL", b"iTXt", b"sBIT", b"tIME",
    b"iCCP", b"vpAg", b"tRNS", b"cHRM", b"PLTE", b"bKGD", b"gAMA", b"sRGB",
    b"pHYs", b"fdAT", b"fcTL", b"tEXt", b"IDAT",
    b"pCAL", b"sCAL", b"eXIf"]

def fuzz(buf, add_buf, max_size):
    if buf[:len(PNG_HEADER)] != PNG_HEADER: #Reject non png files
        return buf
    #Create the PNG structure
    PNG = deserialize(buf)
    choice = random.choice(FUZZ_ACTIONS)
    
    if len(PNG) == 0:
        choice = FuzzAction.INSERT_RANDOM

    match choice:
        case FuzzAction.FUZZ_IHDR:
            #print("IHDR fuzz")
            fuzz_IHDR(PNG)
        case FuzzAction.FUZZ_GENERIC:
            #print("Generic fuzz")
            generic_fuzz(PNG)
        case FuzzAction.SHUFFLE_BLOCKS:
            #print("Shuffle fuzz")
            random.shuffle(PNG)
        case FuzzAction.DELETE_RANDOM_BLOCK:
            #print("Delete fuzz")
            del PNG[random.randint(0,len(PNG)-1)]
        case FuzzAction.INSERT_RANDOM:
            #print("Insert Random Fuzz")
            insert_random_chunk(PNG)
        case FuzzAction.CORRUPT_RANDOM_CRC:
            #print("Corrupt random CRC")
            corrupt_random_crc(PNG)
        case FuzzAction.RANDOM_BYTE_OVERWRITE:
            #print("Random byte overwrite")
            random_byte_overwrite(PNG)

    return serialize(PNG)


def random_byte_overwrite(PNG:list):
    """
        Overwrite a random contiguous region in a randomly selected PNG chunk
        with a single repeated byte value, then recompute the chunk CRC.
        Args:
            PNG (list)
    """ 
    chunk = random.choice(PNG)
    if chunk.length == 0:
        return
    start = random.randint(0, chunk.length - 1)
    max_len = chunk.length - start
    length = random.randint(1, max_len)
    random_byte = random.getrandbits(8)
    chunk.data[start:start + length] = bytes([random_byte]) * length
    crc = calc_crc(chunk.chunk_type,chunk.data)
    chunk.crc=crc

def insert_random_chunk(PNG:list):
    """
       Insert a random Chunk with random data into a random place in the PNG list.
       Ensures a correct length and CRC. If the length of PNG is 0 it just inserts a random chunk.
        Args:
            PNG (list)
    """ 
    chance_for_non_valid_chunk_type = 20
    if random.randint(0,100) > chance_for_non_valid_chunk_type:
        chunk_type = random.choice(CHUNK_TYPES)
        chunk_data = random.randbytes(random.randint(0,255))
    else:
        chunk_type = random.randbytes(4)
        chunk_data = random.randbytes(random.randint(0,255))

    crc = calc_crc(chunk_type,chunk_data)
    chunk = Chunk(chunk_type,chunk_data,crc)
    if len(PNG) <= 1:
        PNG.append(chunk)
        return
    PNG.insert(random.randint(1,len(PNG)-1),chunk)


def corrupt_random_crc(PNG:list):
    """
        Corrupt a random chunks crc
        Args:
            PNG (list)
    """     
    chunk = random.choice(PNG)
    chunk.crc = random.randbytes(CHUNK_CRC_LENGTH)

def fuzz_IHDR(PNG):
    """
        Fuzz the IHDR Chunk. Currently only uses valid values
        Ensures a CRC
        Args:
            PNG (list)
    """ 
    ihdr = PNG[0] #Assumption
    if ihdr.chunk_type != b'IHDR':
        ihdr = next((c for c in PNG if c.chunk_type == b'IHDR'), None)
    if ihdr is None:
        return

    if ihdr.length != IHDR_DATA_LENGTH:
        ihdr.data = bytearray(13) #Reset it 

    #Indexes
    width_end = 4
    height_end = width_end + 4
    bit_depth_end = height_end + 1
    color_type_end = bit_depth_end + 1
    compression_method_end = color_type_end + 1
    filter_method_end = compression_method_end + 1
    interlace_method_end = filter_method_end + 1
    #Randomize PNG fields in IHDR
    ihdr.data[:width_end] = random.randint(0, MAX_INT32).to_bytes(4, ENDIAN_TYPE_BIG)
    ihdr.data[width_end:height_end] = random.randint(0, MAX_INT32).to_bytes(4, ENDIAN_TYPE_BIG)
    ihdr.data[height_end:bit_depth_end] = random.choice(IHDR_BIT_DEPTHS).to_bytes(1, ENDIAN_TYPE_BIG)
    ihdr.data[bit_depth_end:color_type_end] = random.choice(IHDR_COLOR_TYPE).to_bytes(1, ENDIAN_TYPE_BIG)
    ihdr.data[color_type_end:compression_method_end] = random.randint(0, 1).to_bytes(1, ENDIAN_TYPE_BIG)
    ihdr.data[compression_method_end:filter_method_end] = random.randint(0, 1).to_bytes(1, ENDIAN_TYPE_BIG)
    ihdr.data[filter_method_end:interlace_method_end] = random.randint(0, 1).to_bytes(1, ENDIAN_TYPE_BIG)
    #Recalc CRC
    ihdr.crc = calc_crc(ihdr.chunk_type,ihdr.data)
def generic_fuzz(PNG:list):
    """
        Fuzzes a random data section by either flipping random bits,replacing a random byte, deleting a random byte or adding a random byte. Re-calculates CRC.
            Args:
                PNG (list(Chunk))
            
    """ 
   
    chunk = random.choice(PNG)
    
    #IEND is 0
    if chunk.length == 0:
        random_byte_index = 0
        random_choice = 3 #0 and 3 would be equal
    else:
        random_byte_index = random.randint(0,len(chunk.data)-1)
        random_choice = random.randint(0,3)
            
    match random_choice:
        #Random byte replacement
        case 0:
            #print("\t Random byte replacement")
            chunk.data[random_byte_index] = random.getrandbits(8)
            #Recalc CRC
            chunk.crc = calc_crc(chunk.chunk_type,chunk.data)
        #Random bit flip
        case 1:
            #print("\t Random bit flip")
            random_bit = random.randint(0,7)
            mask = 1
            chunk.data[random_byte_index] = chunk.data[random_byte_index] ^ (mask << random_bit)
        #Delete a random byte
        case 2: 
            #print("\t Random byte delete")
            del chunk.data[random_byte_index]
        #Insert random byte
        case 3:
            #print("\t Random byte inserted")
            random_byte = random.getrandbits(8)
            chunk.data.insert(random_byte_index,random_byte)

    chunk.crc = calc_crc(chunk.chunk_type,chunk.data)


def calc_crc(chunk_type:bytearray,chunk_data:bytearray):
    """
        Calculates the CRC
        Args:
            chunk_type (bytearray), the png chunk type
            chunk_data (bytearray), the png data chunk
        Returns:
            crc (bytes)
    """ 
    return zlib.crc32(chunk_type + chunk_data).to_bytes(CHUNK_CRC_LENGTH, ENDIAN_TYPE_BIG)
    

def deserialize(buf:bytearray):
    """
        Deserialize the png into chunks
        Args:
            buf (bytearray)
        Returns:
            PNG (list(Chunk))
    """ 
    #Create the PNG structure
    PNG = []
    index = len(PNG_HEADER)
    while index < len(buf):
        length = buf[index:index + CHUNK_LENGTH_LENGTH]
        length_int = int.from_bytes(length,ENDIAN_TYPE_BIG)
        chunk_type = buf[index + CHUNK_LENGTH_LENGTH:index + CHUNK_LENGTH_LENGTH + CHUNK_TYPE_LENGTH]
        data = buf[index + CHUNK_LENGTH_LENGTH + CHUNK_TYPE_LENGTH:index + CHUNK_LENGTH_LENGTH + CHUNK_TYPE_LENGTH + length_int]
        crc = buf[index + CHUNK_LENGTH_LENGTH + CHUNK_TYPE_LENGTH + length_int:index + CHUNK_LENGTH_LENGTH + CHUNK_TYPE_LENGTH + length_int + CHUNK_CRC_LENGTH] 
        PNG.append(Chunk(chunk_type,data,crc))
        index = index + CHUNK_LENGTH_LENGTH + CHUNK_TYPE_LENGTH + length_int + CHUNK_CRC_LENGTH
    return PNG
def serialize(PNG:list):
    """
        Construct a PNG from a list of PNG chunks
        Args:
            PNG (list)
        Returns:
            output (bytearray)
    """ 
    output = bytearray()
    output += PNG_HEADER
    for chunk in PNG:
        length = len(chunk.data)
        output += length.to_bytes(CHUNK_LENGTH_LENGTH, ENDIAN_TYPE_BIG)
        output += chunk.chunk_type
        output += chunk.data
        output += chunk.crc
    return output
    
    