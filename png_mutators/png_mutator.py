import random
from  crc import Calculator, Crc32

##########################################
#
#   CONSTANTS
#
##########################################

CHUNK_LENGTH_LENGTH = 4
CHUNK_TYPE_LENGTH = 4
CHUNK_CRC_LENGTH = 4
CHUNK_DATA_START_OFFSET = 8
FILE_HEADER_LENGTH = 8


##########################################
#
#   AFL Interface
#
##########################################

def init(seed):
    random.seed(seed)


def fuzz(buf, add_buf, max_size):
    mutated_buf = bytearray(buf)

    # Get a random chunk
    chunk = png_get_random_chunk(mutated_buf)

    chunk2 = png_get_random_chunk(mutated_buf)

    index = mutated_buf.find(chunk)
    if index == -1:
        return buf

    # Go through chunk data and switch a byte

    #modified_chunk = png_switch_byte_data(chunk)

    # Reconstruct
    #mutated_buf[index:index+len(chunk)] = modified_chunk

    return swap_chunks(chunk, chunk2, mutated_buf)
    #return mutated_buf 
    
##########################################
#
#   Helper functions
#
##########################################

def png_get_random_chunk(buf:bytearray):
    """
        Get a random chunk from buf.

        Args:
        buf (bytearray)

        Returns:
        bytearray: Random Chunk from buf.
    """
    
    #Read length of first chunk
    curr_index = FILE_HEADER_LENGTH
    chunk_length = int.from_bytes(buf[curr_index:curr_index+CHUNK_LENGTH_LENGTH], byteorder="big")

    curr_index = curr_index + chunk_length + CHUNK_CRC_LENGTH + CHUNK_LENGTH_LENGTH + CHUNK_TYPE_LENGTH

    while random.randint(0,1) == 0:
        try:
            chunk_length = int.from_bytes(buf[curr_index:curr_index+CHUNK_LENGTH_LENGTH], byteorder="big")
            curr_index = curr_index + chunk_length + CHUNK_CRC_LENGTH + CHUNK_LENGTH_LENGTH + CHUNK_TYPE_LENGTH
        except:
            return buf
    
    return buf[curr_index-chunk_length-(CHUNK_CRC_LENGTH + CHUNK_LENGTH_LENGTH + CHUNK_TYPE_LENGTH):curr_index]


def randomize_random_data_byte(chunk):
    """
        Replace a random byte in the data section of the chunk with a random byte.

        Args:
        chunk (bytearray)

        Returns:
        bytearray: Chunk with random data byte randomized.
    """
    try:
        #print(f'Staring Chunk is {chunk}')
        chunk_length = int.from_bytes(chunk[:CHUNK_LENGTH_LENGTH], byteorder="big")
        chunk_data = chunk[CHUNK_DATA_START_OFFSET: CHUNK_DATA_START_OFFSET + chunk_length]

        byte_index = random.randint(0, len(chunk_data)-1)
        random_byte = random.randbytes(1)[0]
        chunk[CHUNK_TYPE_LENGTH+CHUNK_LENGTH_LENGTH+byte_index] = random_byte


        # Recalculate CRC
        CRC_data = chunk[CHUNK_LENGTH_LENGTH:chunk_length+CHUNK_TYPE_LENGTH+CHUNK_LENGTH_LENGTH]

        calc = Calculator(Crc32.CRC32, optimized=True)

        crc = calc.checksum(CRC_data)

        chunk[-CHUNK_CRC_LENGTH:] = crc.to_bytes(4, 'big')
        #print(f'End Chunk is {chunk}')


    except Exception as e:
        #print(e)

        pass

    return chunk


def swap_chunks(chunk1:bytearray, chunk2:bytearray, buf:bytearray):
    """
        Swap the position of 2 chunks in buf.

        Args:
        chunk1 (bytearray)
        chunk2 (bytearray)
        buf (bytearray)

        Returns:
        bytearray: The same buf but with the position of the two chunks swapped.
    """
    index1 = buf.find(chunk1)
    index2 = buf.find(chunk2)

    mutated = buf

    mutated[index1:index1+len(chunk1)] = buf[index2:index2+len(chunk2)]

    mutated[index2:index2+len(chunk2)] = buf[index1:index1+len(chunk1)]

    return mutated

