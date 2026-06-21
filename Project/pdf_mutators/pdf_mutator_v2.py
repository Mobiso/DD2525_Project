import pikepdf
import random
import io
import string
from enum import Enum

##########################################
#
#   CONSTANTS
#
##########################################
class FuzzAction(Enum):
    MODIFY_RANDOM_KEY_TO_RANDOM_TYPE = 0
    DELETE_RANDOM_KEY = 1
    INSERT_RANDOM_OBJECT = 2
    CORRUPT_RANDOM_STREAM = 3


##########################################
#
#   AFL Interface
#
##########################################

def init(seed):
    random.seed(seed)

def fuzz(buf, add_buf, max_size):
    semantic_mutation = True
    keys = None
    streams = None
    out = None
    try:
        pdf = pikepdf.open(io.BytesIO(buf))
        keys = __get_dict_keys(pdf)
        streams = __get_streams(pdf)
        print("Skipping semantic")
    except:
        semantic_mutation = False
    if semantic_mutation:
        obj, key = random.choice(keys)
        obj[key] = __get_random_type()

        obj, key = random.choice(keys)
        del obj[key]
        __make_random_object_and_attach_randomly(pdf)
        for _ in range(0,10):
            stream_obj = random.choice(streams)
            __corrupt_stream(stream_obj)    
        try:
            out = io.BytesIO()
            pdf.save(out)
        except Exception:
            print("Could not save")
    
    if out != None and not len(out.getvalue()) <= 0:
        buf = bytearray(out.getvalue())
    else:
        buf = bytearray(buf)
    #print(f"BUFF BEFORE: {len(buf)}")
    for _ in range(0,1):
        buf = __replace_byte(buf,random.randint(0,len(buf)-1),random.randint(0,255))
    buf = __n_plicate_byte(random.randint(0,10),random.randint(0,len(buf)-1),buf)
    buf = __delete_bytes(random.randint(0,5),buf)
    #print(f"BUFF AFTER: {len(buf)}")
    return buf
    
##########################################
#
#   Helper functions
#
##########################################

def __random_chars(amount):
    return "".join([chr(random.randint(0, 127)) for _ in range(amount)])

def __random_char(amount):
    random_char = chr(random.randint(0,127))
    return "".join([random_char for _ in range(amount)])
def __random_printable_chars(amount):
     return "".join([chr(random.randint(33, 126)) for _ in range(amount)])

def __random_alpha_numerical(amount):
        return "".join([random.choice(string.ascii_letters + string.digits) for _ in range(amount)])


def __get_random_type():
    return random.choice([
        random.randint(-99999, 999999),
        -1,
        pikepdf.String(__random_chars(random.randint(0, 1000))),
        pikepdf.String(__random_char(random.randint(0,1000))),
        pikepdf.Name("/Fuzz"),
        pikepdf.Name("/" + __random_chars(random.randint(1, 1000))),
        pikepdf.Name("/" + __random_char(random.randint(1, 1000))),
        pikepdf.Array([]),
        pikepdf.Array([0]),
        pikepdf.Name("/FlateDecode"),
        pikepdf.Name("/ASCII85Decode"),
        pikepdf.Name("/LZWDecode"),
        pikepdf.Array([
        pikepdf.Name("/ASCII85Decode"),
        pikepdf.Name("/FlateDecode")
        ]),
        random.randbytes(random.randint(0,1000)),
        True,
        False
    ])


def __make_random_object_and_attach_randomly(pdf):
    new_obj = pdf.make_indirect(pikepdf.Dictionary(
    TYPE="/" + __random_chars(random.randint(0,100)),
    DATA=__get_random_type()
))
    targets = __get_dict_keys(pdf)
    key = "/" + __random_alpha_numerical(random.randint(0,100))
    #print(key)
    if targets:
        try:
            obj, _ = random.choice(targets)
            obj[key] = new_obj
        except:
            return
    #print(f"MADE: {new_obj}")
    #print(pdf.objects)

def __get_dict_keys(pdf):
    targets = []
    for objid in range(1, len(pdf.objects) + 1):
        try:
            obj = pdf.get_object(objid, 0)
            if isinstance(obj, pikepdf.Dictionary):
                for key in obj.keys():
                    targets.append((obj, key))
        except Exception:
            pass
    # Also include trailer keys
    for key in pdf.trailer.keys():
        targets.append((pdf.trailer, key))
    return targets

def __get_streams(pdf):
    streams = []
    for objid in range(1, len(pdf.objects) + 1):
        try:
            obj = pdf.get_object(objid, 0)
            if isinstance(obj, pikepdf.Stream):
                streams.append(obj)
        except Exception:
            pass
    return streams

def __corrupt_stream(obj):
    obj.stream_data = __get_random_type()

def __replace_byte(buf,idx,byte):
    modified = buf
    modified[idx] = byte
    return modified
def __n_plicate_byte(amount,idx,buf):
    nplicate_byte = buf[idx]
    modified_buf =  buf[:idx] + bytes(buf[idx]) * amount + buf[idx:]
    return modified_buf
def __delete_bytes(amount,buf):
    for _ in range(0,amount):
        del buf[random.randint(0,len(buf)-1)]
    return buf
    
