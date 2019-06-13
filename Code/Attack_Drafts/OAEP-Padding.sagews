import hashlib #sha-256
import binascii #Used for coverting between Ascii and binary
from random import SystemRandom #Generate secure random numbers
nBits = 64*6;
k0BitsInt = 128;
k1BitsInt = 0;
encoding='utf-8'
e = 64

def text_to_bits(text, encoding='utf-8', errors='surrogatepass'):
    bits = bin(int(binascii.hexlify(text.encode(encoding, errors)), 16))[2:]
    return bits.zfill(8 * ((len(bits) + 7) // 8))

def text_from_bits(bits, encoding='utf-8', errors='surrogatepass'):
    n = int(bits, 2)
    return int2bytes(n).decode(encoding, errors)

def int2bytes(i):
    hex_string = '%x' % i
    n = len(hex_string)
    return binascii.unhexlify(hex_string.zfill(n + (n & 1)))

F.<t> = GF(2)[]
K.<w> = GF(2^e, name='w', modulus=t^64 + t^4 + t^3 + t + 1)

def transf_String_to_Finite(message):
    testbits = text_to_bits(message)
    testint = int(testbits)
    vec = []
    for i in range(0,e):
        vec.append(testint%10)
        testint = testint//10
    finiteFieldNum = K(vec)
    return finiteFieldNum;

def transf_finite_to_String(finiteFieldNum):
    listPol = vector(finiteFieldNum)
    listPol = listPol[::-1]
    bitNum = "";
    for i in listPol:
        bitNum += str(i)
    return bitNum;

def xor(a,b):
    a = map(int,list(a))
    b = map(int,list(b))
    leng_xor = len(a)
    stre = ""
    if(len(a)>len(b)):
        leng_xor = len(b)
    for i in range(0,leng_xor):
        stre += str((a[i]+b[i])%2)
    return stre



def pad(msg):
    oracle1 = hashlib.sha256()
    oracle2 = hashlib.sha256()
    print oracle1.digest_size
    numRandBits = 0
    while(numRandBits != k0BitsInt):
        test = SystemRandom().getrandbits(k0BitsInt)
        randBitStr = str(bin(test)[2:])
        numRandBits = len(randBitStr)
    global k1BitsInt
    binMsg = text_to_bits(msg)
    zeroPaddedMsg = binMsg
    if len(str(binMsg)) <= (nBits-k0BitsInt):
        k1BitsInt = nBits - k0BitsInt - len(str(binMsg))
        zeroPaddedMsg = binMsg + ('0'*k1BitsInt)

    oracle1.update(randBitStr)
    result_oracle1 = str(bin(int(oracle1.hexdigest(), 16))[2:])
    len_oracle1 = len(result_oracle1)
    result_oracle1 = '0'*(256-len_oracle1) + result_oracle1
    x = xor(zeroPaddedMsg,result_oracle1)
    print len(x)

    oracle2.update(x.encode(encoding))
    len_oracle2 = len(str(bin(int(oracle2.hexdigest(), 16))[2:]))
    y = xor(str(bin(int(oracle2.hexdigest(), 16))[2:]), randBitStr)
    print len(y)
    return x+y

def unpad(msg):
    global k1BitsInt
    oracle1 = hashlib.sha256()
    oracle2 = hashlib.sha256()
    x = msg[0:nBits-k0BitsInt]
    y = msg[nBits-k0BitsInt:]

    oracle2.update(x.encode(encoding))
    len_oracle2 = len(str(bin(int(oracle2.hexdigest(), 16))[2:]))
    r = xor(y,str(bin(int(oracle2.hexdigest(), 16))[2:]))

    oracle1.update(r)
    result_oracle1 = str(bin(int(oracle1.hexdigest(), 16))[2:])
    len_oracle1 = len(result_oracle1)
    result_oracle1 = '0'*(256-len_oracle1) + result_oracle1
    msgWith0s = xor(x,result_oracle1)

    return msgWith0s[0:(nBits-k0BitsInt-k1BitsInt)]

msg = "haa"
output_string = pad(msg)
print len(output_string)
output = int(output_string[::-1])
vec = []
finiteFieldNum = matrix(K,6,1)
for j in range(0,6):
    vec=[]
    for i in range(0,e):
        vec.append(output%10)
        output = output//10
    finiteFieldNum[j,0] = K(vec)
    print finiteFieldNum[j,0]
dec_message = ""
for i in range(0,6):
    
    string_from_f = transf_finite_to_String(finiteFieldNum[i][0])
    dec_message = string_from_f + dec_message
    
dec_message = dec_message[::-1]
out = unpad(dec_message)
print text_from_bits(out)









