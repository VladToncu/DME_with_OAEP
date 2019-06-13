import hashlib #sha-256
import binascii #Used for coverting between Ascii and binary
import hmac
from random import SystemRandom #Generate secure random numbers
nBits = 64*6;
k0BitsInt = 128;
k1BitsInt = 0;
encoding='utf-8'
e = 64

#Function for transforming a string into bits
def text_to_bits(text, encoding='utf-8', errors='surrogatepass'):
    bits = bin(int(binascii.hexlify(text.encode(encoding, errors)), 16))[2:]
    return bits.zfill(8 * ((len(bits) + 7) // 8))

#Function for transforming a series of bits into text
def text_from_bits(bits, encoding='utf-8', errors='surrogatepass'):
    n = int(bits, 2)
    return int2bytes(n).decode(encoding, errors)

def int2bytes(i):
    hex_string = '%x' % i
    n = len(hex_string)
    return binascii.unhexlify(hex_string.zfill(n + (n & 1)))

F.<t> = GF(2)[]
K.<w> = GF(2^e, name='w', modulus=t^64 + t^4 + t^3 + t + 1)

#Function to transform a string into elements of the finite field
def transf_String_to_Finite(message):
    message_to_encrypt = matrix(K,m*n,1)
    vec = []
    for j in range(0,m*n):
        vec=[]
        for i in range(0,e):
            vec.append(message%10)
            message = message//10
        finiteFieldNum = K(vec)
        message_to_encrypt[j,0] = finiteFieldNum
    return message_to_encrypt

#Function to transform a list of elements from the finite field K into a bit string
def transf_finite_to_String(finiteFieldNum):
    listPol = vector(finiteFieldNum)
    listPol = listPol[::-1]
    bitNum = "";
    for i in listPol:
        bitNum += str(i)
    return bitNum;

#XOR function of a bit string
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

#The padding scheme described in the OAEP+ paper.
def pad(msg):
    #Generating the 2 oracles: G and H
    oracle1 = hashlib.sha256()
    oracle2 = hashlib.sha256()
    
    #Generating a random bit string of length k0
    numRandBits = 0
    while(numRandBits != k0BitsInt):
        test = SystemRandom().getrandbits(k0BitsInt)
        randBitStr = str(bin(test)[2:])
        numRandBits = len(randBitStr)

    global k1BitsInt
    binMsg = text_to_bits(msg)
    zeroPaddedMsg = binMsg
    #This is the new component that OAEP+ brings in addition to OAEP. Instead of padding the message with 0, we pad it with a HMAC(m,rand)
    pad_R = hmac.new(randBitStr,digestmod=hashlib.sha256)
    pad_R.update(zeroPaddedMsg)
    pad_R_oracle = str(bin(int(pad_R.hexdigest(), 16))[2:])
    if len(str(binMsg)) <= (nBits-k0BitsInt):
        k1BitsInt = nBits - k0BitsInt - len(str(binMsg))
        zeroPaddedMsg = binMsg + pad_R_oracle[0:k1BitsInt]

    #Running the first hash function to generate the first part of the padded message
    oracle1.update(randBitStr)
    result_oracle1 = str(bin(int(oracle1.hexdigest(), 16))[2:])
    len_oracle1 = len(result_oracle1)
    result_oracle1 = '0'*(256-len_oracle1) + result_oracle1
    x = xor(zeroPaddedMsg,result_oracle1)
    
    #Running the second hash function to generate the second part of the padded message
    oracle2.update(x.encode(encoding))
    len_oracle2 = len(str(bin(int(oracle2.hexdigest(), 16))[2:]))
    y = xor(str(bin(int(oracle2.hexdigest(), 16))[2:]), randBitStr)

    return x+y

#The unpad scheme described in the OAEP+ paper.
def unpad(msg):
    global k1BitsInt

    #Generating the 2 oracles: G and H
    oracle1 = hashlib.sha256()
    oracle2 = hashlib.sha256()
    #Extracting the 2 parts of the padded message
    x = msg[0:nBits-k0BitsInt]
    y = msg[nBits-k0BitsInt:]

    #Retrieving the random string
    oracle2.update(x.encode(encoding))
    len_oracle2 = len(str(bin(int(oracle2.hexdigest(), 16))[2:]))
    r = xor(y,str(bin(int(oracle2.hexdigest(), 16))[2:]))

    #Retrieving the message+the HMAC
    oracle1.update(r)
    result_oracle1 = str(bin(int(oracle1.hexdigest(), 16))[2:])
    len_oracle1 = len(result_oracle1)
    result_oracle1 = '0'*(256-len_oracle1) + result_oracle1
    msgWith0s = xor(x,result_oracle1)
    
    #Before we return the message, we first have to check to see if the HMAC of the message we retrieved is simillar to the one we sent in the pad function
    normal_message = msgWith0s[0:(nBits-k0BitsInt-k1BitsInt)]
    pad_message = msgWith0s[(nBits-k0BitsInt-k1BitsInt):len(msgWith0s)]
    pad_R = hmac.new(r,digestmod=hashlib.sha256)
    pad_R.update(normal_message)
    pad_R_oracle = str(bin(int(pad_R.hexdigest(), 16))[2:])[0:k1BitsInt]
    if(pad_R_oracle == pad_message):
        return msgWith0s[0:(nBits-k0BitsInt-k1BitsInt)]
    else:
        return text_to_bits("Error padding scheme - message not valid with HMAC")

msg = "haaaaaaaaaaaaaaa"
output_string = pad(msg)
output = int(output_string[::-1])
vec = []
finiteFieldNum = matrix(K,6,1)
for j in range(0,6):
    vec=[]
    for i in range(0,e):
        vec.append(output%10)
        output = output//10
    finiteFieldNum[j,0] = K(vec)
dec_message = ""
for i in range(0,6):
    
    string_from_f = transf_finite_to_String(finiteFieldNum[i][0])
    dec_message = string_from_f + dec_message
    
dec_message = dec_message[::-1]
out = unpad(dec_message)
print text_from_bits(out)









