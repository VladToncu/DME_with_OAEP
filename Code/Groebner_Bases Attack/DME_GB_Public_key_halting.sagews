#Setting up the parameters of DME
e = 2;
n = 2;
m = 3;
s = 2;
t = 2;
b = 2;

#Computing the number of monomials that will be generated
mon = (b * n^s)^t
mon2 = b * n^s

#F_q is F_2/{irreducible element in F_2}
F.<r> = GF(2)[];

for p in F.polynomials(e):
    if p.is_irreducible():
        break;

K.<q> = GF(2^e, name='q', modulus=p);

#Zn and Zm is used to generate the elements of matrices A and B
Zn = Integers(2^(e*n)-1);
Zm = Integers(2^(e*m)-1);

R = PolynomialRing(K,'X');
R.inject_variables();

'''
pt_sec2pub is the matrix which contains the 64 plaintext that are used to generate the public key.
M1 is a 64x64 matrix which contains the first 64 monomials of the 64 plaintexts, generated by the function compute_monomials_for_public_key.
M2 is a 64x64 matrix which contains the last 64 monomials of the 64 plaintexts, generated by the function compute_monomials_for_public_key.
M1inv and M2inv are the inverses of M1, respectively M2, which are used to generate the public key.
'''
M1 = matrix(K,mon,mon);
M2 = matrix(K,mon,mon);
M1inv = matrix(K,mon,mon);
M2inv = matrix(K,mon,mon);
pt_sec2pub = matrix(K,mon,m*n);

#Find irreducible polynomial of degree n for F_(q^n) in G1
while True:
    IPn = X^n;
    for i in range(0,n):
        a = K.random_element();
        IPn += a * X^(n-1-i);
    if IPn.is_irreducible():
        break;

#Find irreducible polynomial of degree m for F_(q^m) in G2
while True:
    IPm = X^m;
    for i in range(0,m):
        a = K.random_element();
        IPm += a * X^(m-1-i);
    if IPm.is_irreducible():
        break;

Rm = PolynomialRing(K,'XXX').quotient(IPm);
Rm.inject_variables();

Rn = PolynomialRing(K,'XX').quotient(IPn);
Rn.inject_variables();

#Generate matrix for L1
while(True):
    L1 = matrix(K,m*n,m*n);
    for i in range(0,m*n):
        for j in range(n*(i//n),n*(i//n)+n):
            L1[i,j] = K.random_element();
    if L1.is_invertible():
        break;

#Apply L1
def applyL1(x):
    return L1*x;

#Generate matrix for L2
while(True):
    L2 = matrix(K,m*n,m*n);
    for i in range(0,m*n):
        for j in range(m*(i//m),m*(i//m)+m):
            L2[i,j] = K.random_element();
    if L2.is_invertible():
        break;

#Apply L2
def applyL2(x):
    return L2*x;

#Generate matrix for L3
while(True):
    L3 = matrix(K,m*n,m*n);
    for i in range(0,m*n):
        for j in range(m*(i//m),m*(i//m)+m):
            L3[i,j] = K.random_element();
    if L3.is_invertible():
        break;

#Apply L3
def applyL3(x):
    return L3*x;

#Constructing matrix A using random elements in Zn, which only allows maximum of s elements per rows to be non-zero
A = matrix(Zn,m,m);
Aex = matrix(ZZ,m,m);
Ainv = matrix(Zn,m,m);
def generateA():
    global A
    global Aex
    global Ainv
    while True:
        for i in range(0,m):
            for j in range(0,m):
                if(j != m-1-i):
                    testrand = ZZ.random_element(0,n*e)
                    A[i,j] = 2^testrand;
                    Aex[i,j] = testrand
                else:
                    A[i,j] = 0;
        detA = A.determinant();
        if gcd(detA,2^(e*n)-1) == 1:
                break;
    Ainv = A.inverse()

#Constructing matrix B using random elements in Zm, which only allows maximum of t elements per rows to be non-zero
B = matrix(Zm,n,n);
Bex = matrix(ZZ,n,n);
Binv = matrix(Zm,n,n);

def generateB():
    global B
    global Binv
    while True:
        for i in range(0,n):
            counterZero = 0
            counterNon = 0
            for j in range(0,n):
                testrand = ZZ.random_element(0,m*e)
                B[i,j] = 2^testrand;
                Bex[i,j] = testrand;
        detB = B.determinant();
        if gcd(detB,2^(e*m)-1) == 1:
                break;
    Binv = B.inverse()

#We generate matrices A and B.
generateA()
generateB()

#Apply G1
def G1(x):

    y = matrix(K,m*n,1);
    vec = matrix(Rn,m,1);
    result = matrix(Rn,m,1);

    for i in range(0,m):
        for j in range(0,n):
            vec[i] += XXbar^(n-1-j) * x[i*n+j];

	#Raising the polynomials to an elements of A will give another polynomial of degree 1 because the polynomial ring that contains them is modulus a polynomial of degree n, IPn.
    for i in range(0,m):
        result[i] = 1
        for j in range(0,m):
            if(A[i][j] != 0):
                result[i]  *=  (vec[j])[0]^(A[i][j]).lift();
    for i in range(0,m):
        for j in range(0,n):
            y[i*n+j] = ((result[i])[0])[n-1-j];

    return y;

#Apply G2
def G2(x):

    y = matrix(K,m*n,1);
    vec = matrix(Rm,n,1);
    result = matrix(Rm,n,1);

    for i in range(0,n):
        for j in range(0,m):
            vec[i] += XXXbar^(m-1-j) * x[i*m+j];

	#Raising the polynomials to an elements of A will give another polynomial of degree 1 because the polynomial ring that contains them is modulus a polynomial of degree m, IPm.
    for i in range(0,n):
        result[i] = 1
        for j in range(0,n):
            if(B[i][j] != 0):
                result[i]  *=  (vec[j])[0]^(B[i][j]).lift();
    for i in range(0,n):
        for j in range(0,m):
            y[i*m+j] = ((result[i])[0])[m-1-j];

    return y;

#Encrypt with secret key
def encrypt_with_secret_key(x):

    #Apply L1
    afterL1 = applyL1(x);

    #Apply G1
    afterG1 = G1(afterL1);

    #Apply L2
    afterL2 = applyL2(afterG1);

    #Apply G2
    afterG2 = G2(afterL2);

    #Apply L3
    encrypted = applyL3(afterG2);

    return encrypted;


#Apply inverse of L3
def inverseL3(x):
    return L3.inverse()*x;

#Apply inverse of L2
def inverseL2(x):
    return L2.inverse()*x;

#Apply inverse of L1
def inverseL1(x):
    return L1.inverse()*x;

#Apply inverse of G2
def inverseG2(x):

    y = matrix(K,m*n,1);
    vec = matrix(Rm,n,1);
    result = matrix(Rm,n,1);
    for i in range(0,n):
        for j in range(0,m):
            vec[i] += XXXbar^(m-1-j) * x[i*m+j];

	#Raising the polynomials to an elements of A will give another polynomial of degree 1 because the polynomial ring that contains them is modulus a polynomial of degree n, IPn.
    for i in range(0,n):
        result[i] = 1
        for j in range(0,n):
            if(Binv[i][j] != 0):
                result[i]  *=  (vec[j])[0]^(Binv[i][j]).lift();
    for i in range(0,n):
        for j in range(0,m):
            y[i*m+j] = ((result[i])[0])[m-1-j];

    return y;

#Apply inverse of G1
def inverseG1(x):

    y = matrix(K,m*n,1);
    vec = matrix(Rn,m,1);
    result = matrix(Rn,m,1);

    for i in range(0,m):
        for j in range(0,n):
            vec[i] += XXbar^(n-1-j) * x[i*n+j];

	#Raising the polynomials to an elements of A will give another polynomial of degree 1 because the polynomial ring that contains them is modulus a polynomial of degree m, IPm.
    for i in range(0,m):
        result[i] = 1
        for j in range(0,m):
            if(Ainv[i][j] != 0):
                result[i]  *=  (vec[j])[0]^(Ainv[i][j]).lift();
    for i in range(0,m):
        for j in range(0,n):
            y[i*n+j] = ((result[i])[0])[n-1-j];

    return y;

#Encrypt with secret key
def decrypt_with_secret_key(x):

    #Apply L3_decrypt
    afterL3Decrypt = inverseL3(x);

    #Apply G2_decrypt
    afterG2Decrypt = inverseG2(afterL3Decrypt);

    #Apply L2_decrypt
    afterL2Decrypt = inverseL2(afterG2Decrypt);

    #Apply G1_decrypt
    afterG1Decrypt = inverseG1(afterL2Decrypt);

    #Apply L1_decrypt
    decrypted = inverseL1(afterG1Decrypt);

    return decrypted;

'''
This computes the monomials generated when one applies G1 and G2 to the input. The generation of these monomials work using the following approach:
    For each row of matrix A, we compute s polynomials: 
        The first polynomial will be x_(j*n)*Y_0+x_(j*n+1) raised to the power of the first non-zero element of A in a specific row and j is the column where that A was found. 
        The second polynomial will be x_(j*n)*Y_1+x_(j*n+1) raised to the power of the second non-zero element of A in a specific row and j is the column where that A was found.
        ...
        Do this until you do not have anymore elements non-zero in a row. You multiply these polynomials and get its coefficients (these will be the monomials generated by G1)
    Do the same for matrix B.
'''
def compute_monomials_for_public_key(x):
    row1 = matrix(K,8,1)
    row2 = matrix(K,8,1)
    vector_result = matrix(K,128,1)
    

    row1[0] = x[0][0]^A[0][0].lift() * x[2][0] ^ A[0][1].lift()
    row1[1] = x[1][0]^A[0][0].lift() * x[2][0] ^ A[0][1].lift()
    row1[2] = x[0][0]^A[0][0].lift() * x[3][0] ^ A[0][1].lift()
    row1[3] = x[1][0]^A[0][0].lift() * x[3][0] ^ A[0][1].lift()
    row1[4] = x[0][0]^A[1][0].lift() * x[4][0] ^ A[1][2].lift()
    row1[5] = x[1][0]^A[1][0].lift() * x[4][0] ^ A[1][2].lift()
    row1[6] = x[0][0]^A[1][0].lift() * x[5][0] ^ A[1][2].lift()
    row1[7] = x[1][0]^A[1][0].lift() * x[5][0] ^ A[1][2].lift()
    
    row2[0] = x[0][0]^A[1][0].lift() * x[4][0] ^ A[1][2].lift()
    row2[1] = x[1][0]^A[1][0].lift() * x[4][0] ^ A[1][2].lift()
    row2[2] = x[0][0]^A[1][0].lift() * x[5][0] ^ A[1][2].lift()
    row2[3] = x[1][0]^A[1][0].lift() * x[5][0] ^ A[1][2].lift()
    row2[4] = x[2][0]^A[2][1].lift() * x[4][0] ^ A[2][2].lift()
    row2[5] = x[3][0]^A[2][1].lift() * x[4][0] ^ A[2][2].lift()
    row2[6] = x[2][0]^A[2][1].lift() * x[5][0] ^ A[2][2].lift()
    row2[7] = x[3][0]^A[2][1].lift() * x[5][0] ^ A[2][2].lift()
    
    
    for i in range(0,8):
        for j in range(0,8):
            vector_result[8*i + j] = row1[i][0] ^ B[0][0].lift() * row2[j][0] ^ B[0][1].lift()
            vector_result[8*i + j + 64] = row1[i][0] ^ B[1][0].lift() * row2[j][0] ^ B[1][1].lift()
            
    return vector_result

def compute_monomials_for_public_key_test(x):
    row1 = []
    row2 = []
    vector_result = []

    rowtest = x[0][0]^(2^(Aex[0][0]%e)) * x[2][0] ^ (2^(Aex[0][1]%e))
    row1.append(rowtest)
    rowtest = x[1][0]^(2^(Aex[0][0]%e)) * x[2][0] ^ (2^(Aex[0][1]%e))
    row1.append(rowtest)
    rowtest = x[0][0]^(2^(Aex[0][0]%e)) * x[3][0] ^ (2^(Aex[0][1]%e))
    row1.append(rowtest)
    rowtest = x[1][0]^(2^(Aex[0][0]%e)) * x[3][0] ^ (2^(Aex[0][1]%e))
    row1.append(rowtest)
    rowtest = x[0][0]^(2^(Aex[1][0]%e)) * x[4][0] ^ (2^(Aex[1][2]%e))
    row1.append(rowtest)
    rowtest = x[1][0]^(2^(Aex[1][0]%e)) * x[4][0] ^ (2^(Aex[1][2]%e))
    row1.append(rowtest)
    rowtest = x[0][0]^(2^(Aex[1][0]%e)) * x[5][0] ^ (2^(Aex[1][2]%e))
    row1.append(rowtest)
    rowtest = x[1][0]^(2^(Aex[1][0]%e)) * x[5][0] ^ (2^(Aex[1][2]%e))
    row1.append(rowtest)
    
    rowtest = x[0][0]^(2^(Aex[1][0]%e)) * x[4][0] ^ (2^(Aex[1][2]%e))
    row2.append(rowtest)
    rowtest = x[1][0]^(2^(Aex[1][0]%e)) * x[4][0] ^ (2^(Aex[1][2]%e))
    row2.append(rowtest)
    rowtest = x[0][0]^(2^(Aex[1][0]%e)) * x[5][0] ^ (2^(Aex[1][2]%e))
    row2.append(rowtest)
    rowtest = x[1][0]^(2^(Aex[1][0]%e)) * x[5][0] ^ (2^(Aex[1][2]%e))
    row2.append(rowtest)
    rowtest = x[2][0]^(2^(Aex[2][1]%e)) * x[4][0] ^ (2^(Aex[2][2]%e))
    row2.append(rowtest)
    rowtest = x[3][0]^(2^(Aex[2][1]%e)) * x[4][0] ^ (2^(Aex[2][2]%e))
    row2.append(rowtest)
    rowtest = x[2][0]^(2^(Aex[2][1]%e)) * x[5][0] ^ (2^(Aex[2][2]%e))
    row2.append(rowtest)
    rowtest = x[3][0]^(2^(Aex[2][1]%e)) * x[5][0] ^ (2^(Aex[2][2]%e))
    row2.append(rowtest)

    for i in range(0,8):
        for j in range(0,8):
            rowtest = row1[i] ^ (2^(Bex[0][0]%e)) * row2[j] ^ (2^(Bex[0][1]%e))
            vector_result.append(rowtest)
    
    for i in range(0,8):
        for j in range(0,8):
            rowtest = row1[i] ^ (2^(Bex[1][0]%e)) * row2[j] ^ (2^(Bex[1][1]%e))
            vector_result.append(rowtest)
            
    return vector_result

'''
Encryption of a plaintext with the public key. You generate the public key and multiply it with the monomials of the plaintext you have as an input. 
The monomials are generated by running compute_monomials_for_public_key using the input text as an argument.
'''
def encrypt_with_public_key(x):

    monomials = matrix(K,mon*2,1);
    monomials1 = matrix(K,mon,1);
    monomials2 = matrix(K,mon,1);
    public_key = getPublicKeyFromSecretKey();
    monomials = compute_monomials_for_public_key(x);
    ciphertext = matrix(K,n*m,1);

	# We are splitting the monomials into 2 sections as outlined in the paper: the ones for the first 3 elements in the input and the ones for the last 3 elements.
    for i in range(0,mon):
        monomials1[i] = monomials[i]
        monomials2[i] = monomials[i+mon]

	# Multiply the monomials generated from G1 and G2 with the public key
    cipher_text_1 = public_key[0] * monomials1
    cipher_text_2 = public_key[1] * monomials2
	# Return the ciphertext
    for i in range(0,m):
        ciphertext[i] = cipher_text_1[i];
        ciphertext[i+m] = cipher_text_2[i];

    return ciphertext

'''
Generating the M1 and M2 matrices. The way in which this is done is by running compute_monomials_for_public_key for each plaintext in the pt_sec2pub to generate its monomials
'''
def generateVectors():

    while True:
        for i in range(0,mon):
            for j in range(0,m*n):
                pt_sec2pub[i,j] = K.random_element();
            transp = matrix(pt_sec2pub[i]).transpose();
            vec_transp = compute_monomials_for_public_key(transp);
            for j in range(0,mon):
                M1[j,i] = vec_transp[j][0];
                M2[j,i] = vec_transp[j+mon][0];
        if M1.is_invertible() & M2.is_invertible():
            break;
        else:
            generateA();
            generateB();

'''
Function for getting the public key. For a fast method of doing so, we are going to use the private key as indicated in the paper. 
We are going to encrypt each vector in pt_sec2pub with the secret key and multiply them with the inverses of M1 and M2. The reason is that:

The coefficients of the elements in pt_sec2pub multiplied with the monomials in M1 and M2 will give the encryption with the secret key of the elements in the pt_sec2pub.
The coefficients are the ones that do not depend on which plaintext you use and as a result, they can be used as the public key. As a result, if one multiplies the 
encryption using the secret key with the inverse of the matrices M1 and M2, one can retrieve the coefficients matrix and use it as a public key.
'''
def getPublicKeyFromSecretKey():

    CT1 = matrix(K,m,mon);
    CT2 = matrix(K,m,mon);
    ct = matrix(K,1,m*n);
    generateVectors();

    for i in range(0,mon):
        line =  matrix(pt_sec2pub[i]).transpose()
        ct = encrypt_with_secret_key(line);
        for j in range(0,m):
		# Split the ciphertext in 2 parts given to multiply each with M1 and M2 inverse
            CT1[j,i] = ct[j][0]
            CT2[j,i] = ct[j+m][0]
    return (CT1*M1.inverse(),CT2*M2.inverse())

#Generating the plaintext
test = matrix(K,m*n,1)
for i in range(0,m*n):
    while(test[i,0] == 0):
        test[i,0] = K.random_element()

#We generate a polynomial ring with 6 variables ( the numbers of the element in the input)
Kpol = PolynomialRing(K,'xtest',m*n)
c = Kpol.gens()

#We generate the monomials that would be constructed using the 6 variables (my_attack_vars). Also, we generate the monomials that are constructed using the input, in order to compare with the ones from the 6 variables.
vec_test = matrix(Kpol,m*n,1)
for i in range(0,m*n):
    vec_test[i,0] = c[i]
monoms_for_pt = compute_monomials_for_public_key(test)

my_attack_vars = compute_monomials_for_public_key_test(vec_test)
my_att_var = matrix(Kpol,mon*2,1)

#If my_att_var gives us monoms_for_pt, then we know we have the correct system. We replace the mn variables with the mn input
for i in range(0,mon*2):
    my_att_var[i,0] = my_attack_vars[i]

mydict=[]
for i in range(0,m*n):
    mydict.append({c[i]:test[i][0]})
for i in range(0,m*n):
    my_att_var = my_att_var.subs(mydict[i])


for i in range(0,mon*2):
    if(my_att_var.list()[i] != monoms_for_pt.list()[i]):
        print "Fail"

print "We have the correct system"

#Generating the ciphertext
encrypt_pub = encrypt_with_public_key(test)

#Getting the 1st part of the public key in order to get the first 64 monomials using Groebner bases attack
#Getting the 2nd part of the public key in order to get the last 64 monomials using Groebner bases attack
F_generated_1 = getPublicKeyFromSecretKey()[0]
F_generated_2 = getPublicKeyFromSecretKey()[1]

#Create F1, F2, F3,.. Fmn
row = matrix(Kpol,m*n,1)
for i in range(0,m):
    for j in range(0,mon):
        row[i,0] += F_generated_1[i,j]*my_attack_vars[j]
        row[i+m,0] += F_generated_2[i,j]*my_attack_vars[j+mon]

#Generating the polynomial system to test against F4 algorithm
for i in range(0,m*n):
    row[i,0] = row[i,0] - Kpol(encrypt_pub[i,0])

#Generating the ideal
vect_ideal = []
for i in range(0, m*n):
    vect_ideal.append(row[i][0])

#Run GB attack using slimgb library
I = Ideal(vect_ideal)

#Run the F4 algorithm
GB = I.groebner_basis(algorithm="libsingular:slimgb")

#Print the Grobner bases generated by F4
print GB









