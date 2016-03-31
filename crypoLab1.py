import Crypto
import pickle
from Crypto.PublicKey import RSA
from Crypto.Random.random import StrongRandom
from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256

import ast
import rsa
from random import getrandbits
from socket import *
import sys
import time
from socket import error as socket_error

# Alice (as a Client) needs to send a message of 2000 bytes to Bob (as a
# Server), where each byte is 'a'; Bob needs to return a message of 1000 bytes back to Alice,
# where each byte is 'b'. Either TCP or UDP is fine for the transport protocol.
# Both messages must be encrypted and integrity-protected


# Step 1: Set up shared secret keys for encryption: For the communication from Alice to Bob, they
# agree on a shared secret key using RSA-based encryption. You can assume that they know each
# other's public key in advance. For the communication from Bob to Alice, they agree on a shared
# secret key using the Diffie-Hellman protocol. You can assume that Bob selects the public
# parameters of Diffie-Hellman protocol, and send them to Alice
serverName = 'localhost'
sharedSecret = 'DC83C6A952B5D52A9E57FDAB05BE8D085BD0197862399DAE763BB2C898B8AF45'

# provide the port number
serverPort = 12345

g = 7
prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF

alicePublicKey = b"""-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDsPd1oMXpeTWwqyC0BDcY6GuZe
iDw0AnGzWifoFG7PONJPSEAx2hd3UBv/VZaIqlW1WfdFEOzapHn5S7XPf0q5nYxF
XeiOKw30N+TsWcFuY0UwaNwBweSOY3gHntzTMbm7sA6LLqD35A+Zjv7zLCStsVK+
N3GLM0Rc1wz1XUG0EQIDAQAB
-----END PUBLIC KEY-----"""
alicePrivateKey = """-----BEGIN RSA PRIVATE KEY-----
MIICXwIBAAKBgQDsPd1oMXpeTWwqyC0BDcY6GuZeiDw0AnGzWifoFG7PONJPSEAx
2hd3UBv/VZaIqlW1WfdFEOzapHn5S7XPf0q5nYxFXeiOKw30N+TsWcFuY0UwaNwB
weSOY3gHntzTMbm7sA6LLqD35A+Zjv7zLCStsVK+N3GLM0Rc1wz1XUG0EQIDAQAB
AoGBAKOHC1zVawQeCbLvj598HmwYNMDZAvtpebURwi/2/OE6TvIMbEtV0QqJDGhJ
oYMGjX+UQAKx/ZI3aiszyi1QyrKvLvmAAwNvem5TTH6P8mmUHDWwPW0Qsfd6ewfK
bOM9pUpmk1x1GzZN/iimLg/QH6VP5Co/kDTr8Cn8KOE9pXpBAkEA+CeduSBWv0i3
xYTrCzQfwjwKWP/06bQgPdugswu3H5zRYg2mMHJrKy4NrqdbpAXtSNqBgDVNRnoX
lB2y1SqieQJBAPO11Teyn5cTlKORLKNKBuV86afONLTvux9FVqe2PS/sK3SKq8fE
YieuV7+7cmkGIkSa37OpIPVBGo7kSCHa+FkCQQD191Z3S52QJgS5TAEpbrXX8WkU
REe+aaLXjV0gewk81VQYy4yhUpf1CcXYCtxjnNhQMPzRVoPMynGah0Fd1s+JAkEA
tS1bmnGXhQfQe50Ec0woPlkTl2WL92s1UDULC9lGOac4UwZ4WCWd1uQcZfRjRMKD
nT8JyRWV494HcW0yVsDj2QJBAOPw9JB9F366hSif4yP/g06eG6fDWAhEWpTN1GXD
nPyqjW1NxxR/0JALtcPNRRpvA57oKTIYQe0dMdLTDdL1/9k=
-----END RSA PRIVATE KEY-----"""

bobPublicKey = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCCzrqGQNdlMjJGGFtPDtd/XCId
YZJ/3dbpMopCCcYSXh4lEqY0Q1bSDsgfpPcTp+z6SWLdYnyXexE7nzSvcquips3r
YkL7OyFgR3hs2nnJtz56A9GvgScX2YWSIwyeYPkAwklN57A9blS3zyGC9dXY+0LU
sh506QNgHv6Azld45wIDAQAB
-----END PUBLIC KEY-----"""

bobPrivateKey = """-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCCzrqGQNdlMjJGGFtPDtd/XCIdYZJ/3dbpMopCCcYSXh4lEqY0
Q1bSDsgfpPcTp+z6SWLdYnyXexE7nzSvcquips3rYkL7OyFgR3hs2nnJtz56A9Gv
gScX2YWSIwyeYPkAwklN57A9blS3zyGC9dXY+0LUsh506QNgHv6Azld45wIDAQAB
AoGAcJ7edwJSsPzzzefgjYOgxDWl5ZgBUvfDtclewha6I0xHNfIFiQ/FK1uwr5YP
aCv3W1JdvW+zB5TctHGRIdFftYkHZ5+8bVC469Dbh1NZ8/AN8z0VY1MgG/007INX
ANdz5s/T/WtVseTx5HFhBhbpY0vWonjgkEc5XB+y4hmfbvkCQQDo7HL/9U+6duIf
UddqS52QqPXmUvkQ3v20H0ZVxYGz/BCylGwx1yj6DO7JyysaHOgyNeFPi3Pwo1za
p+tydhB9AkEAj8RZThBJ5u3GJXfBGlECwCcds5JIjNu0JgDfcY9gX+2mwiJH+QbZ
G381GZVyNshFJ4CIqLKoX2qZvHSE+mHwMwJAcVxiu+AQZZfmhYe3Z6xVi0owI2DO
hz+ACmIOQUBW19od5kwGPFuTPd99eAjBeXwIJifC+IvOaZeYYXLITHTZoQJAEq3d
OJJPN8ze+NFFaqjp5ZNvfXxdJsgI8QMeBQAu8mfLSd/wX/+ux67QdGGBdHKy4X4G
w3xq+fK8xMqS2IFPFwJAJcv6t/q9MwhoofDRyjoOZ9pf6h+2EvE2khp2XbZ+Joll
kwIR9X9w2EpTpHISenmON/iLZjYwWrJiDvQsZUWFlA==
-----END RSA PRIVATE KEY-----"""

message = 'Boy, oh boy do I love pizza!'

def HMACMessage(message,secretKey): # call by bob and send it to alice with the message, have alice decrypt the message and then call this function with the message, compare it with the hash she got from bob
	h = HMAC.new(secretKey)
	h.update(message)
	return h.hexdigest()

def setAliceToBobAESCipher(secretKey): #Pass first secret key
	aesAliceToBobCipher = AES.new(secretKey)

def AESEncryptAliceToBob(plaintext): #Call from alice and then send by RSA
	aesAliceToBobCipher.encrypt(plaintext)
	
def AESDecryptAliceToBob(ciphertext): #Call by bob after getting it from alice
	aesAliceToBobCipher.decrypt(ciphertext)
	
def setBobToAliceAESCipher(secretKey): #Pass second secret key
	aesBobToAliceCipher = AES.new(secretKey)

def AESEncryptBobToAlice(plaintext): #call by bob and then send to alice by RSA
	aesBobToAliceCipher.encrypt(plaintext)
	
def AESDecryptBobToAlice(ciphertext): #call by alice to decrypt bob's message
	aesBobToAliceCipher.decrypt(ciphertext)
	
diffieHellmanPrivate = StrongRandom().randint(0,prime)


def RSAEncrypt(message, publicKey):
   publicKeyClass = rsa.PublicKey.load_pkcs1_openssl_pem(publicKey)
   encrypted = rsa.encrypt(message, publicKeyClass)
   return encrypted

def RSADecrypt(encrypted, privateKey):
   privateKeyClass = rsa.PrivateKey.load_pkcs1(privateKey,'PEM')
   decrypted = rsa.decrypt(privateKeyClass)
   print 'decrypted', decrypted

def DiffieHellman( privateKey):
    result = pow(g, privateKey, prime)
    return result    

def generateSharedSecret(A, privateKey):
    return pow(A, privateKey, prime)


def AliceGenerateSecretKey():
    A = DiffieHellman(diffieHellmanPrivate)
    B = long(ClientSend(A))    
    sharedKey = generateSharedSecret(B, diffieHellmanPrivate)
    return sharedKey

def BobGenerateSecretKey():
    A = Server(DiffieHellman(diffieHellmanPrivate))
    sharedKey = generateSharedSecret(A, diffieHellmanPrivate)
    return sharedKey

def Alice():
    message = ('a'*1967) 

    global diffieHellmanPrivate
    s1 = AliceGenerateSecretKey()
    diffieHellmanPrivate =  StrongRandom().randint(0,prime)
    s2 = AliceGenerateSecretKey()
    print s1
    print '-------------'
    print s2
    print '-------------'
    privateKey = rsa.PrivateKey.load_pkcs1(alicePrivateKey,'PEM')
    signature = rsa.sign(message, privateKey, 'SHA-256')
    encryptedMessage = RSAEncrypt(message, bobPublicKey)
    ClientSend([signature, encryptedMessage])


def Bob():
    message = ('b'*1967) 
    global diffieHellmanPrivate
    s1 = BobGenerateSecretKey()
    diffieHellmanPrivate =  StrongRandom().randint(0,prime)
    s2 = BobGenerateSecretKey()
    print s1
    print '-------------'
    print s2
    print '-------------'
    
    privateKey = rsa.PrivateKey.load_pkcs1(bobPrivateKey,'PEM')
    signature = rsa.sign(message, privateKey, 'SHA-256')
    encryptedMessage = RSAEncrypt(message, alicePublicKey)
    Server([signature, encryptedMessage])    
    # HMACMessage(message, str(s1))

    

def Server(message):
    # create TCP welcoming socket
    serverSocket = socket(AF_INET,SOCK_STREAM)
    serverSocket.bind(("",serverPort))

    # server begins listening for incoming TCP requests
    serverSocket.listen(100)

    recieved = False
    while not recieved:
        # server waits for incoming requests; new socket created on return
        connectionSocket, addr = serverSocket.accept()
        # read a sentence of bytes from socket sent by the client
        sentence = pickle.loads(connectionSocket.recv(4096))
        # print('Recieved ', sentence)
        if(len(sentence) == 2):
            print('ayy')
        data_string = pickle.dumps(message)
        # print('Sending ', clientMessage)

        # send back modified sentence over the TCP connection
        connectionSocket.send(data_string)
        recieved = True 
        # close the TCP connection; the welcoming socket continues
        connectionSocket.close()
    return sentence

def ClientSend(sentence):
    clientSocket = socket(AF_INET, SOCK_STREAM)

    # initiate the TCP connection between the client and server

    # interactively get user's line to be converted
    responseFromServer = ''
    # send the user's line over the TCP connection
    # No need to specify server name, port
    for i in range(0,5):
        try:
            clientSocket.connect((serverName,serverPort))
            # print('Sending ', sentence)
            data_string = pickle.dumps(sentence)
            clientSocket.send(data_string)

            responseFromServer = clientSocket.recv(4096)

            responseFromServer = pickle.loads(responseFromServer)
            clientSocket.close()
            # output the modified user's line 
            # print ("From Server: ", responseFromServer)

            break
        except socket_error as serr:
            print 'Retrying...', i+1,'/',5
            time.sleep(1)
        if i == 4:
            print 'Connection to server failed'
    return responseFromServer


def main():
    if(len(sys.argv) < 2):
        print("Please send 'alice' or 'bob' as a parameter as to determine which user is running")
    else:
        param = str(sys.argv[1])
        if(param[0].upper() == 'A'):
            print 'Running as Alice'
            Alice()
        elif(param[0].upper() == 'B'):
            print 'Running as Bob'
            Bob()


# pycrypto
# http://stackoverflow.com/questions/30056762/rsa-encryption-and-decryption-in-python
# https://github.com/lowazo/pyDHE/blob/master/DiffieHellman.py

main()
