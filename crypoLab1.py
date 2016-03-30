import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
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
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAi17GtUa/HzNlrEsG80rv
UBN9AXATAeqAe2GBsmHn4DAEgKXKa/qKeprbD0oliFnjKtQv7RqlBBd0kAbWlfLA
wHvaDnonaqSu/aVN8o08kvxwbs69WOz9lA82SUTnyFaakDiqI+EgeAzLAP8Urvme
OBXmjzFp4FQdXlcYamCzD+nfrG6Z4sSH3JJU3bJdXON00EYFXVpKwZJ+xT7bbr7b
VCM+2EFac1INEDjZF2ERr950LZ+1HYGGZ7SqLOej0mPBQI3X9SS+eGa256T0wZfz
lZJUVWDBvw4DCSXnlhbw5pA9c13qrg0aesAh0h5cDT4tnUULhe2ahD3ZpI5ijwLx
xQIDAQAB
-----END PUBLIC KEY-----"""
alicePrivateKey = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAi17GtUa/HzNlrEsG80rvUBN9AXATAeqAe2GBsmHn4DAEgKXK
a/qKeprbD0oliFnjKtQv7RqlBBd0kAbWlfLAwHvaDnonaqSu/aVN8o08kvxwbs69
WOz9lA82SUTnyFaakDiqI+EgeAzLAP8UrvmeOBXmjzFp4FQdXlcYamCzD+nfrG6Z
4sSH3JJU3bJdXON00EYFXVpKwZJ+xT7bbr7bVCM+2EFac1INEDjZF2ERr950LZ+1
HYGGZ7SqLOej0mPBQI3X9SS+eGa256T0wZfzlZJUVWDBvw4DCSXnlhbw5pA9c13q
rg0aesAh0h5cDT4tnUULhe2ahD3ZpI5ijwLxxQIDAQABAoIBACkZM8O1LxsGTw81
uMD58gRNGunXoONJwcWghVyTHouv3UQKn9yjrz5keADUPqksyJ6Sn+dtmgfQ2uC2
A4WIZmrcmvr17rW2BpxpqMjD+X7mzkj+0jts94I30ixdE3SyhTXOX+3gr3B3ZU3P
6suGdK/ZVXoYej5az6ZITLzh8yvXu14ApAGJ4I8Jf8QRsp4fgr1OMS+FNOgePTr3
Sk28fbYxI8Tr5BeSBgXdHXFD2VBZ6jlo7q2peRfvF9FcvXcpA6L7xqrjLChPH60i
053rYZ5nKubaUR1+TfMbBhuMNdYZEeMF5n60lIE0UtMlfu2hsFpEgpdM7GL57oon
Ht/2kUECgYEA7lgQYV008gBFQn0dBkGA0xyO8q1pVYM/6J4fUTkHSQDVTN3JtKbb
M3+K2gEQRVAJKp89OA7DXre6niB2Tiz/HIvZM45BnvVsg/hsdeBlm8s4ZCV72+SU
OF4+etQhSSsgP6V5+SyR0LloBCzZD+G7bcE1BGja2mtkx2w1N7eDc6kCgYEAlbHI
Ff/M3KnpNbKqSXcuYFwk4RHu1Tj7fJ/RSjCKWw1nuSaHh6gxrrpPsPRw0gqJWfAM
Yr4LL6Sipoxy1WwVNRd6hYdsKBNfZtSWuHcUaYRYzulvAVsAAvj97XqH4I4fbU+u
dfY4nb2ErSM9YA0WvQ1NIqRg4b6HnLkv9Rma3r0CgYEA0oa28UmDGr9ibfhVStFR
GSiAm5rRD9d++9mvj+7voGw7/ElrgUZhGHvwCeAmnxKzBhLh4EIqD9/51vKVjTfx
nyVoFUHydJYT4/3qz7QGDDbU+KCjZvfgdGnKhnQZcqfFNHLV6mKT6enbFtUGZiDd
jXS7f8meho+V1RCfcTeHxQECgYAAksS8aNVlBvWQshV64Iz564BsqD/s6yHzcT1A
9nyhKqT6DY65U0iVbbs+Z0FDXKz3/jZd7nJmhU/mKWWLMbXHFUbv2fvtD13vK+ND
45jdapdYe4ZkT+/pEwEN9sksb/7o0UROyVmgKQioDRmAE6zBnppsBoskcjFcxUzM
uINiVQKBgQCJ4E+RjLr8RAe2W8RHSag/IokYmIkaq4zTRfQAifEwwooL7D6Wz3tu
onsfFKjHKNWIFWQRPE9qJ/b0uOAt0WgcNoCGFRF8EYQuR1LeJqOeHgGshJBCJwJ9
IBhuDy7AxMJq8uur4RblTrW+FlRV0eddayNcHgE2J3wV70XnZY3g5g==
-----END RSA PRIVATE KEY-----"""

bobPublicKey = """-----BEGIN PUBLIC KEY-----
MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQB9pnXXsOmsK52QN3NXXuwo
4kKBWzHq9YerhP7oXECBKLv8u5gP6xM+bNnXAleCiiX1nmqWrxNAGKdKn664i12g
wVozO8f3+Z3VBtZ9gEwiG2W8vctLz0Ktc+pCX5gf4vPBQaxZiVKbVDB4LjCjGSDw
v6++Y+4a/AuiaOO913lHuuIjvMKr7cATjdqX9IoHmJEHGbRZ9eJ1QNWwb6U94XP1
bslVUBr8A/ck0A8jyOrIM7ICZpFISR42CXMw2AVB0RDln/TyKfm8Wf+CqJEO7zmm
wNPOszi66Wsq0uIoVpmNYlM4HQofE54rjUdDIqE4JWSqtKTaPz4644LS9fcho2gj
AgMBAAE=
-----END PUBLIC KEY-----"""

bobPrivateKey = """-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQB9pnXXsOmsK52QN3NXXuwo4kKBWzHq9YerhP7oXECBKLv8u5gP
6xM+bNnXAleCiiX1nmqWrxNAGKdKn664i12gwVozO8f3+Z3VBtZ9gEwiG2W8vctL
z0Ktc+pCX5gf4vPBQaxZiVKbVDB4LjCjGSDwv6++Y+4a/AuiaOO913lHuuIjvMKr
7cATjdqX9IoHmJEHGbRZ9eJ1QNWwb6U94XP1bslVUBr8A/ck0A8jyOrIM7ICZpFI
SR42CXMw2AVB0RDln/TyKfm8Wf+CqJEO7zmmwNPOszi66Wsq0uIoVpmNYlM4HQof
E54rjUdDIqE4JWSqtKTaPz4644LS9fcho2gjAgMBAAECggEAKBTzvox23i9Dof+u
UY68MwaKRI18zQDp+HMChcj34rvFzAdjqKBKkT1T+FyM4d2D4mhYhBzxPR8gLpPl
voTmpyNGzNUjIx2DlbMKtRo6Lx8iQyUgNty03nP9pJKuCm3xaBK1EhLWQSqIE65Y
YY7gjSv4uflSuVTxuStQivyzeYfV2Pgmyve5bReLTOznyqqpNkcQATvcPfgs7qTR
3V6dBKEdrppPFkUCiuUE/8O/6Xi+enchkkgsQlzVzbV9TjRvWjjDiKywqTf4vMUa
VAxoaQEf0vLwnCny0WQvjvQ0B+LFqHtYR1oPeMQkWbJtMYJ699XBZZ9csR78NyZM
M66OIQKBgQDWoxnlkxFpP6SJlhgeQnsbfVTjgaFsY1+ZPDHHrZgT55QA8xACmo9k
1uVov/hOd5U89pD2dBnjdMygK4JaDOoZ8VWOdTbuVs95XQfCNinlhkiBvTQekVdE
go11d5T5uTsEcKbvuYKBJbwJyFz9joKaXu78oJEiH+iO7quL3OqRCwKBgQCV3Ui3
fYj+L7b1gTWhoUeiJgPsr+wQdeTsVdoVq1GAV4uNSp34rsugJIhraDCFCK6fIXbf
8s0EAwfGkq2s7LtNqteK41E4C0kcN1Y4gm65bVO++h+FWBid4rGDrFOTfACLc5Gf
B3hLWUk0sH6t4ED+VahNZbq39R8usSXpWJ+kSQKBgQCp23lrDPACcrMrjvSXPdVe
89hyEuxEcn/9LH3Yn7ByUBn4hmJtLRO9obL7KrC+qDQagqZF46t5Lb2iI8yMpxu8
XBhxHKHUDC80xEKXl3Wghpxqz+inKC3/sbFw/KmQ1t21rdDudcipm8srkrzEjDsf
H3HRyuAQOWA5fPeVP8cB8QKBgCCfTMb0gq+iP1dtyvjmHKvFTrFlEiP7Jdv0TEbP
RiyD4hLdnUmW8yhnC3Ml+Pnci/aD2FajidFHv5eQMlIkLhmYCNdo6DMk8cM8oH4o
lmWy0LoPxHDIXoNv52hcSM0f/xZcD+ToQV1VkEPx74F2AW/bwYknjd+hcio90Zzb
99RRAoGARTASeq+YiAPyzJg9jXagL0+I+zfa+Dla7Pz/iJy516QAjQH4xAIsPXsF
G9XqxvevbfX0hjjPJfV6qsSofL4BpnfnmjitbGGVV6KDegLtDsbANsp1n/ov9y3n
rYxlTsFckzKCbA44pTMQuiKdWkcUE3vaKN18YPWYXC43XQK4f1s=
-----END RSA PRIVATE KEY-----"""

message = 'Boy, oh boy do I love pizza!'


def RSAEncrypt(message, publicKey):
   publicKeyClass = rsa.PublicKey.load_pkcs1_openssl_pem(publicKey)
   encrypted = rsa.encrypt(message, publicKeyClass)
   return encrypted

def RSADecrypt(encrypted, privateKey):
   privateKeyClass = rsa.PrivateKey.load_pkcs1(privateKey,'PEM')
   decrypted = rsa.decrypt(privateKeyClass)
   print 'decrypted', decrypted

def DiffieHellmanAlice():
    a = rsa.PrivateKey.load_pkcs1(alicePrivateKey).n
    A = pow(g, a, prime)
    B = long(Alice(A))
    s2 = pow(B, a, prime)
    
    print '-------------------------------'
    print ''
    print s2
    print ''
    print '-------------------------------'
    
def DiffieHellmanBob(A):
    b = rsa.PrivateKey.load_pkcs1(bobPrivateKey).n
    B = pow(g, b, prime)
    s1 = pow(A, b, prime)
    print '-------------------------------'
    print ''
    print s1
    print ''
    print '-------------------------------'
    return B


def Bob():
    # create TCP welcoming socket
    serverSocket = socket(AF_INET,SOCK_STREAM)
    serverSocket.bind(("",serverPort))

    # server begins listening for incoming TCP requests
    serverSocket.listen(100)

    recieved = False
    while not recieved:
        # server waits for incoming requests; new socket created on return
        connectionSocket, addr = serverSocket.accept()
        print addr 
        # read a sentence of bytes from socket sent by the client
        sentence = long(connectionSocket.recv(2048))
        # print('Recieved ', sentence)
        clientMessage = DiffieHellmanBob(sentence)
        # print('Sending ', clientMessage)

        # send back modified sentence over the TCP connection
        connectionSocket.send(bytes(clientMessage))
        # recieved = True 
        # close the TCP connection; the welcoming socket continues
        connectionSocket.close()
    return clientMessage

def Alice(sentence):
    clientSocket = socket(AF_INET, SOCK_STREAM)

    # initiate the TCP connection between the client and server

    # interactively get user's line to be converted
    responseFromServer = ''
    # send the user's line over the TCP connection
    # No need to specify server name, port
    for i in range(0,5):
        try:
            clientSocket.connect((serverName,serverPort))
            print('Sending ', sentence)
            clientSocket.send(bytes(sentence))

            responseFromServer = clientSocket.recv(2048)

            clientSocket.close()
            # output the modified user's line 
            print ("From Server: ", responseFromServer)

            break
        except socket_error as serr:
            print 'Retrying...', i+1,'/',5
            time.sleep(1)
        if i == 4:
            print 'Connection to server failed'
    return responseFromServer

def main():
    if(len(sys.argv) < 2):
        DiffieHellmanAlice()
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