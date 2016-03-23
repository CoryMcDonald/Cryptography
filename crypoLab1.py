import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
import ast
import rsa
from random import getrandbits
# Alice (as a Client) needs to send a message of 2000 bytes to Bob (as a
# Server), where each byte is 'a'; Bob needs to return a message of 1000 bytes back to Alice,
# where each byte is 'b'. Either TCP or UDP is fine for the transport protocol.
# Both messages must be encrypted and integrity-protected


# Step 1: Set up shared secret keys for encryption: For the communication from Alice to Bob, they
# agree on a shared secret key using RSA-based encryption. You can assume that they know each
# other's public key in advance. For the communication from Bob to Alice, they agree on a shared
# secret key using the Diffie-Hellman protocol. You can assume that Bob selects the public
# parameters of Diffie-Hellman protocol, and send them to Alice

sharedSecret = 'DC83C6A952B5D52A9E57FDAB05BE8D085BD0197862399DAE763BB2C898B8AF45'

bobPublicKey = ''
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

def DiffieHellman(privateKey)
	g = 7
	prime = 84619573
	a = getrandbits(bits)
	A = pow(g, privateKey, prime)
	#Do socket stuff, send Bob A, recieve B
	secret = pow(B,a,prime)
	

# pycrypto
# http://stackoverflow.com/questions/30056762/rsa-encryption-and-decryption-in-python
# https://github.com/lowazo/pyDHE/blob/master/DiffieHellman.py
