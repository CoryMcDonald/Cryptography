
# Alice (as a Client) needs to send a message of 2000 bytes to Bob (as a
# Server), where each byte is 'a'; Bob needs to return a message of 1000 bytes back to Alice,
# where each byte is 'b'. Either TCP or UDP is fine for the transport protocol. 
# Both messages must be encrypted and integrity-protected


# Step 1: Set up shared secret keys for encryption: For the communication from Alice to Bob, they
# agree on a shared secret key using RSA-based encryption. You can assume that they know each
# other's public key in advance. For the communication from Bob to Alice, they agree on a shared
# secret key using the Diffie-Hellman protocol. You can assume that Bob selects the public
# parameters of Diffie-Hellman protocol, and send them to Alice


alicePublicKey = ''
bobPublicKey = ''



# pycrypto
# http://stackoverflow.com/questions/30056762/rsa-encryption-and-decryption-in-python
# https://github.com/lowazo/pyDHE/blob/master/DiffieHellman.py
