from socket import *

# provide the port number
serverPort = 12345


def Server():
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
	    sentence = connectionSocket.recv(1024)
		 
	    # send back modified sentence over the TCP connection
	    connectionSocket.send(clientMessage)
	    recieved = True 
	    # close the TCP connection; the welcoming socket continues
	    connectionSocket.close()
	return clientMessage

Server()