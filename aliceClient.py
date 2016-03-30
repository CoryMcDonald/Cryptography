from socket import *
from socket import error as socket_error

# provide the IP address of the server
serverName = 'localhost'

# provide the port number
serverPort = 12345



def Send(sentence):
    # create TCP socket, called clientSocket, on client to use for connecting to remote server.  
    # indicate the server's remote listening port type SOCK_STREAM for TCP
    clientSocket = socket(AF_INET, SOCK_STREAM)

    # initiate the TCP connection between the client and server

    # interactively get user's line to be converted
    sentence = sentence.encode("utf-8")
    responseFromServer = ''
    # send the user's line over the TCP connection
    # No need to specify server name, port
    for i in range(0,5):
        try:
            clientSocket.connect((serverName,serverPort))
            clientSocket.send(bytes(sentence))

            responseFromServer = clientSocket.recv(1024)

            clientSocket.close()
            # output the modified user's line 
            print ("From Server: ", responseFromServer)

            break
        except socket_error as serr:
            print 'Retrying...', i+1,'/',5
        if i == 4:
            print 'Connection to server failed'

