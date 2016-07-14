# Import socket module
import socket               
import sys
# Create a socket object
s = socket.socket()         

# Define the port on which you want to connect
port = 12345                

# connect to the server on local computer
print "Initating Connection"
s.connect((sys.argv[1],int(sys.argv[2])))
print "Connected"
# receive data from the server
s.send("Test")
print "Data sent"
print s.recv(1024)

# close the connection
s.close()    