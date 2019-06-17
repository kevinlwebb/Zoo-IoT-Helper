# Import socket module 
import socket                
  
# Create a socket object 
s = socket.socket()          
  
# Define the port on which you want to connect 
port = 12345                
  
# connect to the server on local computer 
s.connect(('192.168.1.131', port)) 
#s.connect(('127.0.0.1', port))  

# send a thank you message to the client.  
s.send(b'Sending stuff from client') 

# close the connection 
s.close()   
