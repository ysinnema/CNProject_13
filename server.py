import socket
import threading
import os
import authentication
import secure_messaging

# Choose a free port
PORT = 5000
# IP address of the current host
SERVER = socket.gethostbyname(socket.gethostname())
ADDRESS = (SERVER, PORT)

FORMAT = "utf-8"
 
# Instantiate lists of connected clients
clients, names = [], []
 
# New socket for the server
server = socket.socket(socket.AF_INET,
                       socket.SOCK_STREAM)
server.bind(ADDRESS)

# Generate symmetric key for encrypting and decrypting messages
key = secure_messaging.symmetric_key()
 
# Main function: initialize the server
def startChat():
    # display IP address
    print("server is working on " + SERVER)
     
    # listen for clients
    server.listen()
     
    while True:
       
        # accept connections
        conn, addr = server.accept()

        # request username
        conn.send("NAME".encode(FORMAT))
        name = conn.recv(1024).decode()

        # send symmetric key (should be done after challenge-response authentication)
        key_message = "KEY ".encode(FORMAT) + key
        conn.send(key_message)
         
        # add client to list
        names.append(name)
        clients.append(conn)
        print(f"Name is: {name}")
         
        # letting all users know that someone joined
        broadcastMessage(secure_messaging.encrypt(f"{name} has joined the chat!", key))

        conn.send(secure_messaging.encrypt('Connection successful!', key))
         
        # Instantiate a thread to handle all messages from this client
        thread = threading.Thread(target = handle,
                                  args = (conn, addr))
        thread.start()
         
        # number of clients connected to the server
        print(f"active connections {threading.activeCount()-1}")

# send new client a challenge for user authentication
# inspired by https://towardsdatascience.com/encrypting-your-data-9eac85364cb
def challenge(conn, username):
    # generate challenge message
    nonce = os.urandom(16)

    # look up public key of the client
    with open(username, "r") as file:
        info = file.readlines()

    user_key = authentication.get_public_key(info[2].strip("\n"), info[3].strip("\n"))
    nonce_encr = authentication.encrypt(nonce, user_key)

    # send challenge and wait for response
    conn.send(nonce_encr)
    nonce_back = conn.recv(1024)

    return nonce == nonce_back

# handle the incoming messages from a client
def handle(conn, addr):
   
    print(f"new connection {addr}")
    connected = True
     
    while connected:
        # receive message
        message = conn.recv(1024)

        # broadcast message
        broadcastMessage(message)
     
    # close the connection
    conn.close()
 
# broadcast incoming messages to all users
def broadcastMessage(message):
    for client in clients:
        client.send(message)
 

startChat()
