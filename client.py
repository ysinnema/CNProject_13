import os
import hashlib
import socket
import threading
from tkinter import *
from tkinter import font
from tkinter import ttk
import select
import authentication
import secure_messaging

PORT = 5000
SERVER = "192.168.1.43"
ADDRESS = (SERVER, PORT)
FORMAT = "utf-8"

client = socket.socket(socket.AF_INET,
                       socket.SOCK_STREAM)
client.connect(ADDRESS)

def close_login():
    window_login.destroy()

def close_pw():
    window_pw.destroy()

def close_user():
    window_user.destroy()

def end_session():
    # make the server not crash
    # doesn't work, but here is the link https://stackoverflow.com/questions/409783/socket-shutdown-vs-socket-close
    client.shutdown(socket.SHUT_RDWR)
    client.close()
    window_home.destroy()

def hash_string(input_string):
    pb = bytes(input_string, FORMAT)
    hash = hashlib.sha1(pb)
    return hash.hexdigest()


# GUI class for the chat
class ChatGUI:
    # constructor method
    def __init__(self):

        # chat window which is currently hidden
        self.Window = Tk()
        self.Window.withdraw()

        # entrance window
        self.nickname = Toplevel()
        # set the title
        self.nickname.title("Nickname")
        self.nickname.resizable(width=False,
                                height=False)
        self.nickname.configure(width=400,
                                height=300)
        # create a Label
        self.pls = Label(self.nickname,
                         text="Enter Nickname",
                         justify=CENTER,
                         font="Helvetica 14 bold")

        self.pls.place(relheight=0.15,
                       relx=0.2,
                       rely=0.07)
        # create a Label
        self.labelName = Label(self.nickname,
                               text="Name: ",
                               font="Helvetica 12")

        self.labelName.place(relheight=0.2,
                             relx=0.1,
                             rely=0.2)

        # create an entry box for
        # typing the message
        self.entryName = Entry(self.nickname,
                               font="Helvetica 14")

        self.entryName.place(relwidth=0.4,
                             relheight=0.12,
                             relx=0.35,
                             rely=0.2)

        # set the focus of the cursor
        self.entryName.focus()

        self.key = None

        # create a Continue Button
        # along with action
        self.go = Button(self.nickname,
                         text="CONTINUE",
                         font="Helvetica 14 bold",
                         command=lambda: self.goAhead(self.entryName.get()))

        self.go.place(relx=0.4,
                      rely=0.55)
        self.Window.mainloop()

    def goAhead(self, name):
        self.nickname.destroy()
        self.layout(name)

        # the thread to receive messages
        rcv = threading.Thread(target=self.receive)
        rcv.start()

    # The main layout of the chat
    def layout(self, name):

        self.name = name
        # to show chat window
        self.Window.deiconify()
        self.Window.title("CHATROOM")
        self.Window.resizable(width=False,
                              height=False)
        self.Window.configure(width=470,
                              height=550,
                              bg="#17202A")
        self.labelHead = Label(self.Window,
                               bg="#17202A",
                               fg="#EAECEE",
                               text=self.name,
                               font="Helvetica 13 bold",
                               pady=5)

        self.labelHead.place(relwidth=1)
        self.line = Label(self.Window,
                          width=450,
                          bg="#ABB2B9")

        self.line.place(relwidth=1,
                        rely=0.07,
                        relheight=0.012)

        self.textCons = Text(self.Window,
                             width=20,
                             height=2,
                             bg="#17202A",
                             fg="#EAECEE",
                             font="Helvetica 14",
                             padx=5,
                             pady=5)

        self.textCons.place(relheight=0.745,
                            relwidth=1,
                            rely=0.08)

        self.labelBottom = Label(self.Window,
                                 bg="#ABB2B9",
                                 height=80)

        self.labelBottom.place(relwidth=1,
                               rely=0.825)

        self.entryMsg = Entry(self.labelBottom,
                              bg="#2C3E50",
                              fg="#EAECEE",
                              font="Helvetica 13")

        # place the given widget
        # into the gui window
        self.entryMsg.place(relwidth=0.74,
                            relheight=0.06,
                            rely=0.008,
                            relx=0.011)

        self.entryMsg.focus()

        # create a Send Button
        self.buttonMsg = Button(self.labelBottom,
                                text="Send",
                                font="Helvetica 10 bold",
                                width=20,
                                bg="#ABB2B9",
                                command=lambda: self.sendButton(self.entryMsg.get()))

        self.buttonMsg.place(relx=0.77,
                             rely=0.008,
                             relheight=0.06,
                             relwidth=0.22)

        self.textCons.config(cursor="arrow")

        # create a scroll bar
        scrollbar = Scrollbar(self.textCons)

        # place the scroll bar
        # into the gui window
        scrollbar.place(relheight=1,
                        relx=0.974)

        scrollbar.config(command=self.textCons.yview)

        self.textCons.config(state=DISABLED)

    # function to basically start the thread for sending messages
    def sendButton(self, msg):
        self.textCons.config(state=DISABLED)
        self.msg = msg
        self.entryMsg.delete(0, END)
        snd = threading.Thread(target=self.sendMessage)
        snd.start()

    # function to receive messages
    def receive(self):
        while True:
            try:
                message = client.recv(1024)
                message_text = message.decode()

                # if the messages from the server is NAME send the client's name
                if message_text == 'NAME':
                    client.send(self.name.encode(FORMAT))
                elif message_text[:4] == 'KEY ':
                    self.key = message_text[4:].encode(FORMAT)
                else:
                    decrypted_message = secure_messaging.decrypt(message, self.key)

                    # insert messages to text box
                    self.textCons.config(state=NORMAL)
                    self.textCons.insert(END,
                                         decrypted_message + "\n\n")

                    self.textCons.config(state=DISABLED)
                    self.textCons.see(END)
            except:
                # an error will be printed on the command line or console if there's an error
                print("An error occurred!")
                client.close()
                break

    # function to send messages
    def sendMessage(self):
        self.textCons.config(state=DISABLED)
        while True:
            message = (f"{self.name}: {self.msg}")
            encrypted_message = secure_messaging.encrypt(message, self.key)
            client.send(encrypted_message)
            break


def login_success():
    close_login()
    ChatGUI()


def user_not_found():
    global window_user
    window_user = Toplevel(window_home)
    window_user.title("Wrong username")
    window_user.geometry("150x100")
    Label(window_user, text="User Not Found").pack()
    Button(window_user, text="OK", command=close_user).pack()


def password_not_recognised():
    global window_pw
    window_pw = Toplevel(window_home)
    window_pw.title("Wrong password")
    window_pw.geometry("150x100")
    Label(window_pw, text="Password error").pack()
    Button(window_pw, text="OK", command=close_pw).pack()


def register_user():
    username_info = username.get()
    password_info = password.get()
    password_info = hash_string(password_info)

    global private_key

    public_key, private_key = authentication.asymmetric_keys()

    with open(username_info + ".txt", "w") as file:
        file.write(username_info + "\n")
        file.write(password_info + "\n")
        file.write(str(public_key.n) + "\n")
        file.write(str(public_key.e))

    username_entry.delete(0, END)
    password_entry.delete(0, END)

    Label(window_register, text="Registration Successful\nPlease close this window", fg="green", font=("Calibri", 11)).pack()


def login_verify():
    username1 = username_verify.get()
    password1 = password_verify.get()
    password1 = hash_string(password1)
    username_entry1.delete(0, END)
    password_entry1.delete(0, END)

    list_of_files = os.listdir()
    if username1 + ".txt" in list_of_files:
        with open(username1 + ".txt", "r") as file:
            verify = file.readlines()
            if password1 + "\n" in verify:

                login_success()
            else:
                password_not_recognised()

    else:
        user_not_found()


def register():
    global window_register
    window_register = Toplevel(window_home)
    window_register.title("Register")
    window_register.geometry("300x250")

    global username
    global password
    global username_entry
    global password_entry

    username = StringVar()
    password = StringVar()

    Label(window_register, text="Please enter details below").pack()
    Label(window_register, text="").pack()
    Label(window_register, text="Username *").pack()

    username_entry = Entry(window_register, textvariable=username)
    username_entry.pack()
    Label(window_register, text="Password *").pack()
    password_entry = Entry(window_register, textvariable=password)
    password_entry.pack()
    Label(window_register, text="").pack()
    Button(window_register, text="Register", width="20", height="2", command=register_user).pack()


def login():
    global window_login
    window_login = Toplevel(window_home)
    window_login.title("Login")
    window_login.geometry("300x250")
    Label(window_login, text="Please enter details below to login").pack()
    Label(window_login, text="").pack()

    global username_verify
    global password_verify

    username_verify = StringVar()
    password_verify = StringVar()
    global username_entry1
    global password_entry1

    Label(window_login, text="Username *").pack()
    username_entry1 = Entry(window_login, textvariable=username_verify)
    username_entry1.pack()
    Label(window_login, text="").pack()
    Label(window_login, text="Password *").pack()
    password_entry1 = Entry(window_login, textvariable=password_verify)
    password_entry1.pack()
    Label(window_login, text="").pack()
    Button(window_login, text="Login", width="20", height="2", command=login_verify).pack()


def main_screen():
    global window_home
    window_home = Tk()
    window_home.geometry("350x250")
    window_home.title("CHAT APP")
    Label(text="CHAT APP", bg="grey", width="300", height="2", font=("Calibri", 13)).pack()
    Label(text="").pack()
    Button(text="Login", width="20", height="2", command=login).pack()
    Label(text="").pack()
    Button(text="Register", width="20", height="2", command=register).pack()
    Label(text="").pack()
    Button(text="Exit", width="20", height="2", command=end_session).pack()

    window_home.mainloop()


main_screen()
