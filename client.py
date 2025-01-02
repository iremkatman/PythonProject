import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
import rsa

HOST = '34.154.113.184' # 34.154.105.44
PORT = 1234
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# RSA Keys
server_public_key = None

DARK_GREY = '#121212'
MEDIUM_GREY = '#1F1B24'
OCEAN_BLUE = '#464EB8'
WHITE = "white"
FONT = ("Helvetica", 17)
BUTTON_FONT = ("Helvetica", 15)
SMALL_FONT = ("Helvetica", 13)

username = None
current_group = None
groups = []

def connect_to_server():
    global server_public_key
    try:
        client.connect((HOST, PORT))
        # Receive the server's public key
        server_public_key_data = client.recv(1024)
        server_public_key = rsa.PublicKey.load_pkcs1(server_public_key_data)
        print("Connected to the server and public key received.")
        return True
    except Exception as e:
        messagebox.showerror("Connection Error", f"Cannot connect to server {HOST}:{PORT}: {e}")
        return False

def encrypt_message(message):

    return rsa.encrypt(message.encode('utf-8'), server_public_key)

def send_message_to_server(message):
    try:
        if message and server_public_key:
            encrypted_message = encrypt_message(message)
            client.sendall(encrypted_message)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to send message: {e}")

def listen_for_messages():
    while True:
        try:
            message = client.recv(2048).decode()
            if message:
                handle_server_message(message)
        except Exception as e:
            print(f"Error listening for messages: {e}")
            break

def handle_server_message(message):
    global groups

    if message.startswith("SERVER~GROUPS~"):
        groups_list = message.split("~")[2:]
        groups = groups_list if groups_list[0] != "" else []
        update_groups_frame()
    elif message.startswith("SERVER~"):
        server_message = message.replace("SERVER~", "").strip()
        add_message(f"Server: {server_message}")
    else:
        try:
            sender, content = message.split("~", 1)
            add_message(f"{sender}: {content}")
        except ValueError:
            print(f"Invalid message format: {message}")

