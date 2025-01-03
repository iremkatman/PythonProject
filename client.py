import base64
import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
import rsa

HOST = '34.154.59.250'  # Server IP
PORT = 1234
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# RSA Keys
server_public_key = None
client_public_key, client_private_key = rsa.newkeys(1024)

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
is_loading = False  # Yükleme durumu


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
    try:
        encrypted = rsa.encrypt(message.encode('utf-8'), server_public_key)
        encrypted_b64 = base64.b64encode(encrypted).decode('utf-8')
        return encrypted_b64
    except Exception as e:
        print(f"Encryption error: {e}")
        return None


def decrypt_message(encrypted_message):
    try:
        encrypted_data = base64.b64decode(encrypted_message.encode('utf-8'))
        decrypted_message = rsa.decrypt(encrypted_data, client_private_key).decode('utf-8')
        return decrypted_message
    except Exception as e:
        print(f"Decryption error: {e}")
        return None


def send_message_to_server(message):
    encrypted_message = encrypt_message(message)
    if encrypted_message:
        client.sendall(encrypted_message.encode('utf-8'))


def listen_for_messages():
    while True:
        try:
            encrypted_message = client.recv(2048).decode('utf-8')
            if encrypted_message:
                message = decrypt_message(encrypted_message)
                if message:
                    handle_server_message(message)
        except Exception as e:
            print(f"Error listening for messages: {e}")
            break


def handle_server_message(message):
    global groups, is_loading

    if message.startswith("SERVER~GROUPS~"):
        groups_list = message.split("~")[2:]
        groups = groups_list if groups_list[0] != "" else []
        is_loading = False  # Yükleme tamamlandı
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


def fetch_groups():
    global is_loading
    is_loading = True  # Yükleme başlıyor
    update_groups_frame()
    send_message_to_server("FETCH_GROUPS")


def create_group():
    group_name = simpledialog.askstring("Create Group", "Enter a name for the group:")
    if group_name:
        send_message_to_server(f"CREATE_GROUP~{group_name}")


#GUI PART

root = tk.Tk()
root.geometry("800x600")
root.title("Chat Application")
root.withdraw()

main_frame = tk.Frame(root, bg=MEDIUM_GREY)

groups_label = tk.Label(main_frame, text="Groups", font=FONT, bg=MEDIUM_GREY, fg=WHITE)
groups_label.pack(side=tk.TOP, pady=5)

groups_frame = tk.Frame(main_frame, bg=MEDIUM_GREY)
groups_frame.pack(fill=tk.BOTH, expand=True)
create_group_button = tk.Button(main_frame, text="Create New Group", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE,
                                command=create_group)
create_group_button.pack(side=tk.BOTTOM, pady=10)
chat_frame = tk.Frame(root, bg=DARK_GREY)
chat_label = tk.Label(chat_frame, text="Chat", font=FONT, bg=DARK_GREY, fg=WHITE)
chat_label.pack(side=tk.TOP, pady=10)

chat_window = scrolledtext.ScrolledText(chat_frame, font=SMALL_FONT, bg=MEDIUM_GREY, fg=WHITE)
chat_window.pack(expand=True, fill=tk.BOTH)

message_entry = tk.Entry(chat_frame, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=40)
message_entry.pack(side=tk.LEFT, padx=10)

send_button = tk.Button(chat_frame, text="Send", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE, command=send_message)
send_button.pack(side=tk.LEFT, padx=10)
main_menu_button = tk.Button(chat_frame, text="Main Menu", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE,
                              command=return_to_main_menu)
main_menu_button.pack(side=tk.LEFT, padx=10)

if __name__ == "__main__":
    login()
    root.mainloop()
