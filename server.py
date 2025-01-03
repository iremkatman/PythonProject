import base64
import socket
import threading
import rsa

# Server Constants
HOST = '0.0.0.0'
PORT = 1234
LISTENER_LIMIT = 7

# Generate RSA keys for the server
public_key, private_key = rsa.newkeys(1024)
# Active clients and groups management
active_clients = {}  # {username: (client_socket, group_name, client_public_key)}
groups = {}  # {group_name: [usernames]}


def decrypt_message(encrypted_message):
    """Decrypt an incoming message using the server's private key."""
    try:
        encrypted_data = base64.b64decode(encrypted_message.encode('utf-8'))
        decrypted_message = rsa.decrypt(encrypted_data, private_key).decode('utf-8')
        print(f"Decrypted message: {decrypted_message}")
        return decrypted_message
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None


def send_message_to_client(client, message, client_public_key):
    """Send an encrypted message to a client."""
    try:
        encrypted_message = rsa.encrypt(message.encode('utf-8'), client_public_key)
        encrypted_b64 = base64.b64encode(encrypted_message).decode('utf-8')
        print(f"Sending encrypted message: {encrypted_b64}")
        client.sendall(encrypted_b64.encode('utf-8'))
    except Exception as e:
        print(f"Failed to send message: {e}")


def broadcast_group_update():
    """Send updated group list to all connected clients."""
    groups_list = "~".join(groups.keys())
    message = f"SERVER~GROUPS~{groups_list}"
    for client, _, client_public_key in active_clients.values():
        send_message_to_client(client, message, client_public_key)


def broadcast_message(group_name, sender_username, message_content):
    """Send an encrypted message to all clients in the specified group."""
    if group_name in groups:
        for username in groups[group_name]:
            client, _, client_public_key = active_clients.get(username, (None, None, None))
            if client and client_public_key:
                message = f"{sender_username}~{message_content}"
                send_message_to_client(client, message, client_public_key)


def handle_client(client, username):
    """Handle communication with a client."""
    try:
        while True:
            encrypted_message = client.recv(2048).decode('utf-8')
            if not encrypted_message:
                break

            print(f"Received encrypted message: {encrypted_message}")
            message = decrypt_message(encrypted_message)
            if not message:
                continue

            command, *args = message.split("~")

            if command == "CREATE_GROUP":
                group_name = args[0]
                if group_name not in groups:
                    groups[group_name] = []
                    send_message_to_client(client, f"SERVER~Group {group_name} created.", active_clients[username][2])
                    broadcast_group_update()
                else:
                    send_message_to_client(client, f"SERVER~Group {group_name} already exists.",
                                           active_clients[username][2])

            elif command == "FETCH_GROUPS":
                send_message_to_client(client, f"SERVER~GROUPS~{'~'.join(groups.keys())}", active_clients[username][2])

            elif command == "JOIN_GROUP":
                group_name = args[0]
                if group_name in groups:
                    if username not in groups[group_name]:
                        groups[group_name].append(username)
                        active_clients[username] = (client, group_name, active_clients[username][2])
                        send_message_to_client(client, f"SERVER~Joined group {group_name}.",
                                               active_clients[username][2])
                        broadcast_message(group_name, "SERVER", f"{username} has joined the group.")
                else:
                    send_message_to_client(client, f"SERVER~Group {group_name} does not exist.",
                                           active_clients[username][2])

            elif command == "LEAVE_GROUP":
                group_name = active_clients[username][1]
                if group_name and username in groups[group_name]:
                    groups[group_name].remove(username)
                    send_message_to_client(client, f"SERVER~Left group {group_name}.", active_clients[username][2])
                    broadcast_message(group_name, "SERVER", f"{username} has left the group.")
                    active_clients[username] = (client, None, active_clients[username][2])

            elif command == "SEND_MESSAGE":
                group_name = active_clients[username][1]
                if group_name:
                    message_content = args[0]
                    broadcast_message(group_name, username, message_content)

    finally:
        if username in active_clients:
            group_name = active_clients[username][1]
            if group_name and username in groups[group_name]:
                groups[group_name].remove(username)
            del active_clients[username]
        client.close()

