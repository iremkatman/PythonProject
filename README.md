# Cloud-Based Group Chat Application

## Overview
The **Cloud-Based Group Chat Application** is a Python-based platform designed for secure, real-time group communication. It leverages **RSA encryption** to ensure end-to-end security for all messages exchanged between clients and is hosted on **Google Cloud Platform (GCP)** for global accessibility and scalability.

This application demonstrates the integration of robust encryption techniques, efficient client-server architecture, and user-friendly interfaces to meet modern communication needs.

---

## Features
- **End-to-End Encryption**: Messages are encrypted with RSA, ensuring secure communication.
- **Real-Time Group Management**: 
  - Create, join, and leave groups dynamically.
  - Instant updates across all clients in the group.
- **User-Friendly GUI**: 
  - Simple and intuitive interface built with Python's Tkinter library.
  - Seamless navigation for group management and messaging.
- **Cloud Deployment**: 
  - Hosted on Google Cloud Platform for scalability and reliable global access.
- **Concurrent Connections**: 
  - Supports multiple users simultaneously with efficient threading on the server.
- **NAT Traversal Compatibility:**
  -  Designed to work seamlessly with clients behind Network Address Translation (NAT).

---

## Technologies Used
### Programming Language:
- Python 3.9+

### Libraries and Tools:
- **rsa**: For encryption and decryption.
- **socket** and **threading**: For network communication and multi-client handling.
- **Tkinter**: For the graphical user interface (GUI).

### Cloud Platform:
- Google Cloud Platform (GCP): Server hosting and deployment.

---

## Project Architecture

### Server:
- Handles multiple concurrent client connections using threading.
- Manages active clients and their group memberships in efficient dictionary structures.
- Encrypts outgoing messages with each recipient's RSA public key to ensure security.
- Decrypts incoming messages using the server's private key for processing.

### Client:
- Establishes a secure connection with the server via RSA public/private key exchange.
- Provides a user-friendly GUI for managing groups and sending/receiving messages.
- Encrypts outgoing messages and decrypts incoming messages for secure communication.

### Cloud Deployment:
- Hosted on Google Cloud Platform with a public IP for client-server communication.
- Configured to handle concurrent connections and ensure uptime with GCP's infrastructure.

### NAT Compatibility:
This application is designed to work seamlessly with clients behind Network Address Translation (NAT).
- Server Accessibility: The server is hosted on Google Cloud Platform with a public IP address, making it reachable by clients regardless of their network configuration.
- Client-Server Communication: NAT clients can initiate outbound connections to the server. The NAT router tracks these connections, allowing bidirectional communication without additional configuration.
- Message Routing: All messages are routed through the server, avoiding the need for direct client-to-client connections.
---

## Installation and Setup

### Pre-requisites
1. Python 3.9+ installed on your system.
2. A Google Cloud Platform account (for server hosting).

### Steps to Run Locally

1. Clone the Repository:
   ```bash
   git clone https://github.com/iremkatman/PythonProject.git
   cd <repository-name>
   ```

2. Install Dependencies:
   Install the required Python libraries:
   ```bash
   pip install rsa
   ```

3. Run the Server:
   Start the server by navigating to the project directory and running:
   ```bash
   python server.py
   ```
   The server will listen on port 1234 by default.

4. Run the Client:
   Start the client application:
   ```bash
   python client.py
   ```
   A login prompt will appear for entering the username. Once logged in, the client will connect to the server.

5. Use the Application:
   - Create a new group or join an existing group.
   - Send messages to the group and view real-time updates.

---

## Deployment

### **Cloud Server Deployment**
1. **Set Up a Google Cloud VM Instance**:
   - Create a virtual machine on Google Cloud Platform.
   - Assign a public IP address to the instance.

2. **Configure Firewall Rules**:
   - Allow inbound TCP traffic on port 1234 to enable client connections.

3. **Deploy the Server**:
   - Upload `server.py` to the VM instance.
   - Run the server on the VM:
     ```bash
     python server.py
     ```

4. **Connect Clients**:
   - Update the `HOST` variable in `client.py` with the server's public IP:
     ```python
     HOST = '<YOUR_SERVER_PUBLIC_IP>'
     ```
   - Distribute the updated client code to users.

---

## **Usage**

1. **Start the Server**:
   Run `server.py` on the cloud-hosted VM or locally to start listening for client connections.

2. **Login and Connect**:
   Open `client.py` and log in using a unique username. The client will securely connect to the server.

3. **Create or Join Groups**:
   - Create a new group with a unique name.
   - Join an existing group from the list of available groups.

4. **Send and Receive Messages**:
   Use the chat window to send encrypted messages to the group. Messages will be decrypted and displayed for recipients in real time.

---

