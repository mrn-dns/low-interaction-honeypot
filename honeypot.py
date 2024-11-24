import paramiko  # Library for handling SSH protocol
import socket  # Library for network communication
import threading  # Library to handle multiple connections simultaneously
import os  
import json 
from datetime import datetime 

# References to useful SSH honeypot implementations
# https://github.com/jaksi/sshesame
# https://github.com/fiascototal/FakeSsh
# https://github.com/skeeto/endlessh

# Load configuration from a JSON file
with open("config.json", "r") as config_file:
    config = json.load(config_file)  # Parse configuration file into a dictionary

# Configuration parameters
PORT = config["port"]  # Port the honeypot will listen on
ALLOWED_USER = config["allowed_user"]  # Allowed username for SSH authentication
ALLOWED_PASSWORD = config["allowed_password"]  # Allowed password for SSH authentication
LOG_DIRECTORY = config["log_directory"]  # Directory to store general logs
SESSION_LOG_DIRECTORY = config["session_log_directory"]  # Directory to store session-specific logs

# Ensure log directories exist by creating them if necessary
os.makedirs(LOG_DIRECTORY, exist_ok=True)
os.makedirs(SESSION_LOG_DIRECTORY, exist_ok=True)

# Logging function to write events to a log file and print them to the console
def log_event(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Get the current timestamp
    log_file = os.path.join(LOG_DIRECTORY, "honeypot.log")  # Path to the general log file located in the logs directory
    with open(log_file, "a") as f:  
        f.write(f"[{timestamp}] {message}\n")  # Write the timestamped message to the log
    print(f"[{timestamp}] {message}") 

# SSH Server interface definition using paramiko
class SSHServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()  # Event for handling channel requests

    # Handle password-based authentication
    def check_auth_password(self, username, password):
        # If credentials match the allowed ones, authenticate the user
        if username == ALLOWED_USER and password == ALLOWED_PASSWORD:
            return paramiko.AUTH_SUCCESSFUL  # Authentication success
        # Log failed login attempts
        log_event(f"Failed login attempt - User: {username}, Password: {password}")
        return paramiko.AUTH_FAILED  # Authentication failed

    # Specify that only password-based authentication is allowed
    def get_allowed_auths(self, username):
        return "password"

    # Handle requests for session channels
    def check_channel_request(self, kind, chanid):
        if kind == "session":  # Allow session-type channels
            return paramiko.OPEN_SUCCEEDED  # Open the channel
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED  # Deny other types of channels

    # Handle requests for opening a shell in the channel
    def check_channel_shell_request(self, channel):
        self.event.set()  # Set the event indicating the shell is ready
        return True  # Approve the shell request

# Handle individual SSH client connections
def handle_client(client_socket):
    log_event("New connection established")  # Log new connection
    try:
        # Create a paramiko Transport object for SSH communication
        transport = paramiko.Transport(client_socket)
        # Generate an RSA key for the SSH server
        transport.add_server_key(paramiko.RSAKey.generate(2048))
        server = SSHServer()  # Initialize the custom SSH server
        transport.start_server(server=server)  # Start the server on the transport

        # Wait for the client to open a channel
        chan = transport.accept(20)  # Timeout after 20 seconds if no channel is requested
        if chan is None:  # If no channel is opened, log and exit
            log_event("Channel not established. Closing connection.")
            return

        log_event("Shell opened for attacker.")  # Log shell opening
        chan.send("Welcome to the fake SSH server!\n")  # Send a welcome message to the attacker
        # Create a session log file for this connection
        session_log = os.path.join(
            SESSION_LOG_DIRECTORY, f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )

        # Open the session log file for writing
        with open(session_log, "w") as session_file:
            while True:
                chan.send("$ ")  # Display a fake command prompt
                command = chan.recv(1024).decode("utf-8").strip()  # Receive a command from the attacker
                if not command:  # If no command is received, break the loop
                    break
                # Log the received command
                log_event(f"Command executed: {command}")
                # Write the command to the session log with a timestamp
                session_file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {command}\n")
                session_file.flush()  # Ensure the command is written to the file
                # Send a fake response to the attacker
                chan.send(f"Command '{command}' not recognized.\n")
        chan.close()  # Close the channel when done
    except Exception as e:
        log_event(f"Error: {e}")  # Log any errors that occur
    finally:
        client_socket.close()  # Close the client socket
        log_event("Connection closed.")  # Log the closure of the connection

# Main function to start the SSH honeypot
def start_honeypot():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Create a socket for listening to incoming SSH connections
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow reusing the port
    server_socket.bind((config["hostname"], PORT))  # Bind the socket to the hostname and port
    server_socket.listen(100)  # Allow up to 100 simultaneous connections in the queue

    log_event(f"SSH Honeypot listening on port {PORT}")  # Log that the honeypot is running
    while True:  # Continuously listen for incoming connections
        client_socket, addr = server_socket.accept()  # Accept a new connection
        log_event(f"Incoming connection from {addr}")  # Log the client's address
        # Handle the connection in a separate thread to allow multiple connections
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

# Entry point of the script
if __name__ == "__main__":
    try:
        start_honeypot()  # Start the SSH honeypot
    except KeyboardInterrupt:
        log_event("SSH Honeypot shutting down.")  # Log the shutdown event
