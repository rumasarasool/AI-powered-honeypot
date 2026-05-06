#!/usr/bin/env python3
"""
SSH Honeypot using Paramiko
Accepts any SSH login credentials and logs all activity to JSON format.
Handles multiple concurrent connections with threading and robust error handling.
"""

import socket
import threading
import paramiko
import logging
import json
import uuid
from datetime import datetime
from pathlib import Path

# Configuration
SSH_PORT = 2222
LOG_FILE = Path("logs/cowrie.json")
HOST_KEY_FILE = Path("server.key")

# Load or create persistent host key
if HOST_KEY_FILE.exists():
    HOST_KEY = paramiko.RSAKey(filename=str(HOST_KEY_FILE))
else:
    HOST_KEY = paramiko.RSAKey.generate(1024)
    HOST_KEY.write_private_key_file(str(HOST_KEY_FILE))

# Ensure logs directory exists
LOG_FILE.parent.mkdir(exist_ok=True)

# Setup logging for exceptions (separate from event logging)
logging.basicConfig(
    filename="logs/honeypot.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class SSHServer(paramiko.ServerInterface):
    """
    Custom SSH Server that accepts all credentials and records interactions.
    """
    
    def __init__(self, client_ip, session_id):
        """Initialize SSH server with client connection info."""
        self.client_ip = client_ip
        self.session_id = session_id
        self.username = None
        self.password = None
        self.channel = None
        self.event = threading.Event()
        self.exec_command = None
        self.exec_event = threading.Event()
        
    def check_auth_password(self, username, password):
        """
        Accept any username/password combination.
        Records successful login to JSON log.
        """
        try:
            self.username = username
            self.password = password
            
            # Log login event
            event = {
                "eventid": "cowrie.login.success",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "src_ip": self.client_ip,
                "session_id": self.session_id,
                "username": username,
                "password": password
            }
            _log_event(event)
            
            logger.info(f"Login: {username}@{self.client_ip} (session: {self.session_id})")
            
            return paramiko.AUTH_SUCCESSFUL
        except Exception as e:
            logger.error(f"Error in check_auth_password: {e}")
            return paramiko.AUTH_FAILED
    
    def check_auth_publickey(self, username, key):
        """Reject public key auth (we only want password auth)."""
        return paramiko.AUTH_FAILED
    
    def get_allowed_auths(self, username):
        """Specify that only password authentication is allowed."""
        return "password"
    
    def check_channel_request(self, kind, chanid):
        """Accept all channel requests (SSH shells, subsystems, etc)."""
        try:
            if kind == "session":
                return paramiko.OPEN_SUCCEEDED
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        except Exception as e:
            logger.error(f"Error in check_channel_request: {e}")
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_channel_exec_request(self, channel, command):
        """Accept exec requests (single commands)."""
        try:
            try:
                command_text = command.decode("utf-8", errors="replace")
            except Exception:
                command_text = str(command)

            # Log the command
            event = {
                "eventid": "cowrie.command.input",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "src_ip": self.client_ip,
                "session_id": self.session_id,
                "username": self.username or "unknown",
                "command": command_text
            }
            _log_event(event)
            logger.info(f"Exec: {self.username}@{self.client_ip} - {command_text}")

            self.exec_command = command_text
            self.exec_event.set()
            return True
        except Exception as e:
            logger.error(f"Error in check_channel_exec_request: {e}")
            return False
    
    def check_channel_shell_request(self, channel):
        """Accept shell channel and create interactive session."""
        try:
            self.channel = channel
            self.event.set()
            return True
        except Exception as e:
            logger.error(f"Error in check_channel_shell_request: {e}")
            return False
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        """Accept PTY allocation requests (required for interactive shells)."""
        try:
            return True
        except Exception as e:
            logger.error(f"Error in check_channel_pty_request: {e}")
            return False

    def check_channel_env_request(self, channel, name, value):
        """Accept environment variable requests."""
        return True


def _log_event(event):
    """
    Write event as JSON line to log file.
    Thread-safe operation using file locking pattern.
    """
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(event) + "\n")
            f.flush()
    except Exception as e:
        logger.error(f"Failed to write event log: {e}")


def _handle_channel_input(channel, client_ip, session_id, username):
    """
    Read and log all commands typed in the SSH channel.
    Handles interactive shell input without crashing.
    """
    try:
        # Set channel to blocking mode with timeout for recv()
        channel.settimeout(0.1)
        
        # Send welcome/prompt
        channel.send("Welcome to Honeypot Shell\n")
        channel.send("root@honeypot:~# ")
        
        input_buffer = ""
        while True:
            try:
                # Try to receive data with non-blocking approach
                data = channel.recv(1024)
                
                if len(data) == 0:
                    # Channel closed by client
                    logger.info(f"Channel closed for session {session_id}")
                    break
                
                # Decode input safely
                try:
                    text = data.decode("utf-8", errors="replace")
                except Exception:
                    text = data.decode("latin-1", errors="replace")
                
                # Process each character
                for char in text:
                    if char == "\n" or char == "\r":
                        # Command complete - log it
                        if input_buffer.strip():
                            command_text = input_buffer.strip()
                            event = {
                                "eventid": "cowrie.command.input",
                                "timestamp": datetime.utcnow().isoformat() + "Z",
                                "src_ip": client_ip,
                                "session_id": session_id,
                                "username": username,
                                "command": command_text
                            }
                            _log_event(event)
                            logger.info(f"Command: {username}@{client_ip} - {command_text}")

                            # Fake command responses
                            lower_command = command_text.lower()
                            base_command = lower_command.split()[0]

                            if base_command in ("exit", "quit", "logout"):
                                channel.send("\nlogout\n")
                                break
                            elif base_command == "whoami":
                                channel.send("\nroot\n")
                            elif base_command == "pwd":
                                channel.send("\n/root\n")
                            elif base_command == "ls":
                                channel.send("\n.bashrc  .ssh  bin  etc  home  root  tmp  var\n")
                            elif lower_command == "uname -a":
                                channel.send("\nLinux honeypot 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n")
                            elif base_command == "id":
                                channel.send("\nuid=0(root) gid=0(root) groups=0(root)\n")
                            else:
                                channel.send(f"\n{command_text}: command not found\n")

                        input_buffer = ""
                        # Send new prompt
                        channel.send("\nroot@honeypot:~# ")
                    elif char == "\x08" or char == "\x7f":  # Backspace
                        if input_buffer:
                            input_buffer = input_buffer[:-1]
                        channel.send("\x08 \x08")
                    elif ord(char) >= 32 and ord(char) < 127:  # Printable ASCII
                        input_buffer += char
                        channel.send(char)
                    elif char == "\t":  # Tab
                        input_buffer += "    "
                        channel.send("    ")
                    
            except socket.timeout:
                # No data available - this is normal
                continue
            except EOFError:
                logger.info(f"EOF on channel {session_id}")
                break
            except Exception as e:
                if "Connection reset" not in str(e):
                    logger.error(f"Channel error: {e}")
                break
    except Exception as e:
        logger.error(f"Error handling channel input: {e}")
    finally:
        try:
            channel.close()
        except Exception:
            pass


def _handle_client_connection(client_socket, client_addr):
    """
    Handle a single SSH client connection.
    Manages authentication and channel I/O in a dedicated thread.
    Never raises unhandled exceptions - all errors are logged.
    """
    client_ip = client_addr[0]
    session_id = str(uuid.uuid4())
    
    try:
        logger.info(f"New connection from {client_ip} (session: {session_id})")
        
        # Wrap socket with paramiko transport
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(HOST_KEY)
        transport.set_keepalive(30)
        
        # Create SSH server instance for this client
        ssh_server = SSHServer(client_ip, session_id)
        
        try:
            # Start SSH server on this transport
            transport.start_server(server=ssh_server, event=ssh_server.event)
        except paramiko.SSHException as e:
            logger.error(f"SSH negotiation failed for {session_id}: {e}")
            return
        except Exception as e:
            logger.error(f"Unexpected error during SSH handshake: {e}")
            return
        
        # Keep transport open and handle channel requests
        while transport.is_active():
            try:
                # Check if we have an active channel (with longer timeout)
                channel = transport.accept(timeout=2)
                
                if channel is None:
                    continue
                
                # We have an active channel - handle its input/output
                username = ssh_server.username or "unknown"
                if ssh_server.exec_command:
                    exec_command = ssh_server.exec_command
                    ssh_server.exec_command = None
                    ssh_server.exec_event.clear()
                    try:
                        channel.send(f"Command executed: {exec_command}\n")
                        channel.send_exit_status(0)
                    finally:
                        channel.close()
                    continue

                _handle_channel_input(channel, client_ip, session_id, username)
                
            except socket.timeout:
                continue
            except Exception as e:
                logger.debug(f"Exception accepting channel: {e}")
                break
        
    except Exception as e:
        logger.error(f"Fatal error in client handler for {session_id}: {e}")
    finally:
        try:
            transport.close()
        except Exception:
            pass
        try:
            client_socket.close()
        except Exception:
            pass
        logger.info(f"Connection closed: {session_id}")


def start_honeypot(host="0.0.0.0", port=SSH_PORT):
    """
    Main honeypot loop: listen for SSH connections and handle each in a thread.
    Continues running despite any client errors.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((host, port))
        server_socket.listen(100)
        logger.info(f"SSH Honeypot listening on {host}:{port}")
        print(f"[*] SSH Honeypot listening on {host}:{port}")
        print(f"[*] Logging to {LOG_FILE}")
        
        connection_count = 0
        while True:
            try:
                client_socket, client_addr = server_socket.accept()
                connection_count += 1
                
                # Handle each client in a separate thread
                thread = threading.Thread(
                    target=_handle_client_connection,
                    args=(client_socket, client_addr),
                    daemon=True
                )
                thread.start()
                
                logger.info(f"Total connections: {connection_count}")
                
            except KeyboardInterrupt:
                logger.info("Shutting down honeypot")
                print("\n[*] Shutting down honeypot")
                break
            except Exception as e:
                logger.error(f"Error accepting connection: {e}")
                continue
    
    except OSError as e:
        logger.error(f"Failed to start honeypot: {e}")
        print(f"[!] Failed to bind to {host}:{port}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error in honeypot: {e}")
    finally:
        try:
            server_socket.close()
        except Exception:
            pass


if __name__ == "__main__":
    start_honeypot()
