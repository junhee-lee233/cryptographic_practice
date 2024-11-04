import socket
import json
import base64
import random

def rsa_encrypt(message, public_key):
    e, n = public_key
    message_int = int.from_bytes(message, byteorder='big')
    encrypted_message_int = pow(message_int, e, n)
    encrypted_message = encrypted_message_int.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
    return encrypted_message

def aes_decrypt(encrypted_message, key):
    # Decrypts the message with XOR operation and returns bytes, not a decoded string
    decrypted_bytes = bytes([e ^ k for e, k in zip(encrypted_message, key)])
    return decrypted_bytes  # Return raw bytes instead of decoding

def send_packet(conn, packet):
    try:
        conn.sendall((json.dumps(packet) + "\n").encode("ascii"))
        print("Sent packet:", packet)
    except Exception as e:
        print(f"Error sending packet: {e}")

def receive_packet(conn):
    data = ""
    while True:
        try:
            part = conn.recv(1024).decode("ascii")
            data += part
            if "\n" in data:
                packet_str, data = data.split("\n", 1)
                packet = json.loads(packet_str)
                print("Received packet:", packet)
                return packet
        except ConnectionResetError as e:
            print("Connection was reset by peer:", e)
            return None
        except json.JSONDecodeError as e:
            print("Error decoding JSON:", e)
            return None
# Ensure symmetric key consistency in aes_encrypt
def aes_encrypt(message, key):
    message_bytes = message.encode()
    return bytes([m ^ k for m, k in zip(message_bytes, key)])

# Protocol 2 execution
def protocol_2(addr, port):
    print("Starting Protocol 2...")
    symmetric_key = bytes([random.randint(0, 255) for _ in range(16)])
    print("Generated symmetric key:", symmetric_key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        try:
            conn.connect((addr, port))
            print("Connected to Bob")

            # Step 1: Request RSA Key
            send_packet(conn, {"opcode": 0, "type": "RSAKey"})

            # Step 2: Receive RSA public key from Bob
            rsa_packet = receive_packet(conn)
            if rsa_packet and rsa_packet.get("opcode") == 0 and rsa_packet.get("type") == "RSAKey":
                print("Received RSA public key from Bob")
                public_key_base64 = rsa_packet["public"]
                public_key_bytes = base64.b64decode(public_key_base64)
                e, n = int.from_bytes(public_key_bytes[:4], 'big'), rsa_packet["parameter"]["n"]
                public_key = (e, n)
                print("Decoded RSA public key:", public_key)

                # Encrypt symmetric key
                encrypted_key = rsa_encrypt(symmetric_key, public_key)
                encrypted_key_base64 = base64.b64encode(encrypted_key).decode("ascii")
                send_packet(conn, {"opcode": 2, "type": "RSA", "encryption": encrypted_key_base64})
                print("Sent encrypted symmetric key to Bob")

                # Step 4: Encrypt message using AES and send to Bob
                alice_message = "Hello from Alice via AES"
                encrypted_message = aes_encrypt(alice_message, symmetric_key)
                encrypted_message_base64 = base64.b64encode(encrypted_message).decode("ascii")
                send_packet(conn, {"opcode": 2, "type": "AES", "encryption": encrypted_message_base64})
                print("Sent AES-encrypted message to Bob:", alice_message)

                # Step 5: Receive and decrypt response from Bob
                response_packet = receive_packet(conn)
                if response_packet and response_packet.get("opcode") == 2 and response_packet.get("type") == "AES":
                    encrypted_response_base64 = response_packet["encryption"]
                    encrypted_response = base64.b64decode(encrypted_response_base64)
                    decrypted_message = aes_decrypt(encrypted_response, symmetric_key)
                    print("Decrypted message from Bob:", decrypted_message.decode('utf-8', errors='ignore'))
            else:
                print("Did not receive expected RSA key packet from Bob")

        except ConnectionResetError:
            print("Connection was reset by Bob during communication")
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            print("Protocol 2 completed.\n")

# Server info
SERVER_IP = '127.0.0.1'
PROTOCOL_2_PORT = 5552

# Run Protocol 2
protocol_2(SERVER_IP, PROTOCOL_2_PORT)
