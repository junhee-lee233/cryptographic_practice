import socket
import argparse
import logging
import json
import random
import base64
from crypto.Cipher import AES


def decrypt(key, encrypted):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.decrypt(encrypted)


def run(addr, port, number):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((addr, port))
    logging.info("Alice is connected to {}:{}".format(addr, port))
    if number == 1:
        smsg = {}
        smsg["opcode"] = 0
        smsg["type"] = "RSAKey"
        logging.debug("smsg: {}".format(smsg))

        sjs = json.dumps(smsg)
        logging.debug("sjs: {}".format(sjs))

        sbytes = sjs.encode("ascii")
        logging.debug("sbytes: {}".format(sbytes))

        conn.send(sbytes)
        logging.info("[*] Sent: {}".format(sjs))

        rbytes = conn.recv(1024)
        logging.debug("rbytes: {}".format(rbytes))

        rjs = rbytes.decode("ascii")
        logging.debug("rjs: {}".format(rjs))

        rmsg = json.loads(rjs)
        logging.debug("rmsg: {}".format(rmsg))

        def is_prime(n):
            if n % 2 == 0:
                return False
            for i in range(3, int(n**0.5) + 1, 2):
                if n % i == 0:
                    return False
            return True

        def prime_check(p, q):
            if is_prime(p) and is_prime(q):
                return True
            else:
                return False

        def verify_RSA(p, q, e, d):
            n = p * q
            phi = (p - 1) * (q - 1)
            if (e * d) % phi == 1:
                return True
            else:
                return False

        if rmsg["type"] == "RSAKey" and rmsg["opcode"] == 0:
            p = rmsg["parameter"]["p"]
            q = rmsg["parameter"]["q"]
            e = rmsg["public"]
            d = rmsg["private"]

            if prime_check(p, q) and verify_RSA(p, q, e, d):
                logging.info("Alice verified that Bob's RSA key is valid")
                logging.info("p: {}".format(p))
                logging.info("q: {}".format(q))
                logging.info("e: {}".format(e))
                logging.info("d: {}".format(d))
            else:
                logging.error("Alice verified that Bob's RSA key is invalid")

        conn.close()
    if number == 3:
        # Step 1: Send initial message to start DH key exchange
        smsg = {}
        smsg["opcode"] = 0
        smsg["type"] = "DH"
        sjs = json.dumps(smsg)
        conn.send(sjs.encode("ascii"))
        logging.info("[*] Sent initial DH message: {}".format(sjs))

        # Step 2: Receive Bob's DH public key and parameters
        rbytes = conn.recv(1024)
        if not rbytes:
            logging.error("No data received from Bob")
            conn.close()
            return

        # Print raw response from Bob
        logging.info("[*] Raw response from Bob: {}".format(rbytes))

        try:
            rjs = rbytes.decode("ascii")
            rmsg = json.loads(rjs)
            logging.debug("Received message: {}".format(rmsg))

            if rmsg["opcode"] != 1 or rmsg["type"] != "DH":
                raise ValueError("Invalid message format from Bob")

            # Extract Bob's public key and parameters
            bob_public = rmsg["public"]  # Bob's public key is already an integer
            p = rmsg["parameter"]["p"]
            g = rmsg["parameter"]["g"]

            # Step 3: Verify prime and generator
            def is_prime(n):
                if n < 400 or n > 500:  # Check prime range
                    return False
                if n < 2:
                    return False
                if n % 2 == 0:
                    return False
                for i in range(3, int(n**0.5) + 1, 2):
                    if n % i == 0:
                        return False
                return True

            if not is_prime(p) or not (1 < g < p):
                logging.error("Invalid prime or generator received from Bob")
                conn.close()
                return

            # Generate Alice's DH keypair
            alice_private = random.randint(2, p - 1)
            alice_public = pow(g, alice_private, p)

            # Send Alice's public key
            smsg = {"opcode": 1, "type": "DH", "public": alice_public}
            conn.send(json.dumps(smsg).encode("ascii"))
            logging.info("[*] Sent DH public key")

            # Compute shared secret and derive AES key
            shared_secret = pow(bob_public, alice_private, p)
            secret_bytes = shared_secret.to_bytes(2, byteorder="big")
            aes_key = secret_bytes * 16  # Repeat to fill 32 bytes

            # Step 4: Encrypt and send message
            message = "hello"
            encrypted = bytearray()
            for i in range(len(message)):
                encrypted.append(ord(message[i]) ^ aes_key[i % len(aes_key)])

            smsg = {
                "opcode": 2,
                "type": "AES",
                "encryption": base64.b64encode(encrypted).decode(),
            }
            print(smsg)
            conn.send(json.dumps(smsg).encode("ascii"))
            logging.info("[*] Sent encrypted message")

            # Step 6: Receive and decrypt Bob's response
            rbytes = conn.recv(1024)
            if not rbytes:
                logging.error("No response received from Bob")
                conn.close()
                return

            # Print raw encrypted response from Bob
            logging.info("[*] Raw encrypted response from Bob: {}".format(rbytes))
            try:
                rmsg = json.loads(rbytes.decode("ascii"))
                if rmsg["opcode"] == 2 and rmsg["type"] == "AES":
                    # Ensure encryption field exists and decode base64
                    if "encryption" not in rmsg:
                        raise ValueError("Missing encryption field")

                    try:
                        # Base64 decode the encrypted message
                        encrypted_data = base64.b64decode(rmsg["encryption"])
                        logging.debug(
                            "[*] Base64 decoded data: {}".format(encrypted_data.hex())
                        )
                    except:
                        raise ValueError("Invalid base64 encryption data")

                    import crypto
                    import sys

                    sys.modules["Crypto"] = crypto

                    # Create AES cipher object and decrypt
                    cipher = AES.new(aes_key, AES.MODE_ECB)
                    decrypted = cipher.decrypt(encrypted_data)

                    # Remove padding
                    decrypted = decrypted[0 : -ord(decrypted[-1])]

                    # Convert decrypted bytes to string
                    decrypted_message = decrypted.decode("utf-8", errors="ignore")
                    logging.info(
                        "[*] Decrypted message from Bob: {}".format(decrypted_message)
                    )

            except Exception as e:
                logging.error("Error processing Bob's response: {}".format(e))

        except Exception as e:
            logging.error("Error in DH protocol: {}".format(e))
        finally:
            conn.close()


def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-a",
        "--addr",
        metavar="<bob's address>",
        help="Bob's address",
        type=str,
        required=True,
    )
    parser.add_argument(
        "-p",
        "--port",
        metavar="<bob's port>",
        help="Bob's port",
        type=int,
        required=True,
    )
    parser.add_argument(
        "-l",
        "--log",
        metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>",
        help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)",
        type=str,
        default="INFO",
    )
    parser.add_argument(
        "-n",
        "--number",
        metavar="<number of protocol>",
        help="Number of protocol",
        type=int,
        default=1,
    )
    args = parser.parse_args()
    return args


def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    run(args.addr, args.port, args.number)


if __name__ == "__main__":
    main()
