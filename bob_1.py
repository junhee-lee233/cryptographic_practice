import socket
import threading
import argparse
import logging
import json
import random


def is_prime(n):
    if n % 2 == 0:
        return False
    for i in range(3, int(n**0.5) + 1, 2):
        if n % i == 0:
            return False
    return True


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def gen_prime():
    num = random.randint(400, 500)
    num2 = random.randint(400, 500)
    if num == num2:
        return gen_prime()
    if is_prime(num) and is_prime(num2):
        return num, num2
    else:
        return gen_prime()


def gen_RSA():
    p, q = gen_prime()
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randint(2, phi - 1)
    while gcd(e, phi) != 1:
        e = random.randint(2, phi - 1)
    d = pow(e, -1, phi)
    return p, q, e, d


def handler(conn, number):
    rbytes = conn.recv(1024)
    logging.debug("rbytes: {}".format(rbytes))

    rjs = rbytes.decode("ascii")
    logging.debug("rjs: {}".format(rjs))

    rmsg = json.loads(rjs)
    logging.debug("rmsg: {}".format(rmsg))
    if number == 1:
        if rmsg["type"] == "RSAKey" and rmsg["opcode"] == 0:
            p, q, e, d = gen_RSA()

        smsg = {}
        smsg["opcode"] = 0
        smsg["type"] = "RSAKey"
        smsg["private"] = d
        smsg["public"] = e
        smsg["parameter"] = {}
        smsg["parameter"]["p"] = p
        smsg["parameter"]["q"] = q
        logging.debug("smsg: {}".format(smsg))

        sjs = json.dumps(smsg)
        logging.debug("sjs: {}".format(sjs))

        sbytes = sjs.encode("ascii")
        logging.debug("sbytes: {}".format(sbytes))

        conn.send(sbytes)
        logging.info("[*] Sent: {}".format(sjs))

        conn.close()

    if number == 3:
        # Step 1: Receive initial DH message from Alice
        if rmsg["opcode"] == 0 and rmsg["type"] == "DH":
            # Step 2: Generate DH parameters and keypair
            # Generate prime between 400-500 using gen_prime()
            p, _ = gen_prime()  # We only need one prime for DH

            g = random.randint(2, p - 1)  # Generator
            bob_private = random.randint(2, p - 1)
            bob_public = pow(g, bob_private, p)

            # Send public key and parameters
            smsg = {}
            smsg["opcode"] = 1
            smsg["type"] = "DH"
            smsg["public"] = bob_public
            smsg["parameter"] = {"p": p, "g": g}
            sjs = json.dumps(smsg)
            conn.send(sjs.encode("ascii"))
            logging.info("[*] Sent DH public key: {}".format(sjs))

            # Step 4-5: Receive encrypted message from Alice
            rbytes = conn.recv(1024)
            rmsg = json.loads(rbytes.decode("ascii"))
            if rmsg["opcode"] == 2 and rmsg["type"] == "AES":
                # Compute shared secret
                alice_public = bob_public  # From previous exchange
                shared_secret = pow(alice_public, bob_private, p)

                # Generate AES key
                secret_bytes = shared_secret.to_bytes(2, byteorder="big")
                aes_key = secret_bytes * 16  # Repeat to fill 32 bytes

                # Decrypt Alice's message using XOR
                encrypted = bytes.fromhex(rmsg["encryption"])
                decrypted = ""
                for i in range(len(encrypted)):
                    decrypted += chr(encrypted[i] ^ aes_key[i % len(aes_key)])
                logging.info("[*] Decrypted message from Alice: {}".format(decrypted))

                # Encrypt and send response
                response = "world"
                encrypted = bytearray()
                for i in range(len(response)):
                    encrypted.append(ord(response[i]) ^ aes_key[i % len(aes_key)])

                encrypted_str = "".join([format(b, "02x") for b in encrypted])

                smsg = {}
                smsg["opcode"] = 2
                smsg["type"] = "AES"
                smsg["encryption"] = encrypted_str
                sjs = json.dumps(smsg)
                conn.send(sjs.encode("ascii"))
                logging.info("[*] Sent encrypted response: {}".format(sjs))
            else:
                logging.error("Unexpected message type from Alice")
        else:
            logging.error("Invalid initial DH message from Alice")


def run(addr, port, number):
    bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob.bind((addr, port))

    bob.listen(10)
    logging.info("[*] Bob is listening on {}:{}".format(addr, port))

    while True:
        conn, info = bob.accept()

        logging.info(
            "[*] Bob accepts the connection from {}:{}".format(info[0], info[1])
        )

        conn_handle = threading.Thread(target=handler, args=(conn, number))
        conn_handle.start()


def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-a",
        "--addr",
        metavar="<bob's IP address>",
        help="Bob's IP address",
        type=str,
        default="0.0.0.0",
    )
    parser.add_argument(
        "-p",
        "--port",
        metavar="<bob's open port>",
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
        metavar="<The number of protocol>",
        help="The number of protocol",
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
