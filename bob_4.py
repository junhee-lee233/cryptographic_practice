import json
import socket
import threading
import argparse
import logging
import random
from sympy import isprime

def generate_prime_in_range(start, end):
    """주어진 범위에서 임의의 소수를 생성합니다."""
    p = random.randint(start, end)
    while not isprime(p):
        p = random.randint(start, end)
    return p

def choose_invalid_generator(p):
    """유효하지 않은 제너레이터 g를 선택합니다."""
    return p - 1  # 일반적으로 유효하지 않은 값으로 설정합니다.

def validate_packet(packet, expected_opcode):
    """패킷의 형식과 필수 필드를 검증하고 opcode가 예상한 값인지 확인합니다."""
    required_fields = ["opcode", "type"]
    for field in required_fields:
        if field not in packet:
            logging.error(f"Packet validation error: Missing field '{field}'")
            return False
    if packet["opcode"] != expected_opcode or packet["type"] != "DH":
        logging.error("Packet validation error: Incorrect opcode or type")
        return False
    return True

def handle_client(conn, addr):
    """각 클라이언트(Alice)와 통신하는 핸들러"""
    logging.info("[*] Connected by Alice at {}:{}".format(addr[0], addr[1]))

    try:
        # Step 1: Alice로부터 초기 메시지 수신
        data = conn.recv(1024).decode()
        if not data:
            return
        initial_message = json.loads(data)
        logging.info("Received message from Alice: %s", json.dumps(initial_message))

        # Step 2: 패킷 검증
        if not validate_packet(initial_message, expected_opcode=0):
            error_message = {"opcode": 3, "error": "invalid packet format"}
            conn.sendall(json.dumps(error_message).encode())
            logging.info("Sent error response to Alice: %s", json.dumps(error_message))
            return

        # Step 3: Diffie-Hellman p와 유효하지 않은 g 값 생성 및 전송
        p = generate_prime_in_range(400, 500)  # 400과 500 사이의 임의의 소수 생성
        g = choose_invalid_generator(p)  # 유효하지 않은 제너레이터 값 선택
        dh_message = {
            "opcode": 1,
            "type": "DH",
            "public": "Base64_encoded_public_key_placeholder",
            "parameter": {"p": p, "g": g}
        }
        conn.sendall(json.dumps(dh_message).encode())
        logging.info("Sent DH parameters to Alice: %s", json.dumps(dh_message))

        # Step 4: Alice로부터 응답 수신
        response = conn.recv(1024).decode()
        if response:
            alice_response = json.loads(response)
            logging.info("Received response from Alice: %s", json.dumps(alice_response))

    except Exception as e:
        logging.error("Error during communication with Alice: %s", e)
    
    finally:
        conn.close()
        logging.info("Disconnected from Alice")

def run(addr, port):
    """Bob 서버 실행: 여러 클라이언트와 스레드로 통신합니다."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((addr, port))
    server_socket.listen(10)
    logging.info("[*] Bob is listening on {}:{}".format(addr, port))

    while True:
        conn, client_addr = server_socket.accept()
        logging.info("[*] Bob accepts the connection from {}:{}".format(client_addr[0], client_addr[1]))

        # 각 연결을 스레드로 처리하여 동시에 여러 클라이언트를 처리합니다.
        conn_handle = threading.Thread(target=handle_client, args=(conn, client_addr))
        conn_handle.start()

def command_line_args():
    """명령줄 인수 처리"""
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's IP address>", help="Bob's IP address", type=str, default="0.0.0.0")
    parser.add_argument("-p", "--port", metavar="<bob's open port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = getattr(logging, args.log.upper(), logging.INFO)
    logging.basicConfig(level=log_level)

    # 서버 실행
    run(args.addr, args.port)

if __name__ == "__main__":
    main()
