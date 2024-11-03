import json
import socket
import argparse
import logging

def is_prime(n):
    """소수 판별 함수"""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def is_valid_generator(g, p):
    """제너레이터 판별 함수"""
    def factorize(n):
        # 소인수분해 함수 (p-1의 소인수를 구하기 위함)
        factors = []
        i = 2
        while i * i <= n:
            while (n % i) == 0:
                factors.append(i)
                n //= i
            i += 1
        if n > 1:
            factors.append(n)
        return factors

    # p가 소수라면 p-1의 모든 소인수를 구합니다.
    factors = factorize(p - 1)
    
    # g^( (p-1) / q ) mod p가 1이 아닌지 확인하여 제너레이터 판별
    for q in factors:
        if pow(g, (p - 1) // q, p) == 1:
            return False
    return True

def validate_packet(packet):
    """패킷의 형식과 필수 필드 검증"""
    required_fields = ["opcode", "type", "public", "parameter"]
    parameter_fields = ["p", "g"]

    # 필수 필드 확인
    for field in required_fields:
        if field not in packet:
            print(f"Packet validation error: Missing field '{field}'")
            return False

    # 패킷의 필드 값 형식 확인
    if not isinstance(packet["opcode"], int) or packet["opcode"] != 1:
        print("Packet validation error: 'opcode' should be integer 1")
        return False
    if not isinstance(packet["type"], str) or packet["type"] != "DH":
        print("Packet validation error: 'type' should be 'DH'")
        return False
    # public 필드를 문자열 또는 정수로 허용
    if not isinstance(packet["public"], (str, int)):
        print("Packet validation error: 'public' should be a string or integer")
        return False
    if not isinstance(packet["parameter"], dict):
        print("Packet validation error: 'parameter' should be a dictionary")
        return False
    
    # parameter 필드 내 필수 항목 확인
    for field in parameter_fields:
        if field not in packet["parameter"]:
            print(f"Packet validation error: Missing 'parameter' field '{field}'")
            return False
    
    return True

def communicate_with_server(addr, port):
    """서버와 통신하여 초기 메시지를 전송하고, 수신한 메시지를 검증 및 응답"""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((addr, port))
    logging.info("Alice is connected to {}:{}".format(addr, port))

    try:
        # Step 1: 초기 메시지 전송
        initial_message = {"opcode": 0, "type": "DH"}
        client_socket.sendall(json.dumps(initial_message).encode())
        logging.info("Sent initial message: %s", json.dumps(initial_message))

        # Step 2: 서버로부터 응답 수신
        response = client_socket.recv(1024).decode()
        received_message = json.loads(response)
        logging.info("Received message from server: %s", json.dumps(received_message))

        # Step 3: 수신한 패킷 검증
        if not validate_packet(received_message):
            error_message = {"opcode": 3, "error": "invalid packet format"}
            logging.info("Alice response: %s", json.dumps(error_message))
            client_socket.sendall(json.dumps(error_message).encode())
            return

        # Step 4: 수신한 p와 g 값 검증
        p = received_message["parameter"]["p"]
        g = received_message["parameter"]["g"]

        prime_check = is_prime(p)
        generator_check = is_valid_generator(g, p) if prime_check else False

        # Step 5: 오류 메시지 또는 성공 메시지 생성 및 전송
        if not prime_check and not generator_check:
            error_message = {"opcode": 3, "error": "both incorrect prime and incorrect generator"}
            logging.info("Alice response: %s", json.dumps(error_message))
            client_socket.sendall(json.dumps(error_message).encode())
        elif not prime_check:
            error_message = {"opcode": 3, "error": "incorrect prime number"}
            logging.info("Alice response: %s", json.dumps(error_message))
            client_socket.sendall(json.dumps(error_message).encode())
        elif not generator_check:
            error_message = {"opcode": 3, "error": "incorrect generator"}
            logging.info("Alice response: %s", json.dumps(error_message))
            client_socket.sendall(json.dumps(error_message).encode())
        else:
            success_message = {"opcode": 2, "status": "success"}
            logging.info("Alice response: %s", json.dumps(success_message))
            client_socket.sendall(json.dumps(success_message).encode())
    
    except Exception as e:
        logging.error("Error during communication: %s", e)
    
    finally:
        client_socket.close()
        logging.info("Disconnected from server")

def command_line_args():
    """명령줄 인수 처리"""
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's address>", help="Bob's address", type=str, required=True)
    parser.add_argument("-p", "--port", metavar="<bob's port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = getattr(logging, args.log.upper(), logging.INFO)
    logging.basicConfig(level=log_level)

    # 서버와 통신 수행
    communicate_with_server(args.addr, args.port)

if __name__ == "__main__":
    main()

# 서버 주소와 포트 설정
# server_address = "10.41.12.52"  # 서버 IP 주소를 입력하세요
# server_port = 5554  # 서버 포트를 입력하세요

# 서버와 통신 수행
# communicate_with_server(server_address, server_port)
