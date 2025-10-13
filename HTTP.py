import socket

class HTTP:
    def __init__(self, method, domain, resurce="", user_agent="example_host"):
        self.method = method
        self.domain = domain
        self.resurce = resurce
        self.user_agent = user_agent

    def create_http_request(self):
        request = f"{self.method} /{self.resurce} HTTP/1.1\r\nHost: {self.domain}\r\nUser-Agent: {self.user_agent}\r\n\r\nAccept: */*\r\n\r\n"
        return request.encode()

    def send_http_request(self, http_request):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.domain, 80))
        sock.send(http_request)
        response = sock.recv(1024)
        return response