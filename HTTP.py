import socket

class HTTP:
    def __init__(self, host, method="GET"):
        #-------status_line-------------
        self.status_line = f"{method.upper()} / HTTP/1.1\r\n"

        #-------header------------------
        self.host = f"Host: {host}\r\n"
        self.user_agent = f"User-Agent: Mybrowser1.0\r\n"
        self.accept = f"Accept: text/html\r\n\r\n"

        if method.upper() == "POST":
            #--------body--------
            self.data = {'username':'admin',
                         'password':'1234'}

    def serializer(self):
        packet = self.status_line + self.host + self.user_agent + self.accept
        return packet.encode()

    @staticmethod
    def deserializer(packet):
        dicts = packet.decode().split("\r\n")
        for dict in dicts:
            print(dict)




