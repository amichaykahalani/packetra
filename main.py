from DNS import DNS
from HTTP import HTTP

def main():
    dns = DNS()
    dns_quest = dns.creat_dns_question('www.youtube.com', QTYPE=1)
    answer = dns.sent_dns_question(dns_quest)
    ip = DNS.return_ip_from_dns_answer(answer)
    print(answer)
    print(ip)
    http = HTTP('GET', 'www.google.com')
    http_request = http.create_http_request()
    answer = http.send_http_request(http_request)
    print(answer)

if __name__ == '__main__':
    main()
