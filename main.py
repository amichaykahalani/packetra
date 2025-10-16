from DNS import DNS
from NetworkTransfer import NetworkTransfer

def main():
    domain = input('Enter domain name (ex. google.com): ')
    dns = DNS(domain, record_type='IPv4')
    dns_bytes = dns.serializer()
    answer = NetworkTransfer.send_and_received(dns_bytes, '8.8.8.8', 53, protocol="UDP")
    result = dns.deserializer(answer)
    dns.pretty_print(result)

if __name__ == '__main__':
    main()
