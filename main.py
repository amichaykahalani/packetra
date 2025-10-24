from DNS import DNS
from NTP import NTP
from NetworkTransfer import NetworkTransfer

def main():
    question_object = DNS("youtube.com")
    question = question_object.to_binary()
    answer_object = DNS("youtube.com", is_response=True)
    answer_object.deserializer(NetworkTransfer.send_and_received(question,
                                                                '8.8.8.8',
                                                                53,
                                                                'UDP'))

    answer_object.pretty_print()
    ntp_object = NTP()
    packet = ntp_object.to_bytes()
    answer = NetworkTransfer.send_and_received(packet, 'pool.ntp.org', 123, protocol='UDP')
    print("answer: {}".format(answer))
if __name__ == '__main__':
    main()
