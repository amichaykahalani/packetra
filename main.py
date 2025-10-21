from DNS import DNS
from NetworkTransfer import NetworkTransfer

def main():
    question_object = DNS("youtube.com", record_type="IPv4")
    question = question_object.to_binary()
    answer_object = DNS("youtube.com", is_response=True, record_type="IPv6")
    answer_object.deserializer(NetworkTransfer.send_and_received(question,
                                                                '8.8.8.8',
                                                                53,
                                                                'UDP'))

    answer_object.pretty_print()

if __name__ == '__main__':
    main()
