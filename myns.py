# Name:Fraydi Goldstein

from scapy.all import *
import sys


def main():
    if sys.argv[1] == 'type=A':
        parameter = sys.argv[2]
        dns_packet = IP(dst='8.8.8.8')/UDP(sport=24601, dport=53)/DNS(qdcount=1)/DNSQR(qname=parameter)
        answer_packet = sr1(dns_packet, verbose=0)
        num_answers = answer_packet[DNS].ancount
        num_addresses = 0
        for i in range(num_answers):
            if answer_packet[DNSRR][i].type == 1:
                num_addresses += 1
        print("Non-authoritative answer: ")
        print("Name: ", end='')
        help_num = 0
        while help_num <= num_answers:
            if answer_packet[DNSRR][help_num].type == 1:
                print(answer_packet[DNSRR][help_num].rrname[0:-1:].decode())
                break
            help_num += 1
        if num_addresses == 1:
            print("Address: ", end='')
            print(answer_packet[DNSRR][help_num].rdata)
        if num_addresses > 1:
            print("Addresses: ", end='')
            for i in range(num_answers):
                if answer_packet[DNSRR][i].type == 1:
                    print(answer_packet[DNSRR][i].rdata)
        if num_answers > 1:
            print("Aliases: ", end='')
            for i in range(num_answers):
                if answer_packet[DNSRR][i].type == 5:
                    print(answer_packet[DNSRR][i].rrname[0:-1:].decode())
    if sys.argv[1] == 'type=PTR':
        parameter = sys.argv[2]
        split_parameter = parameter.split('.')
        parameter = ''
        for i in split_parameter[-1::-1]:
            parameter += ("{}.".format(i))
        parameter += 'in-addr.arpa'
        dns_packet = IP(dst='8.8.8.8') / UDP(sport=24601, dport=53) / DNS(qdcount=1) / DNSQR(qtype='PTR',qname=parameter)
        answer_packet = sr1(dns_packet, verbose=0)
        num_answers = answer_packet[DNS].ancount
        print("Non-authoritative answer: ")
        if num_answers == 1:
            print(answer_packet[DNSRR].rrname[0:-1:].decode(), end='     ')
            print("name = ", answer_packet[DNSRR].rdata[0:-1:].decode())
        else:
            for i in range(num_answers):
                print(answer_packet[DNSRR][i].rrname[0:-1:].decode(), end='     ')
                print("name = ", answer_packet[DNSRR][i].rdata[0:-1:].decode())


if __name__ == '__main__':
    main()
