import socket
from dnslib import DNSRecord, DNSHeader, DNSQuestion, QTYPE, RCODE
from dnslib.server import DNSServer, BaseResolver
from dnslib.dns import AAAA, RR
import subprocess
import ipaddress
import threading
import re
import time
from datetime import datetime, timedelta
import psutil
import sqlite3
#
# Abdulkader Alrezej
class RedirectingResolver(BaseResolver):
    def __init__(self, redirect_ip_if_not_in_nft, redirect_ip_if_in_nft, external_domains_file, upstream_dns="8.8.4.4"):
        self.redirect_ip_if_not_in_nft = redirect_ip_if_not_in_nft
        self.redirect_ip_if_in_nft = redirect_ip_if_in_nft
        self.upstream_dns = upstream_dns
        self.redirect_domains = [
            'connectivitycheck.gstatic.com',
            'clients3.google.com',
            'captive.apple.com',
            'www.captive.apple.com',
            'www.apple.com',
            'apple.com',
            'msftconnecttest.com',
            'www.msftconnecttest.com',
            'msftncsi.com',
            'www.msftncsi.com',
            'ipv6.msftconnecttest.com',
            'nmcheck.gnome.org',
            'www.nmcheck.gnome.org',
            'networkcheck.kde.org',
            'www.networkcheck.kde.org',
            'connect.rom.miui.com'
        ]  
        self.nft_redirect_domains = [
            'connectivitycheck.gstatic.com',
            'clients3.google.com',
            'captive.apple.com',
            'www.captive.apple.com',
            'www.apple.com',
            'apple.com',
            'msftconnecttest.com',
            'www.msftconnecttest.com',
            'msftncsi.com',
            'www.msftncsi.com',
            'ipv6.msftconnecttest.com',
            'nmcheck.gnome.org',
            'www.nmcheck.gnome.org',
            'networkcheck.kde.org',
            'www.networkcheck.kde.org',
            'connect.rom.miui.com'
        ]
        self.load_additional_domains_from_db('/mnt/cerr/main_sqlite3_database.db')
        self.external_domains = self.load_domains_from_file(external_domains_file)
    def load_additional_domains_from_db(self, db_path):
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT name_network FROM info_admin")
            rows = cursor.fetchall()
            for row in rows:
                domain = row[0]
                if domain not in self.nft_redirect_domains:
                    self.nft_redirect_domains.append(domain)
            conn.close()
        except Exception as e:
            pass
    def load_domains_from_file(self, file_path):
        try:
            with open(file_path, 'r') as file:
                domains = [re.compile(re.escape(line.strip()).replace(r'\*', '.*')) for line in file.readlines() if line.strip()]
            return domains
        except Exception as e:
            return []
    def is_ip_in_nft(self, ip):
        try:
            result = subprocess.run(
                ['nft', 'list', 'ruleset'],
                capture_output=True,
                text=True
            )
            return ip in result.stdout
        except Exception as e:
            return False
    def ipv4_to_ipv6(self, ipv4_address):
        ipv4 = ipaddress.IPv4Address(ipv4_address)
        ipv6 = ipaddress.IPv6Address(f'64:ff9b::{ipv4}')
        return ipv6.exploded
    def get_ipv4_from_upstream(self, qname):
        try:
            return socket.gethostbyname(qname)
        except Exception as e:
            return None
    def is_domain_in_list(self, qname, domain_list):
        return any(domain.match(qname) for domain in domain_list)
    def resolve(self, request, handler):
        qname = str(request.q.qname)
        qtype = request.q.qtype
        client_ip = handler.client_address[0]
        try:
            if qtype == QTYPE.PTR:
                return self.forward_to_upstream(request)
            if any(qname.startswith(domain) for domain in self.redirect_domains) and qtype == QTYPE.AAAA:
                if not self.is_ip_in_nft(client_ip):
                    reply = DNSRecord(
                        header=DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, rcode=0),
                        q=DNSQuestion(request.q.qname, qtype)
                    )
                    reply.add_answer(RR(request.q.qname, QTYPE.AAAA, rdata=AAAA(self.redirect_ip_if_not_in_nft)))
                    return reply
            if any(qname.startswith(domain) for domain in self.nft_redirect_domains) and qtype == QTYPE.AAAA:
                if self.is_ip_in_nft(client_ip):
                    reply = DNSRecord(
                        header=DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, rcode=0),
                        q=DNSQuestion(request.q.qname, qtype)
                    )
                    reply.add_answer(RR(request.q.qname, QTYPE.AAAA, rdata=AAAA(self.redirect_ip_if_in_nft)))
                    return reply
            if self.is_domain_in_list(qname, self.external_domains) and qtype == QTYPE.AAAA:
                if self.is_ip_in_nft(client_ip):
                    reply = DNSRecord(
                        header=DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, rcode=0),
                        q=DNSQuestion(request.q.qname, qtype)
                    )
                    reply.add_answer(RR(request.q.qname, QTYPE.AAAA, rdata=AAAA(self.redirect_ip_if_in_nft)))
                    return reply
            if qtype == QTYPE.AAAA and self.is_ip_in_nft(client_ip):
                if not any(qname.startswith(domain) for domain in self.redirect_domains) and not any(qname.startswith(domain) for domain in self.nft_redirect_domains) and not self.is_domain_in_list(qname, self.external_domains):
                    ipv4_address = self.get_ipv4_from_upstream(qname.strip('.'))
                    if ipv4_address:
                        ipv6_address = self.ipv4_to_ipv6(ipv4_address)
                        reply = DNSRecord(
                            header=DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, rcode=0),
                            q=DNSQuestion(request.q.qname, QTYPE.AAAA)
                        )
                        reply.add_answer(RR(request.q.qname, QTYPE.AAAA, rdata=AAAA(ipv6_address)))
                        return reply
                    else:
                        reply = DNSRecord(
                            header=DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, rcode=RCODE.NXDOMAIN),
                            q=DNSQuestion(request.q.qname, qtype)
                        )
                        return reply
                else:
                    return self.forward_to_upstream(request)
            else:
                return self.forward_to_upstream(request)
        except Exception as e:
            reply = DNSRecord(
                header=DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, rcode=RCODE.SERVFAIL),
                q=DNSQuestion(request.q.qname, qtype)
            )
            return reply
    def forward_to_upstream(self, request):
        try:
            query = DNSRecord(question=request.q)
            response = query.send(self.upstream_dns, 53)
            answer = DNSRecord.parse(response)
            return answer
        except Exception as e:
            return DNSRecord(
                header=DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, rcode=RCODE.SERVFAIL),
                q=request.q
            )
def start_dns_server(duration=None):
    redirect_ip_if_not_in_nft = '2002:db9::2'
    redirect_ip_if_in_nft = '2002:db7::2'
    external_domains_file = '/mnt/cerr/external_domains.txt'
    resolver = RedirectingResolver(redirect_ip_if_not_in_nft, redirect_ip_if_in_nft, external_domains_file)
    udp_server = DNSServer(resolver, port=53, address='::', tcp=False)
    tcp_server = DNSServer(resolver, port=53, address='::', tcp=True)
    udp_thread = threading.Thread(target=udp_server.start)
    tcp_thread = threading.Thread(target=tcp_server.start)
    udp_thread.start()
    tcp_thread.start()
    if duration:
        time.sleep(duration)
        udp_server.stop()
        tcp_server.stop()
    else:
        udp_thread.join()
        tcp_thread.join()
if __name__ == "__main__":
    start_dns_server()
