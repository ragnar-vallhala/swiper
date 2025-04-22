#include "packetcapture.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <QDateTime>
#include <QDebug>

const int MAX_PACKETS_PER_SECOND = 100; // Adjust as needed
auto lastTime = std::chrono::steady_clock::now();
int packetCount = 0;

PacketCapture::PacketCapture(const QString &interface,
                             const QString &protocol,
                             const QString &filter,
                             QObject *parent)
    : QThread(parent), interface(interface), protocol(protocol), filter(filter), running(true), handle(nullptr)
{
}

PacketCapture::~PacketCapture()
{
    stop();
    wait();
}

void PacketCapture::stop()
{
    running = false;
    if (handle)
    {
        pcap_breakloop(handle);
    }
}

QString PacketCapture::createHexDump(const u_char *data, int len)
{
    if (len <= 0)
        return "No data";

    const int bytesPerLine = 16;
    QString output;
    output.reserve(len * 4); // Pre-allocate memory

    for (int i = 0; i < len; i += bytesPerLine)
    {
        // Hex portion
        QString hexLine;
        QString asciiLine;

        for (int j = 0; j < bytesPerLine && (i + j) < len; j++)
        {
            u_char byte = data[i + j];
            hexLine += QString::asprintf("%02x ", byte);
            asciiLine += (byte >= 32 && byte <= 126) ? QChar(byte) : '.';
        }

        output += QString("%1: %2 | %3\n")
                      .arg(i, 4, 16, QChar('0'))
                      .arg(hexLine.leftJustified(bytesPerLine * 3, ' '))
                      .arg(asciiLine);
    }

    return output;
}

void PacketCapture::run()
{
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(interface.toStdString().c_str(),
                            BUFSIZ, 1, 1000, errbuf);

    if (handle == nullptr)
    {
        qDebug() << "Couldn't open device" << interface << ":" << errbuf;
        return;
    }

    struct bpf_program fp;
    std::string filter_str = filter.toStdString();

    if (pcap_compile(handle, &fp, filter_str.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        qDebug() << "Couldn't parse filter" << filter_str.c_str() << ":"
                 << pcap_geterr(handle);
        pcap_close(handle);
        return;
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        qDebug() << "Couldn't install filter" << filter_str.c_str() << ":"
                 << pcap_geterr(handle);
        pcap_close(handle);
        return;
    }

    while (running)
    {
        // Rate limiting
        auto now = std::chrono::steady_clock::now();
        if (packetCount >= MAX_PACKETS_PER_SECOND)
        {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastTime);
            if (elapsed.count() < 1000)
            {
                QThread::msleep(10);
                continue;
            }
            packetCount = 0;
            lastTime = now;
        }

        struct pcap_pkthdr header;
        const u_char *packet = pcap_next(handle, &header);
        if (!packet)
            continue;

        processPacket(&header, packet);
        packetCount++;
    }

    pcap_freecode(&fp);

    qDebug() << "Started capturing with filter:" << filter;

    while (running)
    {
        struct pcap_pkthdr header;
        const u_char *packet = pcap_next(handle, &header);

        if (packet == nullptr)
            continue;

        processPacket(&header, packet);
    }

    pcap_close(handle);
    handle = nullptr;
}

void PacketCapture::processPacket(const struct pcap_pkthdr *pkthdr,
                                  const u_char *packet)
{
    struct ether_header *eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
    {
        return;
    }

    const u_char *ip_packet = packet + sizeof(struct ether_header);
    struct ip *ip_header = (struct ip *)ip_packet;

    PacketInfo info;
    info.timestamp = QDateTime::currentDateTime().toString("hh:mm:ss.zzz");
    info.sourceIP = QString(inet_ntoa(ip_header->ip_src));
    info.destIP = QString(inet_ntoa(ip_header->ip_dst));
    info.length = pkthdr->len;

    int ip_header_len = ip_header->ip_hl * 4;
    const u_char *transport_header = ip_packet + ip_header_len;
    int transport_header_len = 0;
    QString protocolDetails;

    switch (ip_header->ip_p)
    {
    case IPPROTO_TCP:
    {
        info.protocol = "TCP";
        struct tcphdr *tcp_header = (struct tcphdr *)transport_header;
        transport_header_len = tcp_header->th_off * 4;

        uint16_t source_port = ntohs(tcp_header->th_sport);
        uint16_t dest_port = ntohs(tcp_header->th_dport);

        info.sourceIP = QString("%1:%2").arg(info.sourceIP).arg(source_port);
        info.destIP = QString("%1:%2").arg(info.destIP).arg(dest_port);

        protocolDetails = QString("TCP Header:\n"
                                  "Source Port: %1\n"
                                  "Destination Port: %2\n"
                                  "Sequence Number: %3\n"
                                  "Acknowledgment Number: %4\n"
                                  "Flags: %5%6%7%8%9%10\n")
                              .arg(source_port)
                              .arg(dest_port)
                              .arg(ntohl(tcp_header->th_seq))
                              .arg(ntohl(tcp_header->th_ack))
                              .arg(tcp_header->th_flags & TH_FIN ? "FIN " : "")
                              .arg(tcp_header->th_flags & TH_SYN ? "SYN " : "")
                              .arg(tcp_header->th_flags & TH_RST ? "RST " : "")
                              .arg(tcp_header->th_flags & TH_PUSH ? "PSH " : "")
                              .arg(tcp_header->th_flags & TH_ACK ? "ACK " : "")
                              .arg(tcp_header->th_flags & TH_URG ? "URG" : "");
        break;
    }
    case IPPROTO_UDP:
    {
        info.protocol = "UDP";
        struct udphdr *udp_header = (struct udphdr *)transport_header;
        transport_header_len = sizeof(struct udphdr);

        uint16_t source_port = ntohs(udp_header->uh_sport);
        uint16_t dest_port = ntohs(udp_header->uh_dport);

        info.sourceIP = QString("%1:%2").arg(info.sourceIP).arg(source_port);
        info.destIP = QString("%1:%2").arg(info.destIP).arg(dest_port);

        protocolDetails = QString("UDP Header:\n"
                                  "Source Port: %1\n"
                                  "Destination Port: %2\n"
                                  "Length: %3\n")
                              .arg(source_port)
                              .arg(dest_port)
                              .arg(ntohs(udp_header->uh_ulen));
        break;
    }
    case IPPROTO_ICMP:
    {
        info.protocol = "ICMP";
        struct icmphdr *icmp_header = (struct icmphdr *)transport_header;
        transport_header_len = sizeof(struct icmphdr);

        QString icmpType;
        switch (icmp_header->type)
        {
        case ICMP_ECHOREPLY:
            icmpType = "Echo Reply";
            break;
        case ICMP_DEST_UNREACH:
            icmpType = "Destination Unreachable";
            break;
        case ICMP_SOURCE_QUENCH:
            icmpType = "Source Quench";
            break;
        case ICMP_REDIRECT:
            icmpType = "Redirect";
            break;
        case ICMP_ECHO:
            icmpType = "Echo Request";
            break;
        case ICMP_TIME_EXCEEDED:
            icmpType = "Time Exceeded";
            break;
        case ICMP_PARAMETERPROB:
            icmpType = "Parameter Problem";
            break;
        case ICMP_TIMESTAMP:
            icmpType = "Timestamp Request";
            break;
        case ICMP_TIMESTAMPREPLY:
            icmpType = "Timestamp Reply";
            break;
        case ICMP_INFO_REQUEST:
            icmpType = "Information Request";
            break;
        case ICMP_INFO_REPLY:
            icmpType = "Information Reply";
            break;
        default:
            icmpType = QString::number(icmp_header->type);
            break;
        }

        protocolDetails = QString("ICMP Header:\n"
                                  "Type: %1 (%2)\n"
                                  "Code: %3\n")
                              .arg(icmp_header->type)
                              .arg(icmpType)
                              .arg(icmp_header->code);
        break;
    }
    default:
        info.protocol = QString::number(ip_header->ip_p);
        transport_header_len = 0;
    }

    const u_char *payload = transport_header + transport_header_len;
    int payload_len = pkthdr->len - (payload - packet);

    if (payload_len > 0)
    {
        info.hexDump = createHexDump(payload, std::min(payload_len, 256));
    }
    else
    {
        info.hexDump = "No payload";
    }

    info.details = QString("IP Header:\n"
                           "Version: %1\n"
                           "Header Length: %2 bytes\n"
                           "Total Length: %3 bytes\n"
                           "TTL: %4\n\n"
                           "%5\n"
                           "Payload (%6 bytes):\n"
                           "%7")
                       .arg(ip_header->ip_v)
                       .arg(ip_header_len)
                       .arg(ntohs(ip_header->ip_len))
                       .arg(ip_header->ip_ttl)
                       .arg(protocolDetails)
                       .arg(payload_len)
                       .arg(info.hexDump);

    emit packetCaptured(info);
}