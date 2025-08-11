#include "tpcaptransfer.h"
#include <QCoreApplication>
#include <QDebug>
#include <QDir>
#include <QEventLoop>
#include <QTimer>
#include <QHostAddress>

TPCAPWork::TPCAPWork(QObject *parent) : QObject(parent)
{
    qRegisterMetaType<TPcapPacket>("TPcapPacket");
    qRegisterMetaType<TPcapStats>("TPcapStats");
}

TPCAPWork::~TPCAPWork()
{
    if (m_handle) {
        close();
    }
}

void TPCAPWork::openDevice(const QString &deviceName, bool isSave ,int snaplen, bool promisc, int timeout)
{
//    qDebug() << "TPCAPWork::openDevice - Entered with parameters:"<< "  Device Name:"
//             << deviceName<< "  Is Save:" << isSave<< "  Snaplen:" << snaplen
//             << "  Promisc:" << promisc<< "  Timeout:" << timeout;

    if (m_handle) {
        close();
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    //捕获句柄
    m_handle = pcap_open_live(deviceName.toLocal8Bit().data(), snaplen, promisc ? 1 : 0, timeout, errbuf);

    if (m_handle == nullptr) {
        m_isOpen.storeRelease(0);  // 设置为关闭状态
        emit errorOccurred(QString("Failed to open device: %1").arg(errbuf));
        return;
    }

    m_isOpen.storeRelease(1);  // 设置为打开状态
    if(isSave)
    {
        m_enableDump = isSave;
        QDateTime currentTime = QDateTime::currentDateTime();
        QString fileName = currentTime.toString("yyyyMMdd_HHmmss");
        fileName +=".pcap";
        QDir dir;
        dir.mkpath("pcap_captures");
        fileName = "pcap_captures/" +fileName;
        //使用设置的文件名
        //打开用于写入数据的文件 例如open
        m_dumper = pcap_dump_open(m_handle, fileName.toLocal8Bit().data());
        if (!m_dumper) {
            emit errorOccurred(QString("Failed to open pcap file %1: %2").arg(fileName).arg(pcap_geterr(m_handle)));
            //            pcap_close(m_handle);
            //            m_handle = nullptr;
            m_enableDump = false;  // 禁用保存功能
        }
    }
    emit deviceStatus(m_isOpen.loadAcquire() != 0);
}

void TPCAPWork::openFile(const QString &filename)
{
    if (m_handle) {
        close();
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    //打开已保存的数据文件
    m_handle = pcap_open_offline(filename.toLocal8Bit().data(), errbuf);

    if (m_handle == nullptr) {
        emit errorOccurred(QString("Failed to open file: %1").arg(errbuf));
    }
}

void TPCAPWork::close()
{
    stopCapture();

    if (m_dumper)
    {
        pcap_dump_flush(m_dumper);
        pcap_dump_close(m_dumper);
        m_dumper = nullptr;
    }
    if (m_handle) {
        pcap_close(m_handle);
        m_handle = nullptr;
    }
    m_isOpen.storeRelease(0);  // 设置为关闭状态
}

void TPCAPWork::startCapture()
{
    if (!m_handle || m_capturing) {
        return;
    }

    m_capturing = true;
    m_isCapturing.storeRelease(1);  // 设置为捕获中

    // 设置非阻塞模式
    if (pcap_setnonblock(m_handle, 1, nullptr) == -1)
    {
        emit errorOccurred("Failed to set non-blocking mode");
        m_capturing = false;
        return;
    }

    struct pcap_pkthdr *header;
    const u_char *data;
    int res;
    int savedPacketCount = 0;  // 添加计数器


    while (m_capturing)
    {
        // 处理待处理的事件
        QCoreApplication::processEvents();
        if (!m_capturing) {
            break;
        }
        //返回指向下一个数据包的指针
        res = pcap_next_ex(m_handle, &header, &data);
        if (res == 1)
        {  // 成功捕获数据包
            TPcapPacket packet;
            packet.rawdata = QByteArray((const char*)data, header->caplen);  // 复制数据
            packet.length = header->len;
            packet.caplen = header->caplen;
            packet.timestamp = QDateTime::fromMSecsSinceEpoch(header->ts.tv_sec * 1000LL + header->ts.tv_usec / 1000);

            // 解析协议头部
            int offset = 0;
            //解析以太网头
            if (TPCAPTransfer::parseEthernet(packet.rawdata, packet.eth) && packet.eth.type == 0x0800)
            {
                offset = 14;
                //解析IP头
                if (TPCAPTransfer::parseIp(packet.rawdata, packet.ip, offset) && packet.ip.protocol == 17)
                {
                    offset += packet.ip.headerLength;
                    quint16 srcPort, destPort;
                    //解析实际数据
                    if (TPCAPTransfer::parseUdp(packet.rawdata, srcPort, destPort, offset))
                    {
                        offset += 8;
                        packet.data = TPCAPTransfer::extractPayload(packet.rawdata, offset);
                    }
                }
            }
            // 如果启用了保存且 dumper 有效，保存到 pcap 文件
            if (m_enableDump && m_dumper)
            {
                pcap_dump((u_char*)m_dumper, header, data);
                savedPacketCount++;
                // 每10个包刷新一次，而不是每个包都刷新
                if (savedPacketCount % 10 == 0) {
                    pcap_dump_flush(m_dumper);
                    qDebug() << "Saved" << savedPacketCount << "packets";
                }

            }

            // 发出数据包
            qDebug() << "emit packet";
            emit packetCaptured(packet);
        } else if (res == -1) {  // 错误
            emit errorOccurred(QString("Capture error: %1").arg(pcap_geterr(m_handle)));
            m_capturing = false;
            break;
        }
        QThread::msleep(10); // 防止 CPU 过载
    }
    // 确保所有数据都写入文件
    if (m_dumper) {
        pcap_dump_flush(m_dumper);
        qDebug() << "Total saved packets:" << savedPacketCount;
    }
    m_isCapturing.storeRelease(0);  // 捕获结束
}

void TPCAPWork::stopCapture()
{
//    qDebug() << "stopCapture in thread:" << QThread::currentThreadId();
    m_capturing = false;
    m_isCapturing.storeRelease(0);  // 设置为停止
    if (m_handle)
    {
        pcap_breakloop(m_handle);
    }
}

void TPCAPWork::setFilter(const QString &filter)
{
    if (!m_handle) {
        emit errorOccurred("Device not open");
        return;
    }

    struct bpf_program fp;
    //编写过滤程序
    if (pcap_compile(m_handle, &fp, filter.toLocal8Bit().data(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        emit errorOccurred(QString("Failed to compile filter: %1").arg(pcap_geterr(m_handle)));
        return;
    }
    //指定过滤程序
    if (pcap_setfilter(m_handle, &fp) == -1) {
        pcap_freecode(&fp);
        emit errorOccurred(QString("Failed to set filter: %1").arg(pcap_geterr(m_handle)));
        return;
    }

    pcap_freecode(&fp);
}

void TPCAPWork::sendPacket(const QByteArray &data)
{
    if (!m_handle) {
        emit errorOccurred("Device not open");
        return;
    }

    if (pcap_sendpacket(m_handle, (const u_char*)data.data(), data.size()) != 0) {
        emit errorOccurred(QString("Failed to send packet: %1").arg(pcap_geterr(m_handle)));
    }
}

void TPCAPWork::getStatistics()
{
    TPcapStats stats = {0, 0, 0};
    if (m_handle) {
        struct pcap_stat ps;
        //数据包统计
        if (pcap_stats(m_handle, &ps) == 0) {
            stats.received = ps.ps_recv;
            stats.dropped = ps.ps_drop;
            stats.ifDropped = ps.ps_ifdrop;
        }
    }

    emit statisticsReady(stats); // 值传递
}

bool TPCAPWork::isOpen() const
{
    return m_isOpen.loadAcquire() != 0;
}

bool TPCAPWork::isCapturing() const
{
    return m_isCapturing.loadAcquire() != 0;
}

TPCAPTransfer::TPCAPTransfer(QObject *parent) : QObject(parent)
{
    m_work = new TPCAPWork;
    m_work->moveToThread(&m_thread);

    connect(this, &TPCAPTransfer::workOpenDevice, m_work, &TPCAPWork::openDevice);
    connect(this, &TPCAPTransfer::workOpenFile, m_work, &TPCAPWork::openFile);
    connect(this, &TPCAPTransfer::workClose, m_work, &TPCAPWork::close);
    connect(this, &TPCAPTransfer::workStartCapture, m_work, &TPCAPWork::startCapture);
    connect(this, &TPCAPTransfer::workStopCapture, m_work, &TPCAPWork::stopCapture);
    connect(this, &TPCAPTransfer::workSetFilter, m_work, &TPCAPWork::setFilter);
    connect(this, &TPCAPTransfer::workSendPacket, m_work, &TPCAPWork::sendPacket);
    connect(this, &TPCAPTransfer::workGetStatistics, m_work, &TPCAPWork::getStatistics);
    connect(m_work, &TPCAPWork::packetCaptured, this, &TPCAPTransfer::packetCaptured);
    connect(m_work, &TPCAPWork::errorOccurred, this, &TPCAPTransfer::errorOccurred);
    connect(m_work, &TPCAPWork::statisticsReady, this, &TPCAPTransfer::statisticsReady);
    connect(m_work, &TPCAPWork::deviceStatus, this, &TPCAPTransfer::deviceStatus);
    connect(&m_thread, &QThread::finished, m_work, &TPCAPWork::deleteLater);

    m_thread.start();
    m_thread.setPriority(QThread::HighPriority);
}

TPCAPTransfer::~TPCAPTransfer()
{
    // 先停止捕获和关闭设备
    emit workStopCapture();
    emit workClose();

    // 然后停止线程
    m_thread.quit();
    m_thread.wait(500); // 等待最多5秒

    if (m_thread.isRunning()) {
        m_thread.terminate(); // 强制终止
        m_thread.wait();
    }
}

QList<TPcapDevice> TPCAPTransfer::getDeviceList()
{
    QList<TPcapDevice> devices;
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        qWarning() << "Error finding devices:" << errbuf;
        return devices;
    }

    for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
        TPcapDevice device;
        device.name = QString::fromLocal8Bit(d->name);
        device.description = d->description ? QString::fromLocal8Bit(d->description) : "";
        device.isLoopback = (d->flags & PCAP_IF_LOOPBACK) != 0;
        device.isUp = (d->flags & PCAP_IF_UP) != 0;

        for (pcap_addr_t *a = d->addresses; a != nullptr; a = a->next) {
            if (a->addr && a->addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)a->addr;
                // 使用 QHostAddress 直接转换 IP 地址
                QHostAddress address(ntohl(sin->sin_addr.s_addr)); // 注意字节序转换
                if (!address.isNull()) {
                    device.addresses.append(address.toString());
                }
            }
        }

        devices.append(device);
    }

    pcap_freealldevs(alldevs);
    return devices;
}

bool TPCAPTransfer::openDevice(const QString &deviceName, bool isSave, int snaplen, bool promisc, int timeout)
{
    bool isOpen = false;
    QEventLoop loop;

    connect(this, &TPCAPTransfer::deviceStatus, [&isOpen, &loop](bool s) {
        isOpen = s;
        loop.quit();
    });

    emit workOpenDevice(deviceName, isSave, snaplen, promisc, timeout);
    loop.exec();
    qDebug() << "设备开启状态：" << isOpen;

    disconnect(this, &TPCAPTransfer::deviceStatus, nullptr, nullptr);
    return isOpen;
}

TPcapStats TPCAPTransfer::getStatistics()
{
    TPcapStats stats = {0, 0, 0};
    QEventLoop loop;

    connect(this, &TPCAPTransfer::statisticsReady, [&stats, &loop](TPcapStats s) {
        stats = s;
        loop.quit();
    });
    emit workGetStatistics();

    loop.exec();

    disconnect(this, &TPCAPTransfer::statisticsReady, nullptr, nullptr);
    return stats;
}

bool TPCAPTransfer::openFile(const QString &filename)
{
    emit workOpenFile(filename);
    return true;
}

void TPCAPTransfer::close()
{
    emit workClose();
}

bool TPCAPTransfer::isOpen() const
{
//            qDebug() << "TPCAPTransfer-isOpen";
    return m_work->isOpen();
//    return true;
}

bool TPCAPTransfer::isCapturing() const
{
//                qDebug() << "TPCAPTransfer-isCapturing";
    return m_work->isCapturing();
//    return true;
}

void TPCAPTransfer::startCapture()
{
    emit workStartCapture();    //向work线程传递开始
    emit captureStarted();  //向外传递捕获开始
}

void TPCAPTransfer::stopCapture()
{
    emit workStopCapture();
    emit captureStopped();
}

bool TPCAPTransfer::setFilter(const QString &filter)
{
    emit workSetFilter(filter);
    return true;
}

bool TPCAPTransfer::sendPacket(const QByteArray &data)
{
    emit workSendPacket(data);
    return true;
}

QString TPCAPTransfer::macToString(const quint8 *mac)
{
    return QString("%1:%2:%3:%4:%5:%6")
            .arg(mac[0], 2, 16, QChar('0'))
            .arg(mac[1], 2, 16, QChar('0'))
            .arg(mac[2], 2, 16, QChar('0'))
            .arg(mac[3], 2, 16, QChar('0'))
            .arg(mac[4], 2, 16, QChar('0'))
            .arg(mac[5], 2, 16, QChar('0'))
            .toUpper();
}

QByteArray TPCAPTransfer::stringToMac(const QString &macStr)
{
    QByteArray mac;
    QStringList parts = macStr.split(':');
    if (parts.size() == 6) {
        for (const QString &part : parts) {
            bool ok;
            mac.append(static_cast<char>(part.toInt(&ok, 16)));
            if (!ok) return QByteArray();
        }
    }
    return mac;
}

QString TPCAPTransfer::ipToString(quint32 ip)
{
    return QString("%1.%2.%3.%4")
            .arg((ip >> 24) & 0xFF)
            .arg((ip >> 16) & 0xFF)
            .arg((ip >> 8) & 0xFF)
            .arg(ip & 0xFF);
}

quint32 TPCAPTransfer::stringToIp(const QString &ipStr)
{
    QStringList parts = ipStr.split('.');
    if (parts.size() == 4) {
        return (parts[0].toUInt() << 24) |
                (parts[1].toUInt() << 16) |
                (parts[2].toUInt() << 8) |
                parts[3].toUInt();
    }
    return 0;
}

bool TPCAPTransfer::parseEthernet(const QByteArray &packet, TPcapPacket::EthernetHeader &eth)
{
    if (packet.size() < 14) return false;

    const quint8 *data = reinterpret_cast<const quint8*>(packet.data());
    memcpy(eth.destMac, data, 6);
    memcpy(eth.srcMac, data + 6, 6);
    eth.type = ntohs(*(quint16*)(data + 12));

    return true;
}

bool TPCAPTransfer::parseIp(const QByteArray &packet, TPcapPacket::IpHeader &ip, int offset)
{
    if (packet.size() < offset + 20) return false;

    const quint8 *data = reinterpret_cast<const quint8*>(packet.data() + offset);
    ip.version = (data[0] >> 4) & 0x0F;
    ip.headerLength = (data[0] & 0x0F) * 4;
    ip.tos = data[1];
    ip.totalLength = ntohs(*(quint16*)(data + 2));
    ip.id = ntohs(*(quint16*)(data + 4));
    ip.flags = ntohs(*(quint16*)(data + 6));
    ip.ttl = data[8];
    ip.protocol = data[9];
    ip.checksum = ntohs(*(quint16*)(data + 10));
    ip.srcAddr = ntohl(*(quint32*)(data + 12));
    ip.destAddr = ntohl(*(quint32*)(data + 16));

    return true;
}

bool TPCAPTransfer::parseUdp(const QByteArray &packet, quint16 &srcPort, quint16 &destPort, int offset)
{
    if (packet.size() < offset + 8) return false;

    const quint8 *data = reinterpret_cast<const quint8*>(packet.data() + offset);
    srcPort = ntohs(*(quint16*)(data));
    destPort = ntohs(*(quint16*)(data + 2));

    return true;
}

QByteArray TPCAPTransfer::extractPayload(const QByteArray &packet, int offset)
{
    if (offset >= packet.size()) return QByteArray();
    return packet.mid(offset);
}
