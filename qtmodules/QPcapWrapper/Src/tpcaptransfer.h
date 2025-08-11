#ifndef TPCAPTRANSFER_H
#define TPCAPTRANSFER_H

#include <QDebug>
#include <QObject>
#include <QThread>
#include <QMutex>
#include <QStringList>
#include <QDateTime>
#include <QAtomicInt>

// 平台相关头文件
#ifdef _WIN32
    // #define WPCAP
    // #define HAVE_REMOTE
    #include <pcap.h>
    #include <winsock2.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <pcap/pcap.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
#endif

#pragma pack(1)

/**
 * @brief 网络设备信息结构体
 * 用于存储通过 pcap_findalldevs 获取的网络接口信息
 */
struct TPcapDevice {
    QString name;           // 设备名称（如 eth0、\\Device\\NPF_{GUID}）
    QString description;    // 设备描述（如 Realtek PCIe GbE Family Controller）
    QStringList addresses;  // IP地址列表（一个设备可能有多个IP）
    bool isLoopback;       // 是否回环设备（127.0.0.1）
    bool isUp;             // 是否启用（设备是否处于活动状态）

    void print() const {
        qDebug() << "Name:" << name
        << "Desc:" << description
        << "Address:" << addresses;
    }
};

/**
 * @brief 数据包信息结构体
 * 存储捕获到的网络数据包的完整信息
 */
struct TPcapPacket {
    QByteArray rawdata;     // 完整数据包内容（包含所有协议层）
    quint32 length;         // 原始长度（数据包在网络上的实际大小）
    quint32 caplen;         // 捕获长度（实际捕获的字节数，可能因snaplen限制而小于length）
    QDateTime timestamp;    // 时间戳（数据包捕获时间）
    QByteArray data;        // 净荷数据（应用层数据，去除各种协议头）

    /**
     * @brief 以太网头部信息（14字节）
     */
    struct EthernetHeader {
        quint8 destMac[6];  // 目标MAC地址（6字节）
        quint8 srcMac[6];   // 源MAC地址（6字节）
        quint16 type;       // 以太网类型（2字节，如0x0800表示IPv4）
    } eth;

    /**
     * @brief IP头部信息（20字节，不含选项）
     */
    struct IpHeader {
        quint8 version;         // IP版本（4位）和头部长度（4位）的高4位
        quint8 headerLength;    // 头部长度（单位：4字节）
        quint8 tos;            // 服务类型
        quint16 totalLength;    // 总长度（IP头+数据）
        quint16 id;            // 标识符
        quint16 flags;         // 标志位（3位）和片偏移（13位）
        quint8 ttl;            // 生存时间
        quint8 protocol;       // 协议类型（6=TCP, 17=UDP, 1=ICMP）
        quint16 checksum;      // 头部校验和
        quint32 srcAddr;       // 源IP地址（网络字节序已转换为主机字节序）
        quint32 destAddr;      // 目标IP地址（网络字节序已转换为主机字节序）
    } ip;
};

// 数据包统计结构体，存储捕获的统计信息
struct TPcapStats {
    quint32 received;       // 接收到的数据包数量
    quint32 dropped;        // 丢弃的数据包数量
    quint32 ifDropped;      // 网络接口丢弃的数据包数量
};

#pragma pack()

/**
 * @brief 工作线程类 - 实际执行 pcap 操作
 *
 * 此类在独立线程中运行，负责所有 pcap 相关的操作，
 * 包括打开设备、捕获数据包、应用过滤器等。
 * 通过信号槽机制与主线程通信。
 */
class TPCAPWork : public QObject
{
    Q_OBJECT
public:
    explicit TPCAPWork(QObject *parent = nullptr);
    ~TPCAPWork();

private:
    pcap_t *m_handle = nullptr;         // pcap 句柄，用于捕获数据包
    pcap_dumper_t *m_dumper = nullptr;  // pcap 文件写入器，用于保存数据包
    volatile bool m_capturing = false;   // 捕获状态标志（volatile 确保线程间可见性）
    bool m_enableDump = false;          // 是否启用保存功能

    // 原子变量，用于线程安全的状态查询
    QAtomicInt m_isOpen{0};             // 设备是否打开（0=关闭，1=打开）
    QAtomicInt m_isCapturing{0};        // 是否正在捕获（0=停止，1=捕获中）

signals:
    /**
     * @brief 捕获到数据包时发出
     * @param packet 数据包信息（值传递避免线程问题）
     */
    void packetCaptured(TPcapPacket packet);

    /**
     * @brief 发生错误时发出
     * @param error 错误描述
     */
    void errorOccurred(QString error);
    // 统计数据准备好时发出，携带统计信息
    void statisticsReady(TPcapStats stats);
    void deviceStatus(bool isOpen);


public slots:
    /**
     * @brief 打开网络设备进行捕获
     * @param deviceName 设备名称（如 eth0）
     * @param isSave 是否保存数据包到文件
     * @param snaplen 最大捕获长度（建议65536）
     * @param promisc 是否开启混杂模式
     * @param timeout 读取超时（毫秒）
     */
    void openDevice(const QString &deviceName, bool isSave, int snaplen, bool promisc, int timeout);

    /**
     * @brief 关闭设备或文件
     */
    void close();

    /**
     * @brief 开始捕获数据包
     */
    void startCapture();

    /**
     * @brief 停止捕获数据包
     */
    void stopCapture();

    /**
     * @brief 设置 BPF 过滤器
     * @param filter 过滤器表达式（如 "tcp port 80"）
     */
    void setFilter(const QString &filter);

    /**
     * @brief 查询设备是否打开
     * @return true 已打开，false 未打开
     */
    bool isOpen() const;

    /**
     * @brief 查询是否正在捕获
     * @return true 正在捕获，false 未捕获
     */
    bool isCapturing() const;

    /**
     * @brief 打开 pcap 文件进行读取
     * @param filename 文件路径
     */
    void openFile(const QString &filename);

    /**
     * @brief 发送数据包
     * @param data 要发送的原始数据
     */
    void sendPacket(const QByteArray &data);

    // 获取捕获统计信息
    void getStatistics();

};

/**
 * @brief 主接口类 - 提供线程安全的 pcap 操作接口
 *
 * 此类在主线程中使用，管理工作线程并提供简单的 API。
 * 所有实际的 pcap 操作都委托给 TPCAPWork 在独立线程中执行。
 */
class TPCAPTransfer : public QObject
{
    Q_OBJECT
public:

    explicit TPCAPTransfer(QObject *parent = nullptr);
    ~TPCAPTransfer();

private:
    QThread m_thread;       // 工作线程
    TPCAPWork *m_work;      // 工作对象（在 m_thread 中运行）

signals:
    /**
     * @brief 转发：捕获到数据包
     */
    void packetCaptured(TPcapPacket packet);

    /**
     * @brief 捕获开始信号
     */
    void captureStarted();

    /**
     * @brief 捕获停止信号
     */
    void captureStopped();

    /**
     * @brief 转发：错误发生
     */
    void errorOccurred(QString error);

    // 统计数据准备好时发出
    void statisticsReady(TPcapStats stats);
    void deviceStatus(bool isOpen);

    // 以下为内部信号，用于与工作线程通信
    void workOpenDevice(QString deviceName, bool isSave, int snaplen, bool promisc, int timeout);
    void workOpenFile(QString filename);
    void workClose();
    void workStartCapture();
    void workStopCapture();
    void workSetFilter(QString filter);
    void workSendPacket(QByteArray data);
    void workGetStatistics();

public slots:
    /**
     * @brief 获取系统中所有网络设备列表
     * @return 设备列表
     * @note 静态函数，可直接调用，无需创建对象
     */
    static QList<TPcapDevice> getDeviceList();

    /**
     * @brief 打开网络设备进行数据包捕获
     * @param deviceName 设备名称（通过 getDeviceList 获取）
     * @param isSave 是否保存捕获的数据包到文件（自动生成文件名）
     * @param snaplen 最大捕获长度（默认65536字节，足够大多数情况）
     * @param promisc 是否开启混杂模式（true=接收所有数据包）
     * @param timeout 读取超时时间（毫秒，默认1000ms）
     * @return 操作是否成功（异步操作，实际结果通过信号反馈）
     */
    bool openDevice(const QString &deviceName, bool isSave = false, int snaplen = 65536, bool promisc = true, int timeout = 1000);

    /**
     * @brief 检查设备/文件是否已打开
     * @return true 已打开，false 未打开
     */
    bool isOpen() const;

    /**
     * @brief 开始捕获数据包
     * @note 必须先调用 openDevice 或 openFile
     */
    void startCapture();

    /**
     * @brief 停止捕获数据包【不释放设备或句柄】 暂停作用
     */
    void stopCapture();

    /**
     * @brief 关闭当前打开的设备或文件【关闭设备释放资源】
     */
    void close();

    /**
     * @brief 检查是否正在捕获
     * @return true 正在捕获，false 未捕获
     */
    bool isCapturing() const;

    /**
     * @brief 设置 BPF（Berkeley Packet Filter）过滤器
     * @param filter 过滤表达式，如 "tcp port 80" 或 "udp and host 192.168.1.1"
     * @return 设置是否成功
     * @note 常用过滤器：
     *       - "tcp" / "udp" / "icmp" - 协议过滤
     *       - "port 80" - 端口过滤
     *       - "host 192.168.1.1" - 主机过滤
     *       - "net 192.168.0.0/16" - 网段过滤
     */
    bool setFilter(const QString &filter);

    // 获取捕获统计信息
    // 返回：统计数据（同步获取）
    TPcapStats getStatistics();

    /**
     * @brief 发送原始数据包
     * @param data 数据包内容（需包含完整的以太网帧）
     * @return 发送是否成功
     */
    bool sendPacket(const QByteArray &data);

    /**
     * @brief 打开 pcap 文件进行分析
     * @param filename 文件路径
     * @return 操作是否成功
     */
    bool openFile(const QString &filename);

    // ========== 工具函数（静态） ==========

    /**
     * @brief MAC地址转字符串
     * @param mac 6字节MAC地址
     * @return 格式化的MAC地址字符串（如 "AA:BB:CC:DD:EE:FF"）
     */
    static QString macToString(const quint8 *mac);

    /**
     * @brief 字符串转MAC地址
     * @param macStr MAC地址字符串
     * @return 6字节MAC地址
     */
    static QByteArray stringToMac(const QString &macStr);

    /**
     * @brief IP地址（整数）转字符串
     * @param ip IP地址（主机字节序）
     * @return 点分十进制格式（如 "192.168.1.1"）
     */
    static QString ipToString(quint32 ip);

    /**
     * @brief 字符串转IP地址（整数）
     * @param ipStr 点分十进制IP字符串
     * @return IP地址（主机字节序）
     */
    static quint32 stringToIp(const QString &ipStr);

    /**
     * @brief 解析以太网头部
     * @param packet 原始数据包
     * @param eth 输出：以太网头部信息
     * @return 解析是否成功
     */
    static bool parseEthernet(const QByteArray &packet, TPcapPacket::EthernetHeader &eth);

    /**
     * @brief 解析IP头部
     * @param packet 原始数据包
     * @param ip 输出：IP头部信息
     * @param offset 偏移量（默认14，跳过以太网头）
     * @return 解析是否成功
     */
    static bool parseIp(const QByteArray &packet, TPcapPacket::IpHeader &ip, int offset = 14);

    /**
     * @brief 解析UDP头部
     * @param packet 原始数据包
     * @param srcPort 输出：源端口
     * @param destPort 输出：目标端口
     * @param offset 偏移量（以太网头+IP头）
     * @return 解析是否成功
     */
    static bool parseUdp(const QByteArray &packet, quint16 &srcPort, quint16 &destPort, int offset);

    /**
     * @brief 提取应用层数据
     * @param packet 原始数据包
     * @param offset 偏移量（所有协议头的总长度）
     * @return 应用层数据
     */
    static QByteArray extractPayload(const QByteArray &packet, int offset);

};

#endif // TPCAPTRANSFER_H
