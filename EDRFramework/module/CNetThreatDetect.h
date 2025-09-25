#ifndef CNETTHREATDETECT_H
#define CNETTHREATDETECT_H

@class NetworkAudit;

class CNetThreatDetect
{
public:
    static CNetThreatDetect *shared();

    /// 初始化网络威胁检测模块（使用云枢网络审计）
    bool Initialize();

    /// 反初始化网络威胁检测模块
    bool UnInitialize();

private:
    CNetThreatDetect();
    ~CNetThreatDetect();

    // NetworkAudit实例（保持引用）
    NetworkAudit *m_networkAudit;

    // 网络事件特有属性
    std::string m_localAddress;
    std::string m_remoteAddress;
    uint16_t    m_localPort;
    uint16_t    m_remotePort;
    std::string m_protocol;
    std::string m_threatType;
    std::string m_ruleName;
    std::string m_action;  // 允许/拒绝
};

#endif
