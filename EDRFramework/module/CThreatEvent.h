#ifndef CTHREATEVENT_H
#define CTHREATEVENT_H

#include <iostream>
#include <Foundation/Foundation.h>
#include <string>

#include "../common/SystemUtils.h"
#include "CFilterRule.h"

// 事件报告类型枚举
enum ReportType
{
    REPORT_TYPE_LOG   = 0,  // 日志上报
    REPORT_TYPE_ALERT = 1   // 告警上报
};

enum EVENTID
{
    EDR_EVENT_PROCESSSTAR         = 1,   // 进程启动
    EDR_EVENT_NETWORKCON          = 3,   // 网络连接
    EDR_EVENT_NETWORK_CONNECTION  = 4,   // 网络连接审计
    EDR_EVENT_PROCESSEND          = 5,   // 进程结束
    EDR_EVENT_DRIVERLOAD       = 6,   // 驱动加载
    EDR_EVENT_DLLLOAD          = 7,   // 镜像加载
    EDR_EVENT_REMOTETHREAD     = 8,   // 远程线程
    EDR_EVENT_ACCESSROC        = 9,   // 访问进程
    EDR_EVENT_CREATEFILE       = 11,  // 新建文件
    EDR_EVENT_CREATEPIPE       = 12,  // 新建pipe
    EDR_EVENT_REGSETVALUE      = 13,  // 设置键值
    EDR_EVENT_WMIFILTER        = 19,  // wmi 创建filter
    EDR_EVENT_WMICONSUMER      = 20,  // wmi 创建consumer
    EDR_EVENT_WMIBINDING       = 21,  // wmi 绑定consuser和filter
    EDR_EVENT_DNSQUERY         = 22,  // dns查询
    EDR_EVENT_DISKIO           = 30,  // 直接磁盘读写
    EDR_EVENT_REMOTEAPC        = 31,
    EDR_EVENT_SETTHREADCONTEXT = 32,
    EDR_EVENT_ALLOCVM          = 33,
    EDR_EVENT_PROTECTVM        = 34,
    EDR_EVENT_FILERENAME       = 35,
    EDR_EVENT_FILEDELETE       = 36,
    EDR_EVENT_FILEREAD         = 37,
    EDR_EVENT_FILEWRITE        = 38,
    EDR_EVENT_USEROPE          = 40,  // 用户操作
    EDR_EVENT_LOGON            = 41,  // 登录操作
    EDR_EVENT_SVREVENT         = 42,  // 服务控制
    EDR_EVENT_POWERSEHLLCMD    = 43,  // powershell命令执行
    EDR_EVENT_SCHEDULETASKNEW  = 44,  // 创建新的计划任务
    EDR_EVENT_RDPLOGIN         = 45,  // rdp登录
    EDR_EVENT_LISTEN           = 46,  // 监听端口
    EDR_EVENT_SCRIPTEXECUTE    = 47,  // 脚本执行
    EDR_EVENT_MAPVM            = 48,  // mapview
    EDR_EVENT_CREATESERVICE    = 49   // 创建服务
};

struct EAGLE_THREAT_PROCESS_INFO
{
    int32_t     UtcTime;            // 1
    int32_t     ProcessId;          // 2
    std::string ImagePath;          // 3
    std::string Hash;               // 4
    std::string User;               // 8
    std::string SID;                // 9
    std::string CommandLine;        // 10
    std::string CurrentDirectory;   // 11
    std::string ProcessGuid;        // 14
    std::string ParentProcessGuid;  // 15
    std::string ProcFileId;         // 16
    std::string SignerName;         // 17
    int32_t     CreateTime;         // 19
    int32_t     FileSize;           // 20
    int32_t     SignStatus;         // 21
    std::string fileguid;           // 22
    int32_t     ParentId;
    int32_t     ExitTime;           // 附加不与proto对应
    // 默认构造
    EAGLE_THREAT_PROCESS_INFO();

    // 拷贝构造
    EAGLE_THREAT_PROCESS_INFO(const EAGLE_THREAT_PROCESS_INFO &other);
    // 赋值重载
    EAGLE_THREAT_PROCESS_INFO &operator= (const EAGLE_THREAT_PROCESS_INFO &other);
    // 打印进程信息
    void PrintProcess() const;
};

struct EAGLE_THREAT_CREATE_FILE_INFO
{
    int32_t     UtcTime;        // 1
    std::string ProcessGuid;    // 2
    std::string FileName;       // 3
    int32_t     CreateTime;     // 4
    int32_t     CreateOptions;  // 5
    int32_t     DesiredAccess;  // 6
    std::string FileID;         // 7
    int32_t     FileSize;       // 8
    int32_t     SignStatus;     // 9
    std::string FileHash;       // 10
    std::string Signer;         // 11
    std::string SignerName;     // 12
    std::string CompanyName;    // 13
    std::string OriginalFile;   // 14
    std::string ProductName;    // 15

    // 默认构造
    EAGLE_THREAT_CREATE_FILE_INFO();
    // 拷贝构造
    EAGLE_THREAT_CREATE_FILE_INFO(const EAGLE_THREAT_CREATE_FILE_INFO &other);
    // 赋值重载
    EAGLE_THREAT_CREATE_FILE_INFO &operator= (const EAGLE_THREAT_CREATE_FILE_INFO &other);

    void PrintCreate() const;
};

struct EAGLE_THREAT_RENAME_FILE_INFO
{
    int32_t     UtcTime;      // 1
    std::string ProcessGuid;  // 2
    std::string OldPath;      // 3
    std::string NewPath;      // 4
    std::string FileSigner;   // 5
    std::string FileID;       // 6

    // 默认构造
    EAGLE_THREAT_RENAME_FILE_INFO();
    // 拷贝构造
    EAGLE_THREAT_RENAME_FILE_INFO(const EAGLE_THREAT_RENAME_FILE_INFO &other);
    // 赋值重载
    // 保留一个operator=声明，移除重复项
    void                           PrintRename() const;
    EAGLE_THREAT_RENAME_FILE_INFO &operator= (const EAGLE_THREAT_RENAME_FILE_INFO &other);
};

struct EAGLE_THREAT_NETCON_INFO
{
    int32_t     UtcTime;         // 1
    std::string ProcessGuid;     // 2
    int32_t     Protocol;        // 3
    uint32_t    SourceIp;        // 4
    uint32_t    SourcePort;      // 5
    uint32_t    DestinationIp;   // 6
    uint32_t    DestinationPort; // 7

    // 默认构造
    EAGLE_THREAT_NETCON_INFO();
    // 拷贝构造
    EAGLE_THREAT_NETCON_INFO(const EAGLE_THREAT_NETCON_INFO &other);
    // 赋值重载
    EAGLE_THREAT_NETCON_INFO &operator= (const EAGLE_THREAT_NETCON_INFO &other);
    void PrintNetCon() const;
};

// 事件信息联合体
union EventInfoUnion
{
    EAGLE_THREAT_PROCESS_INFO     *pProcess;  // 进程启动事件
    EAGLE_THREAT_CREATE_FILE_INFO *pCreate;   // 创建文件事件
    EAGLE_THREAT_RENAME_FILE_INFO *pRename;   // 重命名文件事件
    EAGLE_THREAT_NETCON_INFO      *pNetCon;   // 网络连接事件

    EventInfoUnion(): pProcess()
    {
    }  // 默认构造为进程启动

    ~EventInfoUnion()
    {
    }  // 联合体析构函数
};

class CThreatEvent
{
public:
    virtual ~CThreatEvent() = default;

    // 根据reportType返回相应格式的protobuf数据
    // REPORT_TYPE_LOG -> EdrEventMessage, REPORT_TYPE_ALERT -> EdrRiskEvent
    virtual NSData *ToPB() const = 0;

public:
#pragma mark -procinfo 产生事件的进程信息
    std::string                              des;
    EventInfoUnion                           procInfo;
    EVENTID                                  eventId;
    EventInfoUnion                           eventInfo;     // 事件信息（根据 eventId 确定类型）
    ActionStatus                             action;
    ReportType                               reportType;    // 事件报告类型（日志或告警）
    std::vector<EAGLE_THREAT_PROCESS_INFO *> procInfoBuff;  // 直系父进程到1号进程
    std::string                              ip;
    std::string                              host;
};

class CProcExecThreatEvent: public CThreatEvent
{
public:
    explicit CProcExecThreatEvent(const EAGLE_THREAT_PROCESS_INFO *proc)
    {
        // 使用拷贝构造，避免浅拷贝和重复释放
        m_event            = new EAGLE_THREAT_PROCESS_INFO(*proc);
        eventInfo.pProcess = m_event;
        procInfo.pProcess  = m_event;
    }

    ~CProcExecThreatEvent()
    {
        if ( m_event )
        {
            delete m_event;
            m_event = nullptr;
        }
    }

    NSData                    *ToPB() const override;
    EAGLE_THREAT_PROCESS_INFO *m_event;
};

class CFileCreateThreatEvent: public CThreatEvent
{
public:
    explicit CFileCreateThreatEvent(const EAGLE_THREAT_CREATE_FILE_INFO *file)
    {
        // 使用拷贝构造，避免浅拷贝和重复释放
        m_event           = new EAGLE_THREAT_CREATE_FILE_INFO(*file);
        eventInfo.pCreate = m_event;  // 使用基类联合体
        procInfo.pCreate  = m_event;  // 使用基类联合体
        // proc 可以存储在 procInfoBuff 中或单独处理
    }

    ~CFileCreateThreatEvent()
    {
        if ( m_event )
        {
            delete m_event;
            m_event = nullptr;
        }
    }

    NSData                        *ToPB() const override;
    EAGLE_THREAT_CREATE_FILE_INFO *m_event;
};

class CFileRenameThreatEvent: public CThreatEvent
{
public:
    explicit CFileRenameThreatEvent(const EAGLE_THREAT_RENAME_FILE_INFO *file)
    {
        // 使用拷贝构造，避免浅拷贝和重复释放
        m_event           = new EAGLE_THREAT_RENAME_FILE_INFO(*file);
        eventInfo.pRename = m_event;  // 使用基类联合体
        procInfo.pRename  = m_event;  // 使用基类联合体
        // proc 可以存储在 procInfoBuff 中或单独处理
    }

    ~CFileRenameThreatEvent()
    {
        if ( m_event )
        {
            delete m_event;
            m_event = nullptr;
        }
    }

    NSData                        *ToPB() const override;
    EAGLE_THREAT_RENAME_FILE_INFO *m_event;
};

class CNetConThreatEvent: public CThreatEvent
{
public:
    CNetConThreatEvent()
    {
        netConInfo.UtcTime = 0;
        netConInfo.ProcessGuid = "";
        netConInfo.Protocol = 0;
        netConInfo.SourceIp = 0;
        netConInfo.SourcePort = 0;
        netConInfo.DestinationIp = 0;
        netConInfo.DestinationPort = 0;
    }

    ~CNetConThreatEvent() = default;

    NSData *ToPB() const override;

public:
    EAGLE_THREAT_NETCON_INFO netConInfo;
};
#endif
