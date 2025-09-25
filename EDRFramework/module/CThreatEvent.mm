#include <iomanip>

#include "CThreatEvent.h"
// 生成的 protobuf 头
#include "../common/edr_event.pb.h"
#include "../common/Logger.h"

EAGLE_THREAT_PROCESS_INFO::EAGLE_THREAT_PROCESS_INFO()
    : UtcTime(0),
      ProcessId(0),
      ImagePath(),
      Hash(),
      User(),
      SID(),
      CommandLine(),
      CurrentDirectory(),
      ProcessGuid(),
      ParentProcessGuid(),
      ProcFileId(),
      SignerName(),
      CreateTime(0),
      FileSize(0),
      SignStatus(0),
      fileguid()
{
}

EAGLE_THREAT_CREATE_FILE_INFO::EAGLE_THREAT_CREATE_FILE_INFO()
    : UtcTime(0),
      ProcessGuid(),
      FileName(),
      CreateTime(0),
      CreateOptions(0),
      DesiredAccess(0),
      FileID(),
      FileSize(0),
      SignStatus(0),
      FileHash(),
      Signer(),
      SignerName(),
      CompanyName(),
      OriginalFile(),
      ProductName()
{
}

EAGLE_THREAT_CREATE_FILE_INFO::EAGLE_THREAT_CREATE_FILE_INFO(const EAGLE_THREAT_CREATE_FILE_INFO &other) = default;

EAGLE_THREAT_CREATE_FILE_INFO &EAGLE_THREAT_CREATE_FILE_INFO::operator= (const EAGLE_THREAT_CREATE_FILE_INFO &other) =
        default;

void EAGLE_THREAT_CREATE_FILE_INFO::PrintCreate() const
{
    LOG_DEBUG("File create event serialized - ProcessGuid: {}, File: {}, Hash: {}, Size: {} bytes", ProcessGuid,
              FileName, FileHash, FileSize);
}

void EAGLE_THREAT_RENAME_FILE_INFO::PrintRename() const
{
    LOG_DEBUG("File rename event serialized - ProcessGuid: {}, OldPath: {}, NewPath: {}", ProcessGuid, OldPath,
              NewPath);
}

EAGLE_THREAT_RENAME_FILE_INFO::EAGLE_THREAT_RENAME_FILE_INFO()
    : UtcTime(0), ProcessGuid(), OldPath(), NewPath(), FileSigner(), FileID()
{
}

EAGLE_THREAT_RENAME_FILE_INFO::EAGLE_THREAT_RENAME_FILE_INFO(const EAGLE_THREAT_RENAME_FILE_INFO &other) = default;

EAGLE_THREAT_RENAME_FILE_INFO &EAGLE_THREAT_RENAME_FILE_INFO::operator= (const EAGLE_THREAT_RENAME_FILE_INFO &other) =
        default;

EAGLE_THREAT_NETCON_INFO::EAGLE_THREAT_NETCON_INFO()
    : UtcTime(0), ProcessGuid(), Protocol(0), SourceIp(0), SourcePort(0), DestinationIp(0), DestinationPort(0)
{
}

EAGLE_THREAT_NETCON_INFO::EAGLE_THREAT_NETCON_INFO(const EAGLE_THREAT_NETCON_INFO &other) = default;

EAGLE_THREAT_NETCON_INFO &EAGLE_THREAT_NETCON_INFO::operator= (const EAGLE_THREAT_NETCON_INFO &other) = default;

void EAGLE_THREAT_NETCON_INFO::PrintNetCon() const
{
    LOG_DEBUG("Network connection event serialized - ProcessGuid: {}, Protocol: {}, Source: {}:{}, Destination: {}:{}",
              ProcessGuid, Protocol, SourceIp, SourcePort, DestinationIp, DestinationPort);
}

// 拷贝构造
EAGLE_THREAT_PROCESS_INFO::EAGLE_THREAT_PROCESS_INFO(const EAGLE_THREAT_PROCESS_INFO &other) = default;

// 赋值操作符
EAGLE_THREAT_PROCESS_INFO &EAGLE_THREAT_PROCESS_INFO::operator= (const EAGLE_THREAT_PROCESS_INFO &other) = default;

void EAGLE_THREAT_PROCESS_INFO::PrintProcess() const
{
    LOG_DEBUG("Process start event serialized - PID: {}, Path: {}, User: {}, CommandLine: {}", ProcessId, ImagePath,
              User, CommandLine);
}

static void FillProcessStartFromInfo(const EAGLE_THREAT_PROCESS_INFO *info, ProcessStart *out,
                                     int StartType = 0)  // StartType 0 当前进程，1父进程信息不全进程链
{
    if ( !out )
    {
        return;
    }
    out->set_utctime(info->UtcTime);
    out->set_processid(info->ProcessId);
    out->set_imagepath(info->ImagePath);
    out->set_hash(info->Hash);
    out->set_user(info->User);
    out->set_sid(info->SID);
    out->set_commandline(info->CommandLine);
    out->set_currentdirectory(info->CurrentDirectory);
    out->set_processguid(info->ProcessGuid);
    out->set_parentprocessguid(info->ParentProcessGuid);
    out->set_procfileid(info->ProcFileId);
    out->set_signername(info->SignerName);
    out->set_createtime(info->CreateTime);
    out->set_filesize(info->FileSize);
    out->set_signstatus(info->SignStatus);
    out->set_fileguid(info->fileguid);
    out->set_starttype(StartType);
}

static void FillProcessStartFromReport(const THREAT_PROC_INFO &r, ProcessStart *out)
{
    if ( !out )
    {
        return;
    }
    if ( r.guid )
    {
        out->set_processguid(r.guid);
    }
    if ( r.image )
    {
        out->set_imagepath(r.image);
    }
    if ( r.cmd )
    {
        out->set_commandline(r.cmd);
    }
    if ( r.pwd )
    {
        out->set_currentdirectory(r.pwd);
    }
    if ( r.sha256 )
    {
        out->set_hash(r.sha256);
    }
    if ( r.signer )
    {
        out->set_signer(r.signer);
    }
    if ( r.orig_file )
    {
        out->set_originalfile(r.orig_file);
    }
    if ( r.company )
    {
        out->set_company(r.company);
    }
    if ( r.parent_guid )
    {
        out->set_parentprocessguid(r.parent_guid);
    }
    out->set_integrity(static_cast<int32_t>(r.integrity));
    out->set_processid(static_cast<int32_t>(r.pid));
    if ( r.source )
    {
        out->set_fileguid(r.source);
    }
}

NSData *CProcExecThreatEvent::ToPB() const
{
    if ( reportType == REPORT_TYPE_LOG )
    {
        // 日志上报 - 使用EdrEventMessage格式
        EdrEventMessage              logEvent;
        EdrEventMessage::SubMessage *subMsg = logEvent.add_msg();

        subMsg->set_eventtype(static_cast<int32_t>(EDR_EVENT_PROCESSSTAR));
        subMsg->set_times(eventInfo.pProcess->UtcTime);

        ProcessStart start;
        FillProcessStartFromInfo(eventInfo.pProcess, &start);
        std::string startBytes;
        startBytes.reserve(256);
        start.SerializeToString(&startBytes);
        subMsg->set_eventinfo(startBytes);

        std::string serialized;
        if ( !logEvent.SerializeToString(&serialized) )
        {
            LOG_ERROR("Failed to serialize process start log event - PID: {}, Path: {}", eventInfo.pProcess->ProcessId,
                      eventInfo.pProcess->ImagePath);
            return nil;
        }

        LOG_DEBUG("Process start log event serialized - PID: {}, Path: {}, User: {}, CommandLine: {}",
                  eventInfo.pProcess->ProcessId, eventInfo.pProcess->ImagePath, eventInfo.pProcess->User,
                  eventInfo.pProcess->CommandLine);

        return [NSData dataWithBytes:serialized.data() length:serialized.size()];
    }

    // 告警上报 - 使用EdrRiskEvent格式
    EdrRiskEvent event;
    // des=1: pResult->threat_info 信息
    event.set_des(des);

    // 对于进程启动事件：procinfo=2 与 eventinfo=4 都使用 ProcessStart（来自基类联合体）
    ProcessStart start;
    FillProcessStartFromInfo(eventInfo.pProcess, &start);
    std::string startBytes;
    startBytes.reserve(256);
    start.SerializeToString(&startBytes);
    event.set_procinfo(startBytes);

    // eventid=3: 事件类型 id (EVENTID 枚举值)
    event.set_eventid(EDR_EVENT_PROCESSSTAR);

    // eventinfo=4: 与 procinfo 相同
    event.set_eventinfo(startBytes);

    // action=5: ProcessFilterAllow 的返回值 (ActionStatus)
    event.set_action(static_cast<int32_t>(action));

    // procinfos=6: 进程树信息（父进程、曾祖进程等）
    {
        std::string psBytes;
        psBytes.reserve(256);
        for ( const auto &proc: procInfoBuff )
        {
            ProcessStart ps;
            FillProcessStartFromInfo(proc, &ps);
            psBytes.clear();
            ps.SerializeToString(&psBytes);
            event.add_procinfos(psBytes);
        }
    }

    // agentip=7: 本机IP
    event.set_agentip(ip);

    // host=8: host名称
    event.set_hostname(host);

    std::string serialized;
    if ( !event.SerializeToString(&serialized) )
    {
        return nil;
    }
    return [NSData dataWithBytes:serialized.data() length:serialized.size()];
}

NSData *CNetConThreatEvent::ToPB() const
{
    if ( reportType == REPORT_TYPE_LOG )
    {
        // 日志上报 - 使用EdrEventMessage格式
        EdrEventMessage              logEvent;
        EdrEventMessage::SubMessage *subMsg = logEvent.add_msg();

        subMsg->set_eventtype(static_cast<int32_t>(EDR_EVENT_NETWORK_CONNECTION));
        subMsg->set_times(netConInfo.UtcTime);

        NetConEvent netEvent;
        netEvent.set_utctime(netConInfo.UtcTime);
        netEvent.set_processguid(netConInfo.ProcessGuid);
        netEvent.set_protocol(netConInfo.Protocol);
        netEvent.set_sourceip(netConInfo.SourceIp);
        netEvent.set_sourceport(netConInfo.SourcePort);
        netEvent.set_destinationip(netConInfo.DestinationIp);
        netEvent.set_destinationport(netConInfo.DestinationPort);

        std::string netEventBytes;
        netEventBytes.reserve(256);
        netEvent.SerializeToString(&netEventBytes);
        subMsg->set_eventinfo(netEventBytes);

        std::string serialized;
        if ( !logEvent.SerializeToString(&serialized) )
        {
            LOG_ERROR("Failed to serialize network connection log event - ProcessGuid: {}", netConInfo.ProcessGuid);
            return nil;
        }

        LOG_DEBUG(
                "Network connection log event serialized - ProcessGuid: {}, Protocol: {}, Source: {}:{}, Destination: "
                "{}:{}",
                netConInfo.ProcessGuid, netConInfo.Protocol, netConInfo.SourceIp, netConInfo.SourcePort,
                netConInfo.DestinationIp, netConInfo.DestinationPort);

        return [NSData dataWithBytes:serialized.data() length:serialized.size()];
    }

    // 告警上报 - 使用EdrRiskEvent格式
    EdrRiskEvent event;
    // des=1: pResult->threat_info 信息
    event.set_des(des);

    // 创建NetConEvent对象并填充数据
    NetConEvent netEvent;
    netEvent.set_utctime(netConInfo.UtcTime);
    netEvent.set_processguid(netConInfo.ProcessGuid);
    netEvent.set_protocol(netConInfo.Protocol);
    netEvent.set_sourceip(netConInfo.SourceIp);
    netEvent.set_sourceport(netConInfo.SourcePort);
    netEvent.set_destinationip(netConInfo.DestinationIp);
    netEvent.set_destinationport(netConInfo.DestinationPort);

    std::string netEventBytes;
    netEventBytes.reserve(256);
    netEvent.SerializeToString(&netEventBytes);
    event.set_procinfo(netEventBytes);

    // eventid=3: 事件类型 id (EVENTID 枚举值)
    event.set_eventid(EDR_EVENT_NETWORK_CONNECTION);

    // eventinfo=4: 与 procinfo 相同
    event.set_eventinfo(netEventBytes);

    // action=5: ProcessFilterAllow 的返回值 (ActionStatus)
    event.set_action(static_cast<int32_t>(action));

    // procinfos=6: 进程树信息（父进程、曾祖进程等）
    {
        std::string psBytes;
        psBytes.reserve(256);
        for ( const auto &proc: procInfoBuff )
        {
            ProcessStart ps;
            FillProcessStartFromInfo(proc, &ps);
            psBytes.clear();
            ps.SerializeToString(&psBytes);
            event.add_procinfos(psBytes);
        }
    }

    event.set_agentip(ip);
    event.set_hostname(host);

    std::string serialized;
    if ( !event.SerializeToString(&serialized) )
    {
        return nil;
    }
    return [NSData dataWithBytes:serialized.data() length:serialized.size()];
}

NSData *CFileCreateThreatEvent::ToPB() const
{
    if ( reportType == REPORT_TYPE_LOG )
    {
        // 日志上报 - 使用EdrEventMessage格式
        EdrEventMessage              logEvent;
        EdrEventMessage::SubMessage *subMsg = logEvent.add_msg();

        subMsg->set_eventtype(static_cast<int32_t>(EDR_EVENT_CREATEFILE));
        subMsg->set_times(eventInfo.pCreate->UtcTime);

        CreateFileEvent cfe;
        cfe.set_utctime(eventInfo.pCreate->UtcTime);
        cfe.set_processguid(eventInfo.pCreate->ProcessGuid);
        cfe.set_filename(eventInfo.pCreate->FileName);
        cfe.set_createtime(eventInfo.pCreate->CreateTime);
        cfe.set_createoptions(eventInfo.pCreate->CreateOptions);
        cfe.set_desiredaccess(eventInfo.pCreate->DesiredAccess);
        cfe.set_fileid(eventInfo.pCreate->FileID);
        cfe.set_filesize(eventInfo.pCreate->FileSize);
        cfe.set_signstatus(eventInfo.pCreate->SignStatus);
        cfe.set_filehash(eventInfo.pCreate->FileHash);
        cfe.set_signer(eventInfo.pCreate->Signer);
        cfe.set_signername(eventInfo.pCreate->SignerName);
        cfe.set_companyname(eventInfo.pCreate->CompanyName);
        cfe.set_originalfile(eventInfo.pCreate->OriginalFile);
        cfe.set_productname(eventInfo.pCreate->ProductName);

        std::string cfeBytes;
        cfeBytes.reserve(256);
        cfe.SerializeToString(&cfeBytes);
        subMsg->set_eventinfo(cfeBytes);

        std::string serialized;
        if ( !logEvent.SerializeToString(&serialized) )
        {
            LOG_ERROR("Failed to serialize file create log event - File: {}", eventInfo.pCreate->FileName);
            return nil;
        }

        LOG_DEBUG("File create log event serialized - ProcessGuid: {}, File: {}, Hash: {}, Size: {} bytes",
                  eventInfo.pCreate->ProcessGuid, eventInfo.pCreate->FileName, eventInfo.pCreate->FileHash,
                  eventInfo.pCreate->FileSize);

        return [NSData dataWithBytes:serialized.data() length:serialized.size()];
    }

    // 告警上报 - 使用EdrRiskEvent格式
    EdrRiskEvent event;
    // des=1: pResult->threat_info 信息
    event.set_des(des);

    // procinfo=2
    CreateFileEvent cfe;
    cfe.set_utctime(eventInfo.pCreate->UtcTime);
    cfe.set_processguid(eventInfo.pCreate->ProcessGuid);
    cfe.set_filename(eventInfo.pCreate->FileName);
    cfe.set_createtime(eventInfo.pCreate->CreateTime);
    cfe.set_createoptions(eventInfo.pCreate->CreateOptions);
    cfe.set_desiredaccess(eventInfo.pCreate->DesiredAccess);
    cfe.set_fileid(eventInfo.pCreate->FileID);
    cfe.set_filesize(eventInfo.pCreate->FileSize);
    cfe.set_signstatus(eventInfo.pCreate->SignStatus);
    cfe.set_filehash(eventInfo.pCreate->FileHash);
    cfe.set_signer(eventInfo.pCreate->Signer);
    cfe.set_signername(eventInfo.pCreate->SignerName);
    cfe.set_companyname(eventInfo.pCreate->CompanyName);
    cfe.set_originalfile(eventInfo.pCreate->OriginalFile);
    cfe.set_productname(eventInfo.pCreate->ProductName);
    std::string cfeBytes;
    cfeBytes.reserve(256);
    cfe.SerializeToString(&cfeBytes);
    event.set_procinfo(cfeBytes);

    // eventid=3: 事件类型 id (EVENTID 枚举值)
    event.set_eventid(EDR_EVENT_CREATEFILE);

    // eventinfo=4: 与 procinfo 相同
    event.set_eventinfo(cfeBytes);

    // action=5: ProcessFilterAllow 的返回值 (ActionStatus)
    event.set_action(static_cast<int32_t>(action));

    // procinfos=6: 进程树信息（父进程、曾祖进程等）
    {
        std::string psBytes;
        psBytes.reserve(256);
        for ( const auto &proc: procInfoBuff )
        {
            ProcessStart ps;
            FillProcessStartFromInfo(proc, &ps);
            psBytes.clear();
            ps.SerializeToString(&psBytes);
            event.add_procinfos(psBytes);
        }
    }

    event.set_agentip(ip);
    event.set_hostname(host);

    std::string serialized;
    if ( !event.SerializeToString(&serialized) )
    {
        return nil;
    }
    return [NSData dataWithBytes:serialized.data() length:serialized.size()];
}

NSData *CFileRenameThreatEvent::ToPB() const
{
    if ( reportType == REPORT_TYPE_LOG )
    {
        // 日志上报 - 使用EdrEventMessage格式
        EdrEventMessage              logEvent;
        EdrEventMessage::SubMessage *subMsg = logEvent.add_msg();

        subMsg->set_eventtype(static_cast<int32_t>(EDR_EVENT_FILERENAME));
        subMsg->set_times(eventInfo.pRename->UtcTime);

        ReNameFileEvent rne;
        rne.set_utctime(eventInfo.pRename->UtcTime);
        rne.set_processguid(eventInfo.pRename->ProcessGuid);
        rne.set_oldpath(eventInfo.pRename->OldPath);
        rne.set_newpath(eventInfo.pRename->NewPath);
        rne.set_filesigner(eventInfo.pRename->FileSigner);
        rne.set_fileid(eventInfo.pRename->FileID);

        std::string rneBytes;
        rneBytes.reserve(256);
        rne.SerializeToString(&rneBytes);
        subMsg->set_eventinfo(rneBytes);

        std::string serialized;
        if ( !logEvent.SerializeToString(&serialized) )
        {
            LOG_ERROR("Failed to serialize file rename log event - OldPath: {}, NewPath: {}",
                      eventInfo.pRename->OldPath, eventInfo.pRename->NewPath);
            return nil;
        }

        LOG_DEBUG("File rename log event serialized - ProcessGuid: {}, OldPath: {}, NewPath: {}",
                  eventInfo.pRename->ProcessGuid, eventInfo.pRename->OldPath, eventInfo.pRename->NewPath);

        return [NSData dataWithBytes:serialized.data() length:serialized.size()];
    }

    // 告警上报 - 使用EdrRiskEvent格式
    EdrRiskEvent event;
    // des=1: pResult->threat_info 信息
    event.set_des(des);

    // procinfo=2 与 eventinfo=4 都使用 ReNameFileEvent
    ReNameFileEvent rne;
    rne.set_utctime(eventInfo.pRename->UtcTime);
    rne.set_processguid(eventInfo.pRename->ProcessGuid);
    rne.set_oldpath(eventInfo.pRename->OldPath);
    rne.set_newpath(eventInfo.pRename->NewPath);
    rne.set_filesigner(eventInfo.pRename->FileSigner);
    rne.set_fileid(eventInfo.pRename->FileID);
    std::string rneBytes;
    rneBytes.reserve(256);
    rne.SerializeToString(&rneBytes);
    event.set_procinfo(rneBytes);

    // eventid=3: 事件类型 id (EVENTID 枚举值)
    event.set_eventid(EDR_EVENT_FILERENAME);

    // eventinfo=4: 与 procinfo 相同
    event.set_eventinfo(rneBytes);

    // action=5: ProcessFilterAllow 的返回值 (ActionStatus)
    event.set_action(static_cast<int32_t>(action));

    // procinfos=6: 进程树信息（父进程、曾祖进程等）
    {
        std::string psBytes;
        psBytes.reserve(256);
        for ( const auto &proc: procInfoBuff )
        {
            ProcessStart ps;
            FillProcessStartFromInfo(proc, &ps);
            psBytes.clear();
            ps.SerializeToString(&psBytes);
            event.add_procinfos(psBytes);
        }
    }

    event.set_agentip(ip);
    event.set_hostname(host);

    std::string serialized;
    if ( !event.SerializeToString(&serialized) )
    {
        return nil;
    }
    return [NSData dataWithBytes:serialized.data() length:serialized.size()];
}

