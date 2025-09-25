#include "CFilterRule.h"
#include "CProcessTree.h"
#include "CProcessThreatDetect.h"
#include "CThreatEvent.h"
#include "../CThreatDetect.h"
#include "../common/macro.h"
#include "../common/EsfUtils.h"
#include "../common/SystemUtils.h"
#include "../common/Logger.h"
#include "../common/Consts.h"

extern uint64_t gSilentStartUtc;  // 全局静默开始时间

static inline void MapActionToFlags(ActionStatus action, bool &allow, bool &report)
{
    switch ( action )
    {
        case RULE_ACTION_PASS:  // 上报日志
            allow  = true;
            report = true;
            break;
        case RULE_ACTION_BLOCK:  // 拦截上报告警
            allow  = false;
            report = true;
            break;
        case RULE_ACTION_REPORT:  // 上报告警不拦截
            allow  = true;
            report = true;
            break;
        case RULE_ACTION_FILTER:  // 放行不上报
            allow  = true;
            report = false;
            break;
        default:
            break;
    }
}

// 一次性构建执行事件上下文（事件进程 + 规则判定用的当前/父进程信息）
struct ExecContext
{
    EAGLE_THREAT_PROCESS_INFO *eventProc = nullptr;
    THREAT_PROC_INFO          *proc      = nullptr;
    THREAT_PROC_INFO          *parent    = nullptr;
};

CProcessThreatDetect::CProcessThreatDetect()
{
    LOG_INFO("CProcessThreatDetect constructor called, initializing filter rules...");
    CFilterRule *pFilterRule = CFilterRule::shared();
    pFilterRule->Initialize();
}

CProcessThreatDetect::~CProcessThreatDetect()
{
}

CProcessThreatDetect *CProcessThreatDetect::shared()
{
    static CProcessThreatDetect instance;
    return &instance;
}

/// 处理Auth事件（需要返回决策）
/// @param eventType 事件类型
/// @param message ESF消息
/// @return true允许，false拒绝
bool CProcessThreatDetect::OnAuthEventReceived(es_event_type_t eventType, const es_message_t *message)
{
    if ( !message )
    {
        LOG_ERROR("Received null message in auth handler, event_type={}", static_cast<int>(eventType));
        return true;  // 默认放行
    }

    try
    {
        // 只有case处理此事件
        switch ( message->event_type )
        {
            case ES_EVENT_TYPE_AUTH_EXEC:
                return handleAuthExecEvent(message);
            default:
                return true;
        }
    }
    catch ( const std::exception &e )
    {
        LOG_ERROR("Exception in auth event processing: {}, event_type={}", e.what(),
                  static_cast<int>(message->event_type));
        return true;  // 异常时默认放行
    }
    return true;
}

/// 处理Notify事件（仅记录，不拦截）
/// @param eventType 事件类型
/// @param message ESF消息
void CProcessThreatDetect::OnNotifyEventReceived(es_event_type_t eventType, const es_message_t *message)
{
    if ( !message )
    {
        LOG_ERROR("Received null message in notify handler, event_type={}", static_cast<int>(eventType));
        return;
    }

    try
    {
        switch ( message->event_type )
        {
            case ES_EVENT_TYPE_NOTIFY_EXIT:
                handleNotifyExitEvent(message);
                break;
            default:
                break;
        }
    }
    catch ( const std::exception &e )
    {
        LOG_ERROR("Exception in notify event processing: {}, event_type={}", e.what(), static_cast<int>(eventType));
    }
}

/// 获取本模块关心的事件类型（自注册）
std::vector<es_event_type_t> CProcessThreatDetect::GetSubscribedEventTypes() const
{
    return { ES_EVENT_TYPE_AUTH_EXEC,  // 进程执行
             ES_EVENT_TYPE_NOTIFY_EXIT };
}

bool CProcessThreatDetect::handleAuthExecEvent(const es_message_t *message)
{
    if ( message == nullptr || message->event_type != ES_EVENT_TYPE_AUTH_EXEC )
    {
        LOG_ERROR("Invalid message for AUTH_EXEC event: message is null");
        return true;  // 放行
    }

    // 检查进程启动检测功能是否启用
    CThreatDetect *threatDetect            = CThreatDetect::Shared();
    uint32_t       enabledFeatures         = threatDetect->GetEnabledFeatures();
    bool           processDetectionEnabled = (enabledFeatures & EDR_FEATURE_PROCESS_START) != 0;
    bool           processTreeEnabled      = (enabledFeatures & EDR_FEATURE_PROCESS_TREE) != 0;

    CFilterRule *pFilterRule = CFilterRule::shared();
    if ( !pFilterRule )
    {
        LOG_ERROR("Filter rule manager is not initialized, cannot process AUTH_EXEC event");
        return true;  // 放行
    }

    // 构建执行事件上下文（事件信息 + 规则判定用信息）
    EAGLE_THREAT_PROCESS_INFO *pEventProcInfo = new EAGLE_THREAT_PROCESS_INFO();

    THREAT_PROC_INFO *pProcInfo = (THREAT_PROC_INFO *)malloc(sizeof(THREAT_PROC_INFO));
    memset(pProcInfo, 0, sizeof(THREAT_PROC_INFO));

    THREAT_PROC_INFO *pParentProcInfo = (THREAT_PROC_INFO *)malloc(sizeof(THREAT_PROC_INFO));
    memset(pParentProcInfo, 0, sizeof(THREAT_PROC_INFO));

    @autoreleasepool                                 // 获取进程启动的信息
    {
        pProcInfo->pid = EsfUtils::GetPid(message);  // 获取触发事件的进程ID

        NSString *strImage = EsfUtils::GetProcessPath(message);
        pProcInfo->image   = strImage ? strdup([strImage UTF8String]) : nullptr;

        NSString *strCMD = EsfUtils::GetCMD(message);
        pProcInfo->cmd   = strCMD ? strdup([strCMD UTF8String]) : nullptr;

        NSString *strPWD = EsfUtils::GetPWD(message);
        pProcInfo->pwd   = strPWD ? strdup([strPWD UTF8String]) : nullptr;

        //        NSString *strSha256 = EsfUtils::GetSHA256(message);
        //        pProcInfo->sha256 = strSha256 ? strdup([strSha256 UTF8String]) : nullptr;

        std::string strSha256 = SystemUtils::GetSHA256(pProcInfo->pid);
        pProcInfo->sha256     = strdup(strSha256.c_str());

        NSString *strGuid = EsfUtils::GetGUID(message);
        pProcInfo->guid   = strGuid ? strdup([strGuid UTF8String]) : nullptr;

        NSString *strUserName             = EsfUtils::GetUser(message);
        pEventProcInfo->UtcTime           = EsfUtils::GetUtcTime(message);
        pEventProcInfo->User              = strUserName ? [strUserName UTF8String] : "";
        pEventProcInfo->SID               = std::to_string(EsfUtils::GetUid(message));
        pEventProcInfo->ImagePath         = strImage ? [strImage UTF8String] : "";
        pEventProcInfo->CommandLine       = strCMD ? [strCMD UTF8String] : "";
        pEventProcInfo->CurrentDirectory  = strPWD ? [strPWD UTF8String] : "";
        pEventProcInfo->Hash              = strSha256;
        pEventProcInfo->ProcessGuid       = strGuid ? [strGuid UTF8String] : "";
        pEventProcInfo->ProcessId         = pProcInfo->pid;
        pEventProcInfo->ParentId          = EsfUtils::GetPPid(message);
        pEventProcInfo->ParentProcessGuid = SystemUtils::GetGUID(pEventProcInfo->ParentId);
        pEventProcInfo->CreateTime        = EsfUtils::GetCreateTime(message);  // 事件时间
        uint64_t fileSizeRaw              = EsfUtils::GetFileSize(message);
        pEventProcInfo->FileSize          = (int32_t)fileSizeRaw;              // 程序文件大小
        pEventProcInfo->SignerName        = SystemUtils::GetSignerName(pEventProcInfo->ImagePath);

        LOG_DEBUG("Process start event - FileSize: raw={}, converted={}, SignerName: '{}'", fileSizeRaw,
                  pEventProcInfo->FileSize, pEventProcInfo->SignerName);
        //        pEventProcInfo->PrintProcess();
    }

    SystemUtils::GetProcInfo(pEventProcInfo->ParentId, pParentProcInfo);

    const auto &silentRules = pFilterRule->GetFilterRule<SilentProcessRule>();
    std::string processNameForMatch;
    NSString   *strProcName = EsfUtils::GetProcessName(message);
    processNameForMatch     = strProcName ? [strProcName UTF8String] : "";
    for ( const auto &rule: silentRules )
    {
        if ( rule.Matches(processNameForMatch.c_str()) )
        {
            CProcessTree::shared()->insertNode(pEventProcInfo);

            delete pEventProcInfo;

            SystemUtils::FreeReportProcInfo(pParentProcInfo);
            free(pParentProcInfo);

            SystemUtils::FreeReportProcInfo(pProcInfo);
            free(pProcInfo);
            return true;
        }
    }

    CProcessTree::shared()->insertNode(pEventProcInfo);

    // 只有启用了进程启动检测功能时才进行威胁检测
    if ( !processDetectionEnabled )
    {
        delete pEventProcInfo;
        SystemUtils::FreeReportProcInfo(pParentProcInfo);
        free(pParentProcInfo);
        SystemUtils::FreeReportProcInfo(pProcInfo);
        free(pProcInfo);
        return true;  // 放行，仅维护进程树，不进行威胁检测
    }

    std::string  threatInfo;
    ActionStatus actionStaus = pFilterRule->ProcessFilterAllow(pProcInfo, pParentProcInfo, &threatInfo);
    bool         bAllow      = true;
    bool         bReport     = false;
    MapActionToFlags(actionStaus, bAllow, bReport);

    if ( bReport )
    {
        CProcExecThreatEvent *execEvt = new CProcExecThreatEvent(pEventProcInfo);
        execEvt->des                  = std::move(threatInfo);
        execEvt->eventId              = EDR_EVENT_PROCESSSTAR;
        execEvt->action               = actionStaus;
        execEvt->reportType           = (actionStaus == RULE_ACTION_PASS) ? REPORT_TYPE_LOG : REPORT_TYPE_ALERT;
        EsfUtils::FillProcessStart(message, execEvt->eventInfo.pProcess);
        execEvt->procInfoBuff = CProcessTree::shared()->GetProcessChain(pEventProcInfo->ProcessId);
        pid_t leafPid         = EsfUtils::GetPid(message);
        execEvt->ip           = EsfUtils::GetPrimaryIPv4();
        execEvt->host         = EsfUtils::GetHostName();
        CThreatDetect::Shared()->Report(execEvt);
    }

    delete pEventProcInfo;

    SystemUtils::FreeReportProcInfo(pParentProcInfo);
    free(pParentProcInfo);

    SystemUtils::FreeReportProcInfo(pProcInfo);
    free(pProcInfo);

    return bAllow;
}

void CProcessThreatDetect::handleNotifyExitEvent(const es_message_t *message)
{
    if ( !message || message->event_type != ES_EVENT_TYPE_NOTIFY_EXIT )
    {
        return;
    }
    try
    {
        // 获取退出进程的PID
        pid_t exitPid = EsfUtils::GetPid(message);

        // 从进程树中查找进程信息
        EAGLE_THREAT_PROCESS_INFO *procInfo = CProcessTree::shared()->FindByPid(exitPid);
        if ( procInfo )
        {
            procInfo->ExitTime = (int32_t)time(nullptr);
            //            procInfo->PrintProcess();
            ProcTreeKey key;
            key.PID        = procInfo->ProcessId;
            key.PPID       = procInfo->ParentId;
            key.CreateTime = procInfo->CreateTime;
            key.type       = KeyType::FullKey;
            CProcessTree::shared()->markExit(key);
        }
        else
        {
        }
    }
    catch ( const std::exception &e )
    {
        LOG_ERROR("Exception in handleNotifyExitEvent: {}", e.what());
    }
}
