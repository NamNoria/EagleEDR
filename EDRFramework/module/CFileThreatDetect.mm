#include "CFileThreatDetect.h"
#include "CFilterRule.h"
#include "CThreatEvent.h"
#include "CProcessTree.h"
#include "../common/EsfUtils.h"
#include "../common/SystemUtils.h"
#include "../common/Logger.h"
#include "../CThreatDetect.h"
#include "../common/Consts.h"

CFileThreatDetect::CFileThreatDetect()
{

}

CFileThreatDetect::~CFileThreatDetect()
{

}

CFileThreatDetect *CFileThreatDetect::shared()
{
    static CFileThreatDetect instance;
    return &instance;
}

bool CFileThreatDetect::OnAuthEventReceived(es_event_type_t eventType, const es_message_t *message)
{
    if (!message)
    {
        return true;
    }

    // 检查文件检测功能是否启用
    CThreatDetect *threatDetect = CThreatDetect::Shared();
    uint32_t enabledFeatures = threatDetect->GetEnabledFeatures();

    switch (eventType)
    {
        case ES_EVENT_TYPE_AUTH_CREATE:
            if (!(enabledFeatures & EDR_FEATURE_FILE_CREATE)) {
                return true;  // 文件创建检测未启用，放行
            }
            return handleAuthCreateEvent(message);
        case ES_EVENT_TYPE_AUTH_RENAME:
            if (!(enabledFeatures & EDR_FEATURE_FILE_RENAME)) {
                return true;  // 文件重命名检测未启用，放行
            }
            return handleAuthRenameEvent(message);
        default:
            return true;
    }
}

void CFileThreatDetect::OnNotifyEventReceived(es_event_type_t eventType, const es_message_t *message)
{
    if (!message)
    {
        return;
    }

    switch (eventType)
    {
        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            handleNotifyCloseEvent(message);
            break;
        default:
            break;
    }
}

std::vector<es_event_type_t> CFileThreatDetect::GetSubscribedEventTypes() const
{
    return {
        ES_EVENT_TYPE_AUTH_CREATE,
        ES_EVENT_TYPE_AUTH_RENAME,
        ES_EVENT_TYPE_NOTIFY_CLOSE
    };
}

static inline void MapActionToFlags(ActionStatus action, bool &allow, bool &report)
{
    switch (action)
    {
        case RULE_ACTION_PASS://上报日志不拦截
            allow = true;
            report = true;
            break;
        case RULE_ACTION_BLOCK://上报告警拦截
            allow = false;
            report = true;
            break;
        case RULE_ACTION_REPORT://上报告警不拦截
            allow = true;
            report = true;
            break;
        case RULE_ACTION_FILTER://不上报不拦截
            allow = true;
            report = false;
            break;
        default:
            allow = true;
            report = false;
            break;
    }
}

bool CFileThreatDetect::handleAuthCreateEvent(const es_message_t *message)
{
    if (!message || message->event_type != ES_EVENT_TYPE_AUTH_CREATE)
    {
        return true;
    }

    // 快速过滤：检查是否为编译器/开发工具进程，避免昂贵的CMD获取
    pid_t pid = message->process->audit_token.val[5];
    if (SystemUtils::IsCompilerOrDevToolProcess(pid)) {
        LOG_DEBUG("Skipping file create event from compiler/dev tool process (pid={})", pid);
        return true;  // 允许操作，但跳过详细分析
    }

    CFilterRule *pFilterRule = CFilterRule::shared();
    if (!pFilterRule)
    {
        return true;
    }

    // 声明指针变量
    THREAT_PROC_INFO *procInfo = nullptr;
    FILE_CREATE_INFO *eventInfo = nullptr;

    try {
        // 分配内存
        procInfo = (THREAT_PROC_INFO *)malloc(sizeof(THREAT_PROC_INFO));
        if (!procInfo) throw std::bad_alloc();

        eventInfo = (FILE_CREATE_INFO *)malloc(sizeof(FILE_CREATE_INFO));
        if (!eventInfo) {
            free(procInfo);
            throw std::bad_alloc();
        }

        memset(procInfo, 0, sizeof(THREAT_PROC_INFO));
        memset(eventInfo, 0, sizeof(FILE_CREATE_INFO));
        // 获取进程信息
        EsfUtils::GetProcInfo(message, EsfUtils::GetPid(message), procInfo);

        // 获取文件路径
        const es_event_create_t &createEvent = message->event.create;
        std::string filePath;

        if (createEvent.destination_type == ES_DESTINATION_TYPE_NEW_PATH)
        {
            const es_file_t *dirFile = createEvent.destination.new_path.dir;
            if (dirFile && dirFile->path.data)
            {
                std::string dirPath(dirFile->path.data, dirFile->path.length);
                std::string filename(createEvent.destination.new_path.filename.data,
                                   createEvent.destination.new_path.filename.length);
                filePath = dirPath + "/" + filename;
            }
        }
        else if (createEvent.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE)
        {
            if (createEvent.destination.existing_file &&
                createEvent.destination.existing_file->path.data)
            {
                filePath.assign(createEvent.destination.existing_file->path.data,
                              createEvent.destination.existing_file->path.length);
            }
        }

        if (!filePath.empty())
        {
            eventInfo->filepath = strdup(filePath.c_str());
        }

        // 调用过滤规则
        std::string threatInfo;
        ActionStatus actionStatus = pFilterRule->FileCreateFilterAllow(eventInfo, procInfo, &threatInfo);

        bool bAllow = true;
        bool bReport = false;
        MapActionToFlags(actionStatus, bAllow, bReport);

        if (bReport)
        {
            // 创建事件并上报
            EAGLE_THREAT_CREATE_FILE_INFO *pEventInfo = new EAGLE_THREAT_CREATE_FILE_INFO();
            pEventInfo->CreateTime = (int32_t)EsfUtils::GetUtcTime(message);
            pEventInfo->FileName = filePath;
            pEventInfo->ProcessGuid = EsfUtils::GetGUID(message) ? [EsfUtils::GetGUID(message) UTF8String] : "";
            pEventInfo->UtcTime = EsfUtils::GetUtcTime(message);

            CFileCreateThreatEvent *evt = new CFileCreateThreatEvent(pEventInfo);
            evt->des = std::move(threatInfo);
            evt->eventId = EDR_EVENT_CREATEFILE;
            evt->action = actionStatus;
            evt->reportType = (actionStatus == RULE_ACTION_PASS) ? REPORT_TYPE_LOG : REPORT_TYPE_ALERT;
            EsfUtils::FillCreateFileEvent(message, evt->eventInfo.pCreate);
            pid_t leafPid = EsfUtils::GetPid(message);
            evt->procInfoBuff = CProcessTree::shared()->GetProcessChain(leafPid);
            evt->ip = EsfUtils::GetPrimaryIPv4();
            evt->host = EsfUtils::GetHostName();
            CThreatDetect::Shared()->Report(evt);
            delete pEventInfo;
        }

        // 清理内存
        SystemUtils::FreeReportProcInfo(procInfo);
        free(procInfo);

        if (eventInfo->filepath) {
            free((void*)eventInfo->filepath);
        }
        free(eventInfo);

        return bAllow;
    }
    catch (const std::exception &e)
    {
        LOG_ERROR("Exception in handleAuthCreateEvent: {}", e.what());

        // 异常时清理内存
        if (procInfo) {
            SystemUtils::FreeReportProcInfo(procInfo);
            free(procInfo);
        }

        if (eventInfo) {
            if (eventInfo->filepath) {
                free((void*)eventInfo->filepath);
            }
            free(eventInfo);
        }

        return true;
    }
}

bool CFileThreatDetect::handleAuthRenameEvent(const es_message_t *message)
{
    if (!message || message->event_type != ES_EVENT_TYPE_AUTH_RENAME)
    {
        return true;
    }

    // 快速过滤：检查是否为编译器/开发工具进程，避免昂贵的CMD获取
    pid_t pid = message->process->audit_token.val[5];
    if (SystemUtils::IsCompilerOrDevToolProcess(pid)) {
        LOG_DEBUG("Skipping file rename event from compiler/dev tool process (pid={})", pid);
        return true;  // 允许操作，但跳过详细分析
    }

    CFilterRule *pFilterRule = CFilterRule::shared();
    if (!pFilterRule)
    {
        return true;
    }

    // 声明指针变量
    THREAT_PROC_INFO *procInfo = nullptr;
    FILE_RENAME_INFO *eventInfo = nullptr;

    try {
        // 分配内存
        procInfo = (THREAT_PROC_INFO *)malloc(sizeof(THREAT_PROC_INFO));
        if (!procInfo) throw std::bad_alloc();

        eventInfo = (FILE_RENAME_INFO *)malloc(sizeof(FILE_RENAME_INFO));
        if (!eventInfo) {
            free(procInfo);
            throw std::bad_alloc();
        }

        memset(procInfo, 0, sizeof(THREAT_PROC_INFO));
        memset(eventInfo, 0, sizeof(FILE_RENAME_INFO));
        EsfUtils::GetProcInfo(message, EsfUtils::GetPid(message), procInfo);

        // 获取文件路径
        const es_event_rename_t &renameEvent = message->event.rename;
        std::string srcPath;
        std::string dstPath;

        // 源文件路径
        if (renameEvent.source && renameEvent.source->path.data)
        {
            srcPath.assign(renameEvent.source->path.data, renameEvent.source->path.length);
        }

        // 目标文件路径
        if (renameEvent.destination_type == ES_DESTINATION_TYPE_NEW_PATH)
        {
            if (renameEvent.destination.new_path.dir &&
                renameEvent.destination.new_path.dir->path.data)
            {
                std::string dirPath(renameEvent.destination.new_path.dir->path.data,
                                  renameEvent.destination.new_path.dir->path.length);
                std::string filename(renameEvent.destination.new_path.filename.data,
                                   renameEvent.destination.new_path.filename.length);
                dstPath = dirPath + "/" + filename;
            }
        }
        else if (renameEvent.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE)
        {
            if (renameEvent.destination.existing_file &&
                renameEvent.destination.existing_file->path.data)
            {
                dstPath.assign(renameEvent.destination.existing_file->path.data,
                             renameEvent.destination.existing_file->path.length);
            }
        }

        if (!srcPath.empty())
        {
            eventInfo->old_filepath = strdup(srcPath.c_str());
        }

        if (!dstPath.empty())
        {
            eventInfo->new_filepath = strdup(dstPath.c_str());
        }

        // 调用过滤规则
        std::string threatInfo;
        ActionStatus actionStatus = pFilterRule->FileRenameFilterAllow(eventInfo, procInfo, &threatInfo);

        bool bAllow = true;
        bool bReport = false;
        MapActionToFlags(actionStatus, bAllow, bReport);

        if (bReport)
        {
            EAGLE_THREAT_RENAME_FILE_INFO *pEventInfo = new EAGLE_THREAT_RENAME_FILE_INFO();

            // 从已解析的eventInfo填充数据，而不是重新解析ESF消息
            pEventInfo->UtcTime = (int32_t)EsfUtils::GetUtcTime(message);
            pEventInfo->ProcessGuid = EsfUtils::GetGUID(message) ? [EsfUtils::GetGUID(message) UTF8String] : "";
            pEventInfo->OldPath = eventInfo->old_filepath ? eventInfo->old_filepath : "";
            pEventInfo->NewPath = eventInfo->new_filepath ? eventInfo->new_filepath : "";
            pEventInfo->FileID = "";  // 可以后续从文件系统获取
            pEventInfo->FileSigner = "";  // 暂时留空

            // 创建事件对象（会拷贝pEventInfo的内容）
            CFileRenameThreatEvent *renameEvt = new CFileRenameThreatEvent(pEventInfo);
            renameEvt->des = std::move(threatInfo);
            renameEvt->eventId = EDR_EVENT_FILERENAME;
            renameEvt->action = actionStatus;
            renameEvt->reportType = (actionStatus == RULE_ACTION_PASS) ? REPORT_TYPE_LOG : REPORT_TYPE_ALERT;

            pid_t leafPid = EsfUtils::GetPid(message);
            renameEvt->procInfoBuff = CProcessTree::shared()->GetProcessChain(leafPid);
            renameEvt->ip = EsfUtils::GetPrimaryIPv4();
            renameEvt->host = EsfUtils::GetHostName();

            // 上报事件
            CThreatDetect::Shared()->Report(renameEvt);

            // 现在可以安全删除临时对象，因为内容已经被拷贝到renameEvt->m_event中
            delete pEventInfo;
        }

        // 清理内存
        SystemUtils::FreeReportProcInfo(procInfo);
        free(procInfo);

        if (eventInfo->old_filepath) {
            free((void*)eventInfo->old_filepath);
        }
        if (eventInfo->new_filepath) {
            free((void*)eventInfo->new_filepath);
        }
        free(eventInfo);

        return bAllow;
    }
    catch (const std::exception &e)
    {
        LOG_ERROR("Exception in handleAuthRenameEvent: {}", e.what());

        // 异常时清理内存
        if (procInfo) {
            SystemUtils::FreeReportProcInfo(procInfo);
            free(procInfo);
        }

        if (eventInfo) {
            if (eventInfo->old_filepath) {
                free((void*)eventInfo->old_filepath);
            }
            if (eventInfo->new_filepath) {
                free((void*)eventInfo->new_filepath);
            }
            free(eventInfo);
        }

        return true;
    }
}

void CFileThreatDetect::handleNotifyCloseEvent(const es_message_t *message)
{
    if (!message || message->event_type != ES_EVENT_TYPE_NOTIFY_CLOSE)
    {
        return;
    }

    // 快速过滤：检查是否为编译器/开发工具进程，避免处理大量文件关闭事件
    pid_t pid = message->process->audit_token.val[5];
    if (SystemUtils::IsCompilerOrDevToolProcess(pid)) {
        return;  // 编译器进程的文件关闭事件直接跳过
    }

    try
    {
        // 从 close 事件获取文件路径
        std::string filePath;
        const es_event_close_t &closeEvent = message->event.close;
        if (closeEvent.target && closeEvent.target->path.data)
        {
            filePath.assign(closeEvent.target->path.data, closeEvent.target->path.length);
        }
        if (filePath.empty())
        {
            return;
        }

        std::lock_guard<std::mutex> lock(m_cacheMutex);
        auto it = m_createCache.find(filePath);
        if (it != m_createCache.end())
        {
            LOG_DEBUG("File close matched create cache: {}", filePath);
            m_createCache.erase(it);
        }
    }
    catch (const std::exception &e)
    {
        LOG_ERROR("Exception in handleNotifyCloseEvent: {}", e.what());
    }
}
