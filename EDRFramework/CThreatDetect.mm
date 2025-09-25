#include <pthread.h>
#include <Foundation/Foundation.h>

#include "CThreatDetect.h"
#include "common/edr_event.pb.h"
#include "common/macro.h"
#include "common/CodeUtils.h"
#include "common/Logger.h"
#include "common/SystemUtils.h"
#include "common/YSHTTP/YSHTTP.h"
#import "common/YSHTTP/HTTPS/YSHTTPGateway.h"
#import "common/YSHTTP/HTTPS/YSHTTPRequest.h"
#import "common/YSHTTP/HTTPS/YSHTTPResponse.h"
#include "common/Consts.h"
#include "ESF/CESFClientManager.h"
#include "ESF/CESFDispatcher.h"
#include "module/CProcessTree.h"
#include "module/CProcessThreatDetect.h"
#include "module/CFileThreatDetect.h"
#include "module/CNetThreatDetect.h"
#include "module/CThreatEvent.h"
#include "module/IESFEventObserver.h"

pthread_mutex_t            CThreatDetect::m_queMutex    = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t            CThreatDetect::m_switchMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t             CThreatDetect::m_queCond     = PTHREAD_COND_INITIALIZER;
std::queue<CThreatEvent *> CThreatDetect::m_queEvents;
uint64_t                   gSilentStartUtc = static_cast<uint64_t>(time(nullptr));

const int g_iThreatEventQueSize = 0x1000;

class CThreatDetect::Impl
{
public:
    Impl()
    {
    }

    ~Impl()
    {
        UnInitialize();
    }

    bool Initialize()
    {
        try
        {
            // 初始化日志系统
            Logger::instance().init();
            LOG_INFO("EDR threat detection system starting...");

            // 创建ES客户端
            m_pEsfClientManager = CEsfClientManager::shared();
            m_pEsfClientManager->Initialize();

            // 初始化进程树，扫描进程信息，预构建进程树
            m_pProcessTree = CProcessTree::shared();
            m_pProcessTree->StartAging();
            m_pProcessTree->BuildProcessTree();

            // 初始化事件分发器
            m_pEsfDispatcher = CEsfDispatcher::shared();
            m_pEsfDispatcher->Initialize();

            m_pProcessThreatDetect = CProcessThreatDetect::shared();
            m_pFileThreatDetect    = CFileThreatDetect::shared();
            m_pNetThreatDetect     = CNetThreatDetect::shared();

            // 初始化网络威胁检测模块（失败不影响整体初始化）
            if ( !m_pNetThreatDetect->Initialize() )
            {
                LOG_WARN("Failed to initialize network threat detection, continuing without network monitoring");
            }
        }
        catch ( const std::exception &e )
        {
            LOG_ERROR("Exception during initialization: {}", e.what());
            return false;
        }
        catch ( ... )
        {
            LOG_ERROR("Unknown exception during initialization");
            return false;
        }

        m_observers.push_back(m_pFileThreatDetect);
        m_observers.push_back(m_pProcessThreatDetect);
        return true;
    }

    bool UnInitialize()
    {

        if ( m_pEsfClientManager )
        {
            m_pEsfClientManager = nullptr;
        }

        if ( m_pEsfDispatcher )
        {
            m_pEsfDispatcher = nullptr;
        }

        if ( m_pFileThreatDetect )
        {
            m_pFileThreatDetect = nullptr;
        }

        if ( m_pProcessThreatDetect )
        {
            m_pProcessThreatDetect = nullptr;
        }

        if ( m_pNetThreatDetect )
        {
            m_pNetThreatDetect->UnInitialize();
            m_pNetThreatDetect = nullptr;
        }

        return true;
    }

    void Enable()
    {
        // 获取启动时间
        gSilentStartUtc = static_cast<uint64_t>(time(nullptr));

        for ( auto observer: m_observers )
        {
            if ( !observer )
            {
                LOG_WARN("Observer is nullptr for enable operation");
                continue;
            }
            for ( auto eventtype: observer->GetSubscribedEventTypes() )
            {
                m_pEsfDispatcher->SubscribeEvent(eventtype, observer);
            }
        }
        // 统计和打印事件类型详情
        std::vector<std::string> eventTypeNames;
        for ( auto observer: m_observers )
        {
            if ( !observer )
            {
                continue;
            }
            auto eventTypes = observer->GetSubscribedEventTypes();
            for ( auto eventType: eventTypes )
            {
                std::string typeName;
                switch ( eventType )
                {
                    case ES_EVENT_TYPE_AUTH_EXEC:
                        typeName = "AUTH_EXEC";
                        break;
                    case ES_EVENT_TYPE_NOTIFY_EXIT:
                        typeName = "NOTIFY_EXIT";
                        break;
                    case ES_EVENT_TYPE_AUTH_CREATE:
                        typeName = "AUTH_CREATE";
                        break;
                    case ES_EVENT_TYPE_AUTH_RENAME:
                        typeName = "AUTH_RENAME";
                        break;
                    case ES_EVENT_TYPE_NOTIFY_CLOSE:
                        typeName = "NOTIFY_CLOSE";
                        break;
                    default:
                        typeName = "EVENT_" + std::to_string(static_cast<int>(eventType));
                        break;
                }
                eventTypeNames.push_back(typeName);
            }
        }

        std::string eventTypesList;
        for ( size_t i = 0; i < eventTypeNames.size(); ++i )
        {
            if ( i > 0 )
            {
                eventTypesList += ", ";
            }
            eventTypesList += eventTypeNames[i];
        }
        LOG_INFO("EventTypeSum: {}, types: [{}]", eventTypeNames.size(), eventTypesList);
        m_pEsfClientManager->SetDefaultSubscription();

        return;
    }

    void EnableFeatures(uint32_t features)
    {
        // 获取启动时间
        gSilentStartUtc = static_cast<uint64_t>(time(nullptr));

        // 根据功能开关订阅对应事件
        if ( features & EDR_FEATURE_PROCESS_START )
        {
            if ( m_pProcessThreatDetect )
            {
                for ( auto eventtype: m_pProcessThreatDetect->GetSubscribedEventTypes() )
                {
                    m_pEsfDispatcher->SubscribeEvent(eventtype, m_pProcessThreatDetect);
                }
                LOG_INFO("Enabled process start detection");
            }
        }

        // 进程树特殊处理：即使不启用进程启动检测，如果启用了进程树功能，
        // 也需要订阅进程事件来维护进程树（通过进程检测模块间接维护）
        if ( (features & EDR_FEATURE_PROCESS_TREE) && !(features & EDR_FEATURE_PROCESS_START) )
        {
            if ( m_pProcessThreatDetect )
            {
                for ( auto eventtype: m_pProcessThreatDetect->GetSubscribedEventTypes() )
                {
                    m_pEsfDispatcher->SubscribeEvent(eventtype, m_pProcessThreatDetect);
                }
                LOG_INFO("Process tree enabled: subscribing to process events for tree maintenance");
            }
        }

        if ( features & (EDR_FEATURE_FILE_CREATE | EDR_FEATURE_FILE_RENAME) )
        {
            if ( m_pFileThreatDetect )
            {
                for ( auto eventtype: m_pFileThreatDetect->GetSubscribedEventTypes() )
                {
                    // 根据具体的feature决定是否订阅某个事件类型
                    bool shouldSubscribe = false;
                    if ( eventtype == ES_EVENT_TYPE_AUTH_CREATE && (features & EDR_FEATURE_FILE_CREATE) )
                    {
                        shouldSubscribe = true;
                    }
                    if ( eventtype == ES_EVENT_TYPE_AUTH_RENAME && (features & EDR_FEATURE_FILE_RENAME) )
                    {
                        shouldSubscribe = true;
                    }
                    if ( shouldSubscribe )
                    {
                        m_pEsfDispatcher->SubscribeEvent(eventtype, m_pFileThreatDetect);
                    }
                }
                LOG_INFO("Enabled file detection features: create={}, rename={}",
                         (features & EDR_FEATURE_FILE_CREATE) ? "yes" : "no",
                         (features & EDR_FEATURE_FILE_RENAME) ? "yes" : "no");
            }
        }

        if ( features & EDR_FEATURE_NETWORK_MONITOR )
        {
            // 网络监测暂时保持原有逻辑，不做事件订阅
            LOG_INFO("Network monitoring feature enabled");
        }

        m_pEsfClientManager->SetDefaultSubscription();
        LOG_INFO("Enabled features: 0x{:08x}", features);
    }

    void Disable()
    {
        if ( m_pEsfDispatcher )
        {
            m_pEsfDispatcher->m_eventSubscriptions.clear();
        }

        LOG_INFO("Disabled all event subscriptions");
    }

    void DisableFeatures(uint32_t features)
    {
        if ( !m_pEsfDispatcher )
        {
            return;
        }

        // 需要从事件订阅中移除特定的观察者
        auto &subscriptions = m_pEsfDispatcher->m_eventSubscriptions;

        if ( features & EDR_FEATURE_PROCESS_START )
        {
            if ( m_pProcessThreatDetect )
            {
                for ( auto eventtype: m_pProcessThreatDetect->GetSubscribedEventTypes() )
                {
                    auto it = subscriptions.find(eventtype);
                    if ( it != subscriptions.end() )
                    {
                        auto &observers = it->second;
                        observers.erase(std::remove(observers.begin(), observers.end(), m_pProcessThreatDetect),
                                        observers.end());
                        if ( observers.empty() )
                        {
                            subscriptions.erase(it);
                        }
                    }
                }
                LOG_INFO("Disabled process start detection");
            }
        }

        if ( features & (EDR_FEATURE_FILE_CREATE | EDR_FEATURE_FILE_RENAME) )
        {
            if ( m_pFileThreatDetect )
            {
                for ( auto eventtype: m_pFileThreatDetect->GetSubscribedEventTypes() )
                {
                    bool shouldRemove = false;
                    if ( eventtype == ES_EVENT_TYPE_AUTH_CREATE && (features & EDR_FEATURE_FILE_CREATE) )
                    {
                        shouldRemove = true;
                    }
                    if ( eventtype == ES_EVENT_TYPE_AUTH_RENAME && (features & EDR_FEATURE_FILE_RENAME) )
                    {
                        shouldRemove = true;
                    }
                    if ( shouldRemove )
                    {
                        auto it = subscriptions.find(eventtype);
                        if ( it != subscriptions.end() )
                        {
                            auto &observers = it->second;
                            observers.erase(std::remove(observers.begin(), observers.end(), m_pFileThreatDetect),
                                            observers.end());
                            if ( observers.empty() )
                            {
                                subscriptions.erase(it);
                            }
                        }
                    }
                }
                LOG_INFO("Disabled file detection features: create={}, rename={}",
                         (features & EDR_FEATURE_FILE_CREATE) ? "yes" : "no",
                         (features & EDR_FEATURE_FILE_RENAME) ? "yes" : "no");
            }
        }

        if ( features & EDR_FEATURE_NETWORK_MONITOR )
        {
            LOG_INFO("Network monitoring feature disabled");
        }

        LOG_INFO("Disabled features: 0x{:08x}", features);
    }

    void PrintTree(pid_t pid)
    {
        m_pProcessTree->PrintTree(pid);
    }

private:
    CEsfClientManager    *m_pEsfClientManager;
    CEsfDispatcher       *m_pEsfDispatcher;
    CFileThreatDetect    *m_pFileThreatDetect;
    CProcessTree         *m_pProcessTree;
    CProcessThreatDetect *m_pProcessThreatDetect;
    CNetThreatDetect     *m_pNetThreatDetect;

    std::vector<IESFEventObserver *> m_observers;
};

const int g_iEventQueSize = 0x1000;

CThreatDetect::CThreatDetect()
{
    Logger::instance().init("logs/edr.log");
    m_bEnabled        = false;
    m_enabledFeatures = 0;  // 默认所有子功能都关闭
    m_bInitialized    = false;
}

CThreatDetect::~CThreatDetect()
{
}

CThreatDetect *CThreatDetect::Shared()
{
    static CThreatDetect instance;
    return &instance;
}

bool CThreatDetect::Initialize()
{
    try
    {
        m_pImpl = std::unique_ptr<Impl>(new Impl());
        if ( !m_pImpl->Initialize() )
        {
            LOG_ERROR("Failed to initialize Impl instance in Enable()");
            return false;
        }

        m_bInitialized = true;

        // 创建规则更新定时线程，线程需要DETACH
        pthread_t tidRulesUpdateThread;

        pthread_attr_t rulesAttr;
        pthread_attr_init(&rulesAttr);
        pthread_attr_setdetachstate(&rulesAttr, PTHREAD_CREATE_DETACHED);

        int rulesThreadResult =
                pthread_create(&tidRulesUpdateThread, &rulesAttr, CThreatDetect::rulesUpdateThreadFunc, (void *)this);
        pthread_attr_destroy(&rulesAttr);
        if ( 0 != rulesThreadResult )
        {
            LOG_ERROR("Failed to create rules update thread, pthread_create error");
        }
        else
        {
            LOG_INFO("Rules update thread created successfully");
        }

        // 创建事件上报线程，线程需要DETACH
        pthread_t tidReportThread;

        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

        int bSetSuccess = pthread_create(&tidReportThread, &attr, CThreatDetect::reportThreadFunc, (void *)this);
        pthread_attr_destroy(&attr);
        if ( 0 != bSetSuccess )
        {
            LOG_ERROR("Failed to create report thread (EDR-Reporter), pthread_create error");
        }
        else
        {
            LOG_INFO("Event report thread (EDR-Reporter) created successfully");
        }
        return true;
    }
    catch ( const std::exception &e )
    {
        LOG_ERROR("Exception during enable: {}", e.what());
        return false;
    }
    catch ( ... )
    {
        LOG_ERROR("Unknown exception during enable");
        return false;
    }
}

bool CThreatDetect::UnInitialize()
{
    if ( m_pImpl )
    {
        m_pImpl->UnInitialize();
        m_pImpl.reset();
    }

    // 清理事件队列，释放所有未处理的事件
    pthread_mutex_lock(&m_queMutex);
    while ( !m_queEvents.empty() )
    {
        CThreatEvent *event = m_queEvents.front();
        m_queEvents.pop();
        delete event;  // 释放事件对象内存
    }
    pthread_mutex_unlock(&m_queMutex);

    m_bInitialized = false;
    m_bEnabled     = false;

    pthread_mutex_destroy(&m_queMutex);
    pthread_cond_destroy(&m_queCond);
    return true;
}

bool CThreatDetect::Enable()
{
    if ( !m_bInitialized )
    {
        LOG_WARN("Cannot enable: system not initialized");
        return false;
    }
    if ( m_bEnabled )
    {
        LOG_INFO("System already enabled, skipping");
        return true;
    }
    pthread_mutex_lock(&m_switchMutex);
    m_enabledFeatures = EDR_FEATURE_ALL;
    m_pImpl->Enable();
    m_bEnabled = true;
    pthread_mutex_unlock(&m_switchMutex);
    // 生成功能列表字符串
    std::vector<std::string> featureNames;
    if ( m_enabledFeatures & EDR_FEATURE_PROCESS_START )
    {
        featureNames.push_back("PROCESS_START");
    }
    if ( m_enabledFeatures & EDR_FEATURE_PROCESS_TREE )
    {
        featureNames.push_back("PROCESS_TREE");
    }
    if ( m_enabledFeatures & EDR_FEATURE_FILE_CREATE )
    {
        featureNames.push_back("FILE_CREATE");
    }
    if ( m_enabledFeatures & EDR_FEATURE_FILE_RENAME )
    {
        featureNames.push_back("FILE_RENAME");
    }
    if ( m_enabledFeatures & EDR_FEATURE_NETWORK_MONITOR )
    {
        featureNames.push_back("NETWORK_MONITOR");
    }

    std::string featuresList;
    for ( size_t i = 0; i < featureNames.size(); ++i )
    {
        if ( i > 0 )
        {
            featuresList += ", ";
        }
        featuresList += featureNames[i];
    }
    LOG_INFO("System enabled with all features (0x{:08x}): [{}]", m_enabledFeatures, featuresList);
    return true;
}

bool CThreatDetect::Disable()
{
    if ( !m_bInitialized )
    {
        LOG_INFO("System not initialized, no need to disable");
        return true;
    }
    if ( !m_bEnabled )
    {
        LOG_INFO("System already disabled, skipping");
        return true;
    }
    pthread_mutex_lock(&m_switchMutex);
    m_pImpl->Disable();
    m_bEnabled        = false;
    m_enabledFeatures = 0;  // 清除所有功能标记
    pthread_mutex_unlock(&m_switchMutex);
    return true;
}

bool CThreatDetect::IsEnabled()
{
    pthread_mutex_lock(&m_switchMutex);
    bool bEnable = m_bEnabled;
    pthread_mutex_unlock(&m_switchMutex);
    return bEnable;
}

bool CThreatDetect::EnableFeatures(uint32_t features)
{
    if ( !m_bInitialized )
    {
        LOG_ERROR("System not initialized, cannot enable features");
        return false;
    }

    pthread_mutex_lock(&m_switchMutex);

    if ( !m_pImpl )
    {
        LOG_ERROR("Failed to access Impl instance in EnableFeatures()");
        pthread_mutex_unlock(&m_switchMutex);
        return false;
    }

    m_pImpl->EnableFeatures(features);
    m_enabledFeatures |= features;  // 添加新的功能

    // 如果系统还未启用，现在启用它
    if ( !m_bEnabled )
    {
        m_bEnabled = true;
    }

    pthread_mutex_unlock(&m_switchMutex);
    LOG_INFO("Features enabled: 0x{:08x}, total enabled: 0x{:08x}", features, m_enabledFeatures);
    return true;
}

bool CThreatDetect::DisableFeatures(uint32_t features)
{
    if ( !m_bInitialized )
    {
        LOG_ERROR("System not initialized, cannot disable features");
        return false;
    }

    pthread_mutex_lock(&m_switchMutex);

    if ( !m_pImpl )
    {
        LOG_ERROR("Failed to access Impl instance in DisableFeatures()");
        pthread_mutex_unlock(&m_switchMutex);
        return false;
    }

    m_pImpl->DisableFeatures(features);
    m_enabledFeatures &= ~features;  // 移除指定功能

    // 如果所有功能都关闭了，禁用整个系统
    if ( m_enabledFeatures == 0 )
    {
        m_bEnabled = false;
        LOG_INFO("All features disabled, system disabled");
    }

    pthread_mutex_unlock(&m_switchMutex);
    LOG_INFO("Features disabled: 0x{:08x}, remaining enabled: 0x{:08x}", features, m_enabledFeatures);
    return true;
}

uint32_t CThreatDetect::GetEnabledFeatures()
{
    pthread_mutex_lock(&m_switchMutex);
    uint32_t features = m_enabledFeatures;
    pthread_mutex_unlock(&m_switchMutex);
    return features;
}

void CThreatDetect::PrintTree(pid_t pid)
{
    return m_pImpl->PrintTree(pid);
}

void CThreatDetect::Report(CThreatEvent *event)
{
    if ( !event )
    {
        return;
    }
    pthread_mutex_lock(&m_queMutex);
    if ( m_queEvents.size() >= g_iEventQueSize )
    {
        // 正确释放被移除事件的内存
        CThreatEvent *oldEvent = m_queEvents.front();
        m_queEvents.pop();
        delete oldEvent;  // 释放事件对象内存
    }
    m_queEvents.push(event);
    pthread_mutex_unlock(&m_queMutex);
    pthread_cond_signal(&m_queCond);
}

void *CThreatDetect::reportThreadFunc(void *arg)
{
    pthread_t tid = pthread_self();

    // 设置线程名称
    pthread_setname_np("EDR-Reporter");

    LOG_INFO("Report thread (EDR-Reporter) started, tid={}", (void *)tid);

    CThreatDetect *pThreatDetection = (CThreatDetect *)arg;

    NSString     *json        = YSCODEUtils::decryptConfig(kYunshuConfigUserInfoPath);
    NSData       *jsonData    = [json dataUsingEncoding:NSUTF8StringEncoding];
    NSError      *err         = nil;
    NSDictionary *userInfo    = [NSJSONSerialization JSONObjectWithData:jsonData
                                                             options:NSJSONReadingMutableContainers
                                                               error:&err];
    NSString     *token       = [userInfo objectForKey:@"token"];
    NSString     *strDomain   = userInfo[@"apiDomain"];
    NSString     *strCorpCode = userInfo[@"corpname"];

    [YSHttpClient updateGatewayWithToken:token domain:strDomain corpCode:strCorpCode];

    while ( true )
    {
        pthread_mutex_lock(&m_queMutex);

        // 等待通知，直到队列不为空或开关关闭
        while ( m_queEvents.empty() )
        {
            pthread_cond_wait(&m_queCond, &m_queMutex);
        }

        CThreatEvent *event = m_queEvents.front();
        m_queEvents.pop();
        pthread_mutex_unlock(&m_queMutex);

        try
        {
            // 使用ToPB方法，内部根据reportType选择不同的protobuf格式
            NSData *data = event->ToPB();
            if ( !data || [data length] == 0 )
            {
                const char *serializationType = (event->reportType == REPORT_TYPE_LOG) ? "Log" : "Alert";
                LOG_ERROR("{} serialization failed: protobuf data is empty, event={}", serializationType,
                          static_cast<void *>(event));
                continue;
            }
            const char *serializationType = (event->reportType == REPORT_TYPE_LOG) ? "Log" : "Alert";
            LOG_DEBUG("{} serialized successfully, size={} bytes, event_type={}", serializationType, [data length],
                      typeid(*event).name());
            static std::vector<NSData *> failedQueue;
            static pthread_mutex_t       failedQueueMutex    = PTHREAD_MUTEX_INITIALIZER;
            static const size_t          kMaxFailedQueueSize = 500;  // 限制失败队列大小
            __block bool                 mainSuccess         = false;
            dispatch_semaphore_t         mainSema            = dispatch_semaphore_create(0);

            // 生成事件类型描述
            std::string eventTypeDesc = "Unknown";
            std::string eventDetails  = "";

            if ( auto *procEvent = dynamic_cast<const CProcExecThreatEvent *>(event) )
            {
                eventTypeDesc = "ProcessExec";
                if ( procEvent->eventInfo.pProcess && !procEvent->eventInfo.pProcess->ImagePath.empty() )
                {
                    eventDetails = std::string("image=") + procEvent->eventInfo.pProcess->ImagePath;
                }
            }
            else if ( auto *fileCreateEvent = dynamic_cast<const CFileCreateThreatEvent *>(event) )
            {
                eventTypeDesc = "FileCreate";
                if ( fileCreateEvent->eventInfo.pCreate && !fileCreateEvent->eventInfo.pCreate->FileName.empty() )
                {
                    eventDetails = std::string("file=") + fileCreateEvent->eventInfo.pCreate->FileName;
                }
            }
            else if ( auto *fileRenameEvent = dynamic_cast<const CFileRenameThreatEvent *>(event) )
            {
                eventTypeDesc = "FileRename";
                if ( fileRenameEvent->eventInfo.pRename && !fileRenameEvent->eventInfo.pRename->OldPath.empty()
                     && !fileRenameEvent->eventInfo.pRename->NewPath.empty() )
                {
                    eventDetails = std::string("from=") + fileRenameEvent->eventInfo.pRename->OldPath
                                   + ", to=" + fileRenameEvent->eventInfo.pRename->NewPath;
                }
            }
            else if ( auto *netEvent = dynamic_cast<const CNetConThreatEvent *>(event) )
            {
                eventTypeDesc = "NetworkConnection";
                char buffer[256];
                // 将uint32_t IP地址转换为字符串
                char     srcIp[16], dstIp[16];
                uint32_t src = netEvent->netConInfo.SourceIp;
                uint32_t dst = netEvent->netConInfo.DestinationIp;
                snprintf(srcIp, sizeof(srcIp), "%d.%d.%d.%d", (src >> 24) & 0xFF, (src >> 16) & 0xFF, (src >> 8) & 0xFF,
                         src & 0xFF);
                snprintf(dstIp, sizeof(dstIp), "%d.%d.%d.%d", (dst >> 24) & 0xFF, (dst >> 16) & 0xFF, (dst >> 8) & 0xFF,
                         dst & 0xFF);
                snprintf(buffer, sizeof(buffer), "proto=%d, src=%s:%d, dst=%s:%d", netEvent->netConInfo.Protocol, srcIp,
                         netEvent->netConInfo.SourcePort, dstIp, netEvent->netConInfo.DestinationPort);
                eventDetails = buffer;
            }

            // 根据reportType字段选择不同的上报接口
            bool isLogReport = (event->reportType == REPORT_TYPE_LOG);

            if ( isLogReport )
            {
                // RULE_ACTION_PASS - 上报日志
                [YSHttpClient reportEDRLog:data
                                 remoteURL:@""
                                  complate:^(NSError *error) {
                                      if ( error )
                                      {
                                          LOG_ERROR("HTTP log report failed: {}, data_size={}",
                                                    [[error localizedDescription] UTF8String], [data length]);
                                          pthread_mutex_lock(&failedQueueMutex);
                                          // 检查失败队列大小限制
                                          if ( failedQueue.size() >= kMaxFailedQueueSize )
                                          {
                                              // 移除最老的失败事件
                                              NSData *oldData = failedQueue.front();
                                              failedQueue.erase(failedQueue.begin());
                                              // NSData会自动释放，不需要手动free
                                          }
                                          failedQueue.push_back([data copy]);
                                          pthread_mutex_unlock(&failedQueueMutex);
                                      }
                                      else
                                      {
                                          // 打印上报数据的详细信息
//                                          pThreatDetection->printReportDetails(data, event, "LOG");
//                                          LOG_INFO("Log upload successful: type={}, details={}, data_size={} bytes", eventTypeDesc, eventDetails, [data length]);
                                          mainSuccess = true;
                                      }
                                      dispatch_semaphore_signal(mainSema);
                                  }];
            }
            else
            {
                // RULE_ACTION_BLOCK/RULE_ACTION_REPORT - 上报告警
                [YSHttpClient reportEDREvent:data
                                   remoteURL:@""
                                    complate:^(NSError *error) {
                                        if ( error )
                                        {
                                            LOG_ERROR("HTTP report failed: {}, data_size={}",
                                                      [[error localizedDescription] UTF8String], [data length]);
                                            pthread_mutex_lock(&failedQueueMutex);
                                            // 检查失败队列大小限制
                                            if ( failedQueue.size() >= kMaxFailedQueueSize )
                                            {
                                                // 移除最老的失败事件
                                                NSData *oldData = failedQueue.front();
                                                failedQueue.erase(failedQueue.begin());
                                                // NSData会自动释放，不需要手动free
                                            }
                                            failedQueue.push_back([data copy]);
                                            pthread_mutex_unlock(&failedQueueMutex);
                                        }
                                        else
                                        {
                                            // 打印上报数据的详细信息
                                            pThreatDetection->printReportDetails(data, event, "ALERT");

                                            LOG_INFO("Event upload successful: type={}, details={}, data_size={} bytes",
                                                     eventTypeDesc, eventDetails, [data length]);
                                            LOG_INFO("Alert upload successful: type={}, details={}, data_size={} bytes",
                                                     eventTypeDesc, eventDetails, [data length]);
                                            mainSuccess = true;
                                        }
                                        dispatch_semaphore_signal(mainSema);
                                    }];
            }
            dispatch_semaphore_wait(mainSema, DISPATCH_TIME_FOREVER);

            // 重试所有未成功的告警
            pthread_mutex_lock(&failedQueueMutex);
            for ( auto it = failedQueue.begin(); it != failedQueue.end(); )
            {
                __block bool         success = false;
                dispatch_semaphore_t sema    = dispatch_semaphore_create(0);
                [YSHttpClient reportEDREvent:*it
                                   remoteURL:@""
                                    complate:^(NSError *err) {
                                        if ( !err )
                                        {
                                            success = true;
                                        }
                                        dispatch_semaphore_signal(sema);
                                    }];
                dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
                if ( success )
                {
                    // 上报成功才移除
                    it = failedQueue.erase(it);
                }
                else
                {
                    ++it;
                }
            }
            pthread_mutex_unlock(&failedQueueMutex);

            pthread_mutex_lock(&failedQueueMutex);
            size_t failedCount = failedQueue.size();
            pthread_mutex_unlock(&failedQueueMutex);

            pthread_mutex_lock(&m_queMutex);
            size_t queueSize = m_queEvents.size();
            pthread_mutex_unlock(&m_queMutex);

            LOG_DEBUG("Queue status - remaining: {}, failed cache: {}", queueSize, failedCount);
        }
        catch ( const std::exception &e )
        {
            LOG_ERROR("Critical exception in report thread: {}", e.what());
        }

        usleep(100000);  // 100 毫秒
    }
    return NULL;
}

void CThreatDetect::printReportDetails(NSData *data, const CThreatEvent *event, const std::string &reportTypeStr)
{
    if ( event->reportType == REPORT_TYPE_LOG )
    {
        // 日志上报 - EdrEventMessage格式，按照告警打印格式显示
        NSLog(@"===== EdrEventMessage %s (fields by tag) =====", reportTypeStr.c_str());

        // 1 eventtype
        NSLog(@"1 eventtype: %d", (int)event->eventId);

        // 2 times
        int32_t eventTime = 0;
        switch ( event->eventId )
        {
            case EDR_EVENT_PROCESSSTAR:
                eventTime = event->eventInfo.pProcess ? event->eventInfo.pProcess->UtcTime : 0;
                break;
            case EDR_EVENT_CREATEFILE:
                eventTime = event->eventInfo.pCreate ? event->eventInfo.pCreate->UtcTime : 0;
                break;
            case EDR_EVENT_FILERENAME:
                eventTime = event->eventInfo.pRename ? event->eventInfo.pRename->UtcTime : 0;
                break;
            case EDR_EVENT_NETWORK_CONNECTION:
                if ( const CNetConThreatEvent *netEvent = dynamic_cast<const CNetConThreatEvent *>(event) )
                {
                    eventTime = netEvent->netConInfo.UtcTime;
                }
                break;
            default:
                break;
        }
        NSLog(@"2 times: %d", eventTime);

        // 3 eventinfo -> 根据不同事件类型显示详细信息
        switch ( event->eventId )
        {
            case EDR_EVENT_PROCESSSTAR:
                if ( event->eventInfo.pProcess )
                {
                    NSLog(@"3 eventinfo.UtcTime: %d", event->eventInfo.pProcess->UtcTime);
                    NSLog(@"3 eventinfo.ProcessId: %d", event->eventInfo.pProcess->ProcessId);
                    NSLog(@"3 eventinfo.ImagePath: %s", event->eventInfo.pProcess->ImagePath.c_str());
                    NSLog(@"3 eventinfo.Hash: %s", event->eventInfo.pProcess->Hash.c_str());
                    NSLog(@"3 eventinfo.User: %s", event->eventInfo.pProcess->User.c_str());
                    NSLog(@"3 eventinfo.SID: %s", event->eventInfo.pProcess->SID.c_str());
                    NSLog(@"3 eventinfo.CommandLine: %s", event->eventInfo.pProcess->CommandLine.c_str());
                    NSLog(@"3 eventinfo.CurrentDirectory: %s", event->eventInfo.pProcess->CurrentDirectory.c_str());
                    NSLog(@"3 eventinfo.ProcessGuid: %s", event->eventInfo.pProcess->ProcessGuid.c_str());
                    NSLog(@"3 eventinfo.ParentProcessGuid: %s", event->eventInfo.pProcess->ParentProcessGuid.c_str());
                    NSLog(@"3 eventinfo.ProcFileId: %s", event->eventInfo.pProcess->ProcFileId.c_str());
                    NSLog(@"3 eventinfo.SignerName: %s", event->eventInfo.pProcess->SignerName.c_str());
                    NSLog(@"3 eventinfo.CreateTime: %d", event->eventInfo.pProcess->CreateTime);
                    NSLog(@"3 eventinfo.FileSize: %d", event->eventInfo.pProcess->FileSize);
                    NSLog(@"3 eventinfo.SignStatus: %d", event->eventInfo.pProcess->SignStatus);
                }
                break;
            case EDR_EVENT_CREATEFILE:
                if ( event->eventInfo.pCreate )
                {
                    NSLog(@"3 eventinfo.UtcTime: %d", event->eventInfo.pCreate->UtcTime);
                    NSLog(@"3 eventinfo.ProcessGuid: %s", event->eventInfo.pCreate->ProcessGuid.c_str());
                    NSLog(@"3 eventinfo.FileName: %s", event->eventInfo.pCreate->FileName.c_str());
                    NSLog(@"3 eventinfo.CreateTime: %d", event->eventInfo.pCreate->CreateTime);
                    NSLog(@"3 eventinfo.CreateOptions: %d", event->eventInfo.pCreate->CreateOptions);
                    NSLog(@"3 eventinfo.DesiredAccess: %d", event->eventInfo.pCreate->DesiredAccess);
                    NSLog(@"3 eventinfo.FileID: %s", event->eventInfo.pCreate->FileID.c_str());
                    NSLog(@"3 eventinfo.FileSize: %d", event->eventInfo.pCreate->FileSize);
                    NSLog(@"3 eventinfo.SignStatus: %d", event->eventInfo.pCreate->SignStatus);
                    NSLog(@"3 eventinfo.FileHash: %s", event->eventInfo.pCreate->FileHash.c_str());
                    NSLog(@"3 eventinfo.Signer: %s", event->eventInfo.pCreate->Signer.c_str());
                    NSLog(@"3 eventinfo.SignerName: %s", event->eventInfo.pCreate->SignerName.c_str());
                    NSLog(@"3 eventinfo.CompanyName: %s", event->eventInfo.pCreate->CompanyName.c_str());
                    NSLog(@"3 eventinfo.OriginalFile: %s", event->eventInfo.pCreate->OriginalFile.c_str());
                    NSLog(@"3 eventinfo.ProductName: %s", event->eventInfo.pCreate->ProductName.c_str());
                }
                break;
            case EDR_EVENT_FILERENAME:
                if ( event->eventInfo.pRename )
                {
                    NSLog(@"3 eventinfo.UtcTime: %d", event->eventInfo.pRename->UtcTime);
                    NSLog(@"3 eventinfo.ProcessGuid: %s", event->eventInfo.pRename->ProcessGuid.c_str());
                    NSLog(@"3 eventinfo.OldPath: %s", event->eventInfo.pRename->OldPath.c_str());
                    NSLog(@"3 eventinfo.NewPath: %s", event->eventInfo.pRename->NewPath.c_str());
                    NSLog(@"3 eventinfo.FileSigner: %s", event->eventInfo.pRename->FileSigner.c_str());
                    NSLog(@"3 eventinfo.FileID: %s", event->eventInfo.pRename->FileID.c_str());
                }
                break;
            case EDR_EVENT_NETWORK_CONNECTION:
                if ( const CNetConThreatEvent *netEvent = dynamic_cast<const CNetConThreatEvent *>(event) )
                {
                    NSLog(@"3 eventinfo.UtcTime: %d", netEvent->netConInfo.UtcTime);
                    NSLog(@"3 eventinfo.ProcessGuid: %s", netEvent->netConInfo.ProcessGuid.c_str());
                    NSLog(@"3 eventinfo.Protocol: %d", netEvent->netConInfo.Protocol);
                    NSLog(@"3 eventinfo.SourceIp: %u", netEvent->netConInfo.SourceIp);
                    NSLog(@"3 eventinfo.SourcePort: %u", netEvent->netConInfo.SourcePort);
                    NSLog(@"3 eventinfo.DestinationIp: %u", netEvent->netConInfo.DestinationIp);
                    NSLog(@"3 eventinfo.DestinationPort: %u", netEvent->netConInfo.DestinationPort);
                }
                break;
            default:
                NSLog(@"3 eventinfo: <Unknown eventtype=%d>", (int)event->eventId);
                break;
        }

        NSLog(@"===== EdrEventMessage %s (end) =====", reportTypeStr.c_str());
    }
    else
    {
        // 告警上报 - 使用EdrRiskEvent解析
        EdrRiskEvent parsed;
        if ( parsed.ParseFromArray([data bytes], static_cast<int>([data length])) )
        {
            // 定义通用的字段打印结构
            struct FieldInfo
            {
                const char *name;
                const char *format;
            };

            // ProcessStart字段定义
            static const FieldInfo processStartFields[] = {
                {           "UtcTime", "%d" },
                {         "ProcessId", "%d" },
                {         "ImagePath", "%s" },
                {              "Hash", "%s" },
                {              "User", "%s" },
                {               "SID", "%s" },
                {       "CommandLine", "%s" },
                {  "CurrentDirectory", "%s" },
                {            "Signer", "%s" },
                {       "ProcessGuid", "%s" },
                { "ParentProcessGuid", "%s" },
                {        "ProcFileId", "%s" },
                {        "SignerName", "%s" },
                {        "CreateTime", "%d" },
                {          "FileSize", "%d" },
                {        "SignStatus", "%d" },
                {         "StartType", "%d" }
            };

            // CreateFileEvent字段定义
            static const FieldInfo createFileFields[] = {
                {       "UtcTime", "%d" },
                {   "ProcessGuid", "%s" },
                {      "FileName", "%s" },
                {    "CreateTime", "%d" },
                { "CreateOptions", "%d" },
                { "DesiredAccess", "%d" },
                {        "FileID", "%s" },
                {      "FileSize", "%d" },
                {    "SignStatus", "%d" },
                {      "FileHash", "%s" },
                {        "Signer", "%s" },
                {    "SignerName", "%s" },
                {   "CompanyName", "%s" },
                {  "OriginalFile", "%s" },
                {   "ProductName", "%s" }
            };

            // ReNameFileEvent字段定义
            static const FieldInfo renameFileFields[] = {
                {     "UtcTime", "%d" },
                { "ProcessGuid", "%s" },
                {     "OldPath", "%s" },
                {     "NewPath", "%s" },
                {  "FileSigner", "%s" },
                {      "FileID", "%s" }
            };

            // NetConEvent字段定义
            static const FieldInfo netConFields[] = {
                {         "UtcTime", "%d" },
                {     "ProcessGuid", "%s" },
                {        "Protocol", "%d" },
                {        "SourceIp", "%u" },
                {      "SourcePort", "%u" },
                {   "DestinationIp", "%u" },
                { "DestinationPort", "%u" }
            };

            auto printPS = ^(NSString *prefix, const ProcessStart &ps) {
                const void *values[] = { (void *)ps.utctime(),
                                         (void *)ps.processid(),
                                         ps.imagepath().c_str(),
                                         ps.hash().c_str(),
                                         ps.user().c_str(),
                                         ps.sid().c_str(),
                                         ps.commandline().c_str(),
                                         ps.currentdirectory().c_str(),
                                         ps.signer().c_str(),
                                         ps.processguid().c_str(),
                                         ps.parentprocessguid().c_str(),
                                         ps.procfileid().c_str(),
                                         ps.signername().c_str(),
                                         (void *)ps.createtime(),
                                         (void *)ps.filesize(),
                                         (void *)ps.signstatus(),
                                         (void *)ps.starttype() };
                for ( size_t i = 0; i < sizeof(processStartFields) / sizeof(processStartFields[0]); i++ )
                {
                    if ( strcmp(processStartFields[i].format, "%d") == 0 )
                    {
                        NSLog(@"%@.%s: %d", prefix, processStartFields[i].name, (int)(intptr_t)values[i]);
                    }
                    else if ( strcmp(processStartFields[i].format, "%s") == 0 )
                    {
                        NSLog(@"%@.%s: %s", prefix, processStartFields[i].name, (const char *)values[i]);
                    }
                }
            };

            auto printCFE = ^(NSString *prefix, const CreateFileEvent &cfe) {
                const void *values[] = {
                    (void *)cfe.utctime(),     cfe.processguid().c_str(),   cfe.filename().c_str(),
                    (void *)cfe.createtime(),  (void *)cfe.createoptions(), (void *)cfe.desiredaccess(),
                    cfe.fileid().c_str(),      (void *)cfe.filesize(),      (void *)cfe.signstatus(),
                    cfe.filehash().c_str(),    cfe.signer().c_str(),        cfe.signername().c_str(),
                    cfe.companyname().c_str(), cfe.originalfile().c_str(),  cfe.productname().c_str()
                };
                for ( size_t i = 0; i < sizeof(createFileFields) / sizeof(createFileFields[0]); i++ )
                {
                    if ( strcmp(createFileFields[i].format, "%d") == 0 )
                    {
                        NSLog(@"%@.%s: %d", prefix, createFileFields[i].name, (int)(intptr_t)values[i]);
                    }
                    else if ( strcmp(createFileFields[i].format, "%s") == 0 )
                    {
                        NSLog(@"%@.%s: %s", prefix, createFileFields[i].name, (const char *)values[i]);
                    }
                }
            };

            auto printRFE = ^(NSString *prefix, const ReNameFileEvent &rfe) {
                const void *values[] = { (void *)rfe.utctime(), rfe.processguid().c_str(), rfe.oldpath().c_str(),
                                         rfe.newpath().c_str(), rfe.filesigner().c_str(),  rfe.fileid().c_str() };
                for ( size_t i = 0; i < sizeof(renameFileFields) / sizeof(renameFileFields[0]); i++ )
                {
                    if ( strcmp(renameFileFields[i].format, "%d") == 0 )
                    {
                        NSLog(@"%@.%s: %d", prefix, renameFileFields[i].name, (int)(intptr_t)values[i]);
                    }
                    else if ( strcmp(renameFileFields[i].format, "%s") == 0 )
                    {
                        NSLog(@"%@.%s: %s", prefix, renameFileFields[i].name, (const char *)values[i]);
                    }
                }
            };

            auto printNCE = ^(NSString *prefix, const NetConEvent &nce) {
                const void *values[] = { (void *)nce.utctime(),        nce.processguid().c_str(),
                                         (void *)nce.protocol(),       (void *)nce.sourceip(),
                                         (void *)nce.sourceport(),     (void *)nce.destinationip(),
                                         (void *)nce.destinationport() };
                for ( size_t i = 0; i < sizeof(netConFields) / sizeof(netConFields[0]); i++ )
                {
                    if ( strcmp(netConFields[i].format, "%d") == 0 )
                    {
                        NSLog(@"%@.%s: %d", prefix, netConFields[i].name, (int)(intptr_t)values[i]);
                    }
                    else if ( strcmp(netConFields[i].format, "%u") == 0 )
                    {
                        NSLog(@"%@.%s: %u", prefix, netConFields[i].name, (unsigned int)(intptr_t)values[i]);
                    }
                    else if ( strcmp(netConFields[i].format, "%s") == 0 )
                    {
                        NSLog(@"%@.%s: %s", prefix, netConFields[i].name, (const char *)values[i]);
                    }
                }
            };

            NSLog(@"===== EdrRiskEvent %s (fields by tag) =====", reportTypeStr.c_str());

            // 使用数组定义主要字段的处理逻辑
            struct
            {
                int                   tag;
                const char           *name;
                std::function<void()> handler;
            } mainFields[] = {
                { 1,       "des",
                 [&]()
                 {
                 NSLog(@"1 des: %s", parsed.des().c_str());
                 } },
                { 2,  "procinfo",
                 [&]()
                 {
                 ProcessStart ps2;
                 if ( ps2.ParseFromString(parsed.procinfo()) )
                 {
                 printPS(@"2 procinfo", ps2);
                 }
                 else
                 {
                 NSLog(@"2 procinfo: <empty/parse-failed>");
                 }
                 } },
                { 3,   "eventid",
                 [&]()
                 {
                 NSLog(@"3 eventid: %d", parsed.eventid());
                 } },
                { 4, "eventinfo",
                 [&]()
                  {
                      int eventId = parsed.eventid();
                      struct
                      {
                          int                   id;
                          const char           *name;
                          std::function<void()> parser;
                      } eventParsers[] = {
                          { 1, "ProcessStart",
                 [&]()
                            {
                                ProcessStart ps4;
                                if ( ps4.ParseFromString(parsed.eventinfo()) )
                                {
                                    printPS(@"4 eventinfo", ps4);
                                }
                                else
                                {
                                    NSLog(@"4 eventinfo: <ProcessStart parse-failed>");
                                }
                            } },
                          { 11, "CreateFileEvent",
                 [&]()
                            {
                                CreateFileEvent cfe4;
                                if ( cfe4.ParseFromString(parsed.eventinfo()) )
                                {
                                    printCFE(@"4 eventinfo", cfe4);
                                }
                                else
                                {
                                    NSLog(@"4 eventinfo: <CreateFileEvent parse-failed>");
                                }
                            } },
                          { 35, "ReNameFileEvent",
                 [&]()
                            {
                                ReNameFileEvent rfe4;
                                if ( rfe4.ParseFromString(parsed.eventinfo()) )
                                {
                                    printRFE(@"4 eventinfo", rfe4);
                                }
                                else
                                {
                                    NSLog(@"4 eventinfo: <ReNameFileEvent parse-failed>");
                                }
                            } },
                          { 3, "NetConEvent",
                 [&]()
                 {
                 NetConEvent nce4;
                 if ( nce4.ParseFromString(parsed.eventinfo()) )
                 {
                 printNCE(@"4 eventinfo", nce4);
                 }
                 else
                 {
                 NSLog(@"4 eventinfo: <NetConEvent parse-failed>");
                 }
                 } }
                 };

                 bool found = false;
                 for ( const auto &parser: eventParsers )
                 {
                 if ( parser.id == eventId )
                 {
                 parser.parser();
                 found = true;
                 break;
                 }
                 }
                 if ( !found )
                 {
                 NSLog(@"4 eventinfo: <Unknown eventid=%d>", eventId);
                 }
                 }                  },
                { 5,    "action",
                 [&]()
                 {
                 NSLog(@"5 action: %d", parsed.action());
                 }                 },
                { 6, "procinfos",
                 [&]()
                 {
                 int count = parsed.procinfos_size();
                 NSLog(@"6 procinfos count: %d", count);
                 for ( int i = 0; i < count; ++i )
                 {
                 ProcessStart psi;
                 if ( psi.ParseFromString(parsed.procinfos(i)) )
                 {
                 NSString *prefix = [NSString stringWithFormat:@"6[%d]", i];
                 printPS(prefix, psi);
                 }
                 else
                 {
                 NSLog(@"6[%d]: <parse-failed>", i);
                 }
                 }
                 }                },
                { 7,   "agentip",
                 [&]()
                 {
                 NSLog(@"7 agentip: %s", parsed.agentip().c_str());
                 } },
                { 8,  "hostname",
                 [&]()
                 {
                 NSLog(@"8 hostname: %s", parsed.hostname().c_str());
                 } }
            };

            // 循环处理所有字段
            for ( const auto &field: mainFields )
            {
                field.handler();
            }

            NSLog(@"===== EdrRiskEvent %s (end) =====", reportTypeStr.c_str());
        }
        else
        {
            NSLog(@"ParseFromArray 失败，无法打印明文");
        }
    }
}

void CThreatDetect::fetchRulesConfig()
{
    @autoreleasepool
    {
        LOG_INFO("Starting to fetch rules configuration from /api/agent/v1/get_rules");

        // 创建HTTP请求
        YSHTTPRequest *request = [[YSHTTPRequest alloc] init];
        request.method         = YSHTTPMethodGET;
        request.apiName        = @"/api/agent/v1/get_rules";

        // 获取YSHTTPGateway实例
        YSHTTPGateway *gateway = [YSHTTPGateway instance];

        // 发起请求
        [gateway startRequest:request
                successBlock:^(YSHTTPResponse *response) {
                    if ( response && response.succeed && response.data )
                    {
                        LOG_INFO("Successfully received rules configuration from server");

                        // 获取配置文件目录路径
                        std::string configDir = SystemUtils::GetConfigFilePath("filterjson.cfg");
                        size_t      lastSlash = configDir.find_last_of('/');
                        if ( lastSlash != std::string::npos )
                        {
                            configDir = configDir.substr(0, lastSlash);
                        }

                        // 构建新规则文件路径
                        std::string rulesFilePath = configDir + "/rules.cfg";
                        LOG_INFO("Saving rules to path: {}", rulesFilePath);

                        // 将响应数据转换为JSON字符串
                        NSError *error    = nil;
                        NSData  *jsonData = [NSJSONSerialization dataWithJSONObject:response.data
                                                                           options:NSJSONWritingPrettyPrinted
                                                                             error:&error];
                        if ( jsonData && !error )
                        {
                            // 保存到文件
                            BOOL success = [jsonData writeToFile:@(rulesFilePath.c_str()) atomically:YES];
                            if ( success )
                            {
                                LOG_INFO("Rules configuration saved successfully to {}", rulesFilePath);
                            }
                            else
                            {
                                LOG_ERROR("Failed to save rules configuration to {}", rulesFilePath);
                            }
                        }
                        else
                        {
                            LOG_ERROR("Failed to serialize rules data to JSON: {}",
                                      error ? error.localizedDescription.UTF8String : "unknown error");
                        }
                    }
                    else
                    {
                        LOG_WARN("Received empty or invalid response from rules API");
                    }
                }
                failureBlock:^(YSHTTPResponse *response) {
                    if ( response && response.error )
                    {
                        NSError *error = (NSError *)response.error;
                        LOG_ERROR("Failed to fetch rules configuration: {} (code: {})",
                                  error.localizedDescription.UTF8String, (int)error.code);
                    }
                    else
                    {
                        LOG_ERROR("Failed to fetch rules configuration: unknown error");
                    }
                }];
    }
}

void *CThreatDetect::rulesUpdateThreadFunc(void *arg)
{
    CThreatDetect *pThis = static_cast<CThreatDetect *>(arg);
    if ( !pThis )
    {
        LOG_ERROR("Rules update thread: Invalid CThreatDetect instance");
        return nullptr;
    }

    LOG_INFO("Rules update thread started, will fetch rules every 30 minutes");

    // 立即执行一次规则获取
    pThis->fetchRulesConfig();

    while ( true )
    {
        // 等待30分钟 (30 * 60 seconds)
        sleep(30 * 60);

        // 检查实例是否仍然初始化
        if ( !pThis->m_bInitialized )
        {
            LOG_INFO("CThreatDetect instance uninitialized, rules update thread exiting");
            break;
        }

        LOG_DEBUG("Rules update thread: Starting periodic rules fetch");
        pThis->fetchRulesConfig();
    }

    LOG_INFO("Rules update thread exited");
    return nullptr;
}
