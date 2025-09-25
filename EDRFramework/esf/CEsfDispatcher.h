#ifndef CESFDISPATCHER_H
#define CESFDISPATCHER_H

#include <EndpointSecurity/EndpointSecurity.h>
#include <atomic>
#include <mutex>
#include <map>
#include <queue>
#include <vector>
#include <thread>

struct ESFEvent
{
    es_client_t        *client;  // 只存指针，不拷贝
    const es_message_t *message;
};

class IESFEventObserver;

class CEsfDispatcher
{
public:
    static CEsfDispatcher *shared();

    bool Initialize();

    bool UnInitialize();

    bool IsInitialized();

    

    static void PushNotifyEvent(ESFEvent *message);
    static void PushAuthEvent(ESFEvent *message);

    void SubscribeEvent(es_event_type_t eventType, IESFEventObserver *observer);

    // 性能统计方法
    void LogPerformanceStats();

private:
    /// Notify事件回调函数
    static void handleNotifyEvent(es_client_t *client, const es_message_t *message);

    /// Auth事件回调函数
    static void handleAuthEvent(es_client_t *client, const es_message_t *message);
    /// Notify事件分发处理
    void dispatchNotifyEvent(es_event_type_t eventType, const es_message_t *message);

    /// Auth事件分发处理
    /// @return true允许事件，false拒绝事件
    bool dispatchAuthEvent(es_event_type_t eventType, const es_message_t *message);

    static void *dispatchNotifyThreadFunc(void *arg);
    static void *authWorkerThreadFunc(void *arg);

public:
    std::atomic<bool>                                           m_bInitialized;        // 初始化标志
    std::mutex                                                  m_subscriptionMutex;   // 订阅互斥锁
    std::map<es_event_type_t, std::vector<IESFEventObserver *>> m_eventSubscriptions;  // 事件订阅映射

    // Notify单线程
    pthread_t m_dispatchNotifyThread;

    // Auth线程池
    static const size_t kAuthThreadPoolSize = 4;  // 可配置的Auth线程数
    std::vector<pthread_t> m_authThreadPool;

    // 退出标志
    static std::atomic<bool> m_shouldExit;

    static pthread_mutex_t        m_queNotifyMutex;
    static pthread_mutex_t        m_queAuthMutex;
    static pthread_cond_t         m_queNotifyCond;
    static pthread_cond_t         m_queAuthCond;
    static std::queue<ESFEvent *> m_queNotifyEvent;  // 事件队列TODO：无锁队列
    static std::queue<ESFEvent *> m_queAuthEvent;    // 事件队列TODO：无锁队列

    // 队列大小限制 - 增加容量以应对编译时的高频事件
    static const size_t kMaxNotifyQueueSize = 8000;  // 从2000增加到8000
    static const size_t kMaxAuthQueueSize = 4000;    // 从2000增加到4000

    // 性能统计 - 用于监控线程池效果
    static std::atomic<uint64_t> m_authEventsProcessed;
    static std::atomic<uint64_t> m_notifyEventsProcessed;
    static std::atomic<uint64_t> m_authQueueOverflows;
    static std::atomic<uint64_t> m_notifyQueueOverflows;
};

#endif
