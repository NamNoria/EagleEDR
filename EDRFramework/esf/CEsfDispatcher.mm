#include <utility>
#include <vector>
#include <atomic>
#include <EndpointSecurity/EndpointSecurity.h>

#include "../module/IESFEventObserver.h"
#include "../common/Logger.h"
#include "../common/SystemUtils.h"
#include "CEsfDispatcher.h"

pthread_mutex_t        CEsfDispatcher::m_queNotifyMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t        CEsfDispatcher::m_queAuthMutex   = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t         CEsfDispatcher::m_queNotifyCond  = PTHREAD_COND_INITIALIZER;
pthread_cond_t         CEsfDispatcher::m_queAuthCond    = PTHREAD_COND_INITIALIZER;
std::queue<ESFEvent *> CEsfDispatcher::m_queNotifyEvent;
std::queue<ESFEvent *> CEsfDispatcher::m_queAuthEvent;
std::atomic<bool>      CEsfDispatcher::m_shouldExit{false};

// 静态常量定义
const size_t CEsfDispatcher::kAuthThreadPoolSize;
const size_t CEsfDispatcher::kMaxNotifyQueueSize;
const size_t CEsfDispatcher::kMaxAuthQueueSize;

// 性能统计变量
std::atomic<uint64_t> CEsfDispatcher::m_authEventsProcessed{0};
std::atomic<uint64_t> CEsfDispatcher::m_notifyEventsProcessed{0};
std::atomic<uint64_t> CEsfDispatcher::m_authQueueOverflows{0};
std::atomic<uint64_t> CEsfDispatcher::m_notifyQueueOverflows{0};

CEsfDispatcher *CEsfDispatcher::shared()
{
    static CEsfDispatcher instance;
    return &instance;
}

bool CEsfDispatcher::Initialize()
{
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    // 创建Notify单线程
    int threadNotify = pthread_create(&m_dispatchNotifyThread, &attr, CEsfDispatcher::dispatchNotifyThreadFunc, (void *)this);
    if (threadNotify != 0) {
        LOG_ERROR("Failed to create notify thread, result={}", threadNotify);
        pthread_attr_destroy(&attr);
        return false;
    }
    LOG_INFO("Notify worker thread created successfully");

    // 创建Auth线程池
    m_authThreadPool.reserve(kAuthThreadPoolSize);
    for (size_t i = 0; i < kAuthThreadPoolSize; ++i) {
        pthread_t authThread;
        int result = pthread_create(&authThread, &attr, CEsfDispatcher::authWorkerThreadFunc, (void *)this);
        if (result != 0) {
            LOG_ERROR("Failed to create auth worker thread {}, error={}", i, result);
            pthread_attr_destroy(&attr);
            return false;
        }
        m_authThreadPool.push_back(authThread);
        LOG_INFO("Auth worker thread {} created successfully", i);
    }

    pthread_attr_destroy(&attr);
    m_bInitialized.store(true);
    LOG_INFO("All dispatch threads created successfully - notify: 1, auth pool: {}", kAuthThreadPoolSize);
    return true;
}

bool CEsfDispatcher::UnInitialize()
{
    LOG_INFO("Starting dispatcher uninitialization");

    // 设置退出标志
    m_shouldExit.store(true);

    // 唤醒所有等待的线程
    pthread_cond_broadcast(&m_queNotifyCond);
    for (size_t i = 0; i < kAuthThreadPoolSize; ++i) {
        pthread_cond_broadcast(&m_queAuthCond);
    }

    // 清理Auth队列中的剩余事件
    pthread_mutex_lock(&m_queAuthMutex);
    while (!m_queAuthEvent.empty()) {
        ESFEvent *event = m_queAuthEvent.front();
        m_queAuthEvent.pop();
        if (event && event->message) {
            es_release_message(event->message);
        }
        free(event);
    }
    pthread_mutex_unlock(&m_queAuthMutex);

    // 清理Notify队列中的剩余事件
    pthread_mutex_lock(&m_queNotifyMutex);
    while (!m_queNotifyEvent.empty()) {
        ESFEvent *event = m_queNotifyEvent.front();
        m_queNotifyEvent.pop();
        if (event && event->message) {
            es_release_message(event->message);
        }
        free(event);
    }
    pthread_mutex_unlock(&m_queNotifyMutex);

    m_bInitialized.store(false);
    LOG_INFO("Dispatcher uninitialization completed, auth pool size: {}", m_authThreadPool.size());
    return true;
}

bool CEsfDispatcher::IsInitialized()
{
    return m_bInitialized;
}

void CEsfDispatcher::PushNotifyEvent(ESFEvent *message)
{
    // 智能事件过滤：检查是否为编译器/开发工具进程的CLOSE事件
    if (message && message->message && message->message->event_type == ES_EVENT_TYPE_NOTIFY_CLOSE) {
        pid_t pid = message->message->process->audit_token.val[5];
        if (SystemUtils::IsCompilerOrDevToolProcess(pid)) {
            // 编译器进程的文件关闭事件直接丢弃，避免队列积压
            static std::atomic<uint64_t> filteredCount{0};
            uint64_t currentCount = ++filteredCount;
            if (currentCount % 1000 == 0) {  // 每过滤1000个事件记录一次
                LOG_DEBUG("Filtered {} NOTIFY_CLOSE events from compiler/dev tool processes", currentCount);
            }
            es_release_message(message->message);
            free(message);
            return;
        }
    }

    pthread_mutex_lock(&m_queNotifyMutex);

    // 检查队列大小限制，防止内存无限增长
    if (m_queNotifyEvent.size() >= kMaxNotifyQueueSize) {
        // 丢弃最老的事件
        ESFEvent *oldEvent = m_queNotifyEvent.front();
        m_queNotifyEvent.pop();
        m_notifyQueueOverflows.fetch_add(1);
        LOG_WARN("Notify queue overflow, dropping oldest event, event_type={}, queue_size={}, total_overflows={}",
                static_cast<int>(oldEvent->message->event_type), m_queNotifyEvent.size(), m_notifyQueueOverflows.load());
        es_release_message(oldEvent->message);
        free(oldEvent);
    }

    m_queNotifyEvent.push(message);
    pthread_mutex_unlock(&m_queNotifyMutex);

    pthread_cond_signal(&m_queNotifyCond);
}

void CEsfDispatcher::PushAuthEvent(ESFEvent *message)
{
    pthread_mutex_lock(&m_queAuthMutex);

    // 检查队列大小限制，防止内存无限增长
    if (m_queAuthEvent.size() >= kMaxAuthQueueSize) {
        // 丢弃最老的事件
        ESFEvent *oldEvent = m_queAuthEvent.front();
        m_queAuthEvent.pop();
        m_authQueueOverflows.fetch_add(1);
        LOG_WARN("Auth queue overflow, dropping oldest event, event_type={}, queue_size={}, total_overflows={}",
                static_cast<int>(oldEvent->message->event_type), m_queAuthEvent.size(), m_authQueueOverflows.load());
        es_release_message(oldEvent->message);
        free(oldEvent);
    }

    m_queAuthEvent.push(message);
    pthread_mutex_unlock(&m_queAuthMutex);
    pthread_cond_signal(&m_queAuthCond);
}

void CEsfDispatcher::SubscribeEvent(es_event_type_t eventType, IESFEventObserver *observer)
{
    LOG_DEBUG("Subscribing to event type: {}", static_cast<int>(eventType));
    if ( !observer )
    {
        LOG_ERROR("Subscribe event failed: observer is null, event_type={}", static_cast<int>(eventType));
        return;
    }

    auto &vec = m_eventSubscriptions[eventType];
    if ( std::find(vec.begin(), vec.end(), observer) != vec.end() )
    {
        LOG_WARN("Event {} already subscribed by this observer", static_cast<int>(eventType));
        return;
    }

    vec.push_back(observer);
}

/// Notify事件回调函数
void CEsfDispatcher::handleNotifyEvent(es_client_t *client, const es_message_t *message)
{
    if ( !message )
    {
        LOG_ERROR("Received null message in notify handler");
        return;
    }
    CEsfDispatcher *dispatcher = CEsfDispatcher::shared();
    if ( dispatcher && dispatcher->IsInitialized() )
    {
        // Notify事件：仅记录，不拦截
        dispatcher->dispatchNotifyEvent(message->event_type, message);
    }
}

void CEsfDispatcher::handleAuthEvent(es_client_t *client, const es_message_t *message)
{
    if ( !message )
    {
        LOG_ERROR("Received null message in auth handler");
        return;
    }

    CEsfDispatcher *dispatcher  = CEsfDispatcher::shared();
    bool            shouldAllow = true;
    if ( dispatcher && dispatcher->IsInitialized() )
    {
        shouldAllow = dispatcher->dispatchAuthEvent(message->event_type, message);
    }

    es_auth_result_t    authResult = shouldAllow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY;
    es_respond_result_t result     = ES_RESPOND_RESULT_SUCCESS;

    // 根据不同事件类型使用不同的响应方式
    switch (message->event_type)
    {
            
        case ES_EVENT_TYPE_AUTH_EXEC:
            // exec 事件使用 auth_result
            result = es_respond_auth_result(client, message, authResult, false);
            break;
            
        case ES_EVENT_TYPE_AUTH_CREATE:
            // create 事件使用 auth_result
            result = es_respond_auth_result(client, message, authResult, false);
            break;
            
        case ES_EVENT_TYPE_AUTH_RENAME:
            // rename 事件使用 auth_result
            result = es_respond_auth_result(client, message, authResult, false);
            break;
            
        default:
            LOG_WARN("Unhandled auth event type: {}", static_cast<int>(message->event_type));
            // 其他 auth 事件默认使用 auth_result
            result = es_respond_auth_result(client, message, authResult, false);
            break;
    }

    if ( result != ES_RESPOND_RESULT_SUCCESS )
    {
        LOG_ERROR("es_respond_xxx failed for event {} with result {} authResult {}",
                  static_cast<int>(message->event_type), static_cast<int>(result), (authResult == ES_AUTH_RESULT_ALLOW ? "ALLOW" : "DENY"));
        
        // 如果响应失败，尝试使用默认的允许响应 
        if ( result == ES_RESPOND_RESULT_ERR_INVALID_ARGUMENT )
        {
            LOG_WARN("Invalid argument, using default allow policy");
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
        }
    }
}

/// Notify事件分发处理
void CEsfDispatcher::dispatchNotifyEvent(es_event_type_t eventType, const es_message_t *message)
{
    if ( !message )
    {
        LOG_ERROR("Received null message in notify dispatcher, event_type={}", static_cast<int>(eventType));
        return;
    }
    std::lock_guard<std::mutex> lock(m_subscriptionMutex);
    auto                        it = m_eventSubscriptions.find(eventType);
    if ( it != m_eventSubscriptions.end() )
    {
        const auto &observers = it->second;
        for ( auto *observer: observers )
        {
            if ( observer )
            {
                try
                {
                    // Notify事件：仅记录，不拦截
                    observer->OnNotifyEventReceived(eventType, message);
                }
                catch ( const std::exception &e )
                {
                    LOG_ERROR("Exception in notify event observer: {}, event_type={}, observer={}", e.what(), static_cast<int>(eventType), static_cast<void*>(observer));
                }
                catch ( ... )
                {
                    LOG_ERROR("Unknown exception in notify event observer, event_type={}, observer={}", static_cast<int>(eventType), static_cast<void*>(observer));
                }
            }
        }
    }
}

/// Auth事件分发处理
/// @return true允许事件，false拒绝事件
bool CEsfDispatcher::dispatchAuthEvent(es_event_type_t eventType, const es_message_t *message)
{
    if ( !message )
    {
        LOG_ERROR("Received null message in auth dispatcher, event_type={}, defaulting to allow", static_cast<int>(eventType));
        return true;  // 默认放行
    }

    std::lock_guard<std::mutex> lock(m_subscriptionMutex);
    auto                        it = m_eventSubscriptions.find(eventType);
    if ( it != m_eventSubscriptions.end() )
    {
        const auto &observers = it->second;
        for ( auto *observer: observers )
        {
            if ( observer )
            {
                try
                {
                    // Auth事件：需要决策，如果返回false则拒绝
                    if ( !observer->OnAuthEventReceived(eventType, message) )
                    {
                        LOG_INFO("Auth event denied by observer, event_type={}, observer={}", static_cast<int>(eventType), static_cast<void*>(observer));
                        return false;  // 拒绝
                    }
                }
                catch ( const std::exception &e )
                {
                    LOG_ERROR("Exception in auth event observer: {}, event_type={}, observer={}", e.what(), static_cast<int>(eventType), static_cast<void*>(observer));
                }
                catch ( ... )
                {
                    LOG_ERROR("Unknown exception in auth event observer, event_type={}, observer={}", static_cast<int>(eventType), static_cast<void*>(observer));
                }
            }
        }
    }
    return true;  // 默认放行
}

void *CEsfDispatcher::dispatchNotifyThreadFunc(void *arg)
{
    LOG_INFO("DispatchNotifyThread started");
    CEsfDispatcher *self = static_cast<CEsfDispatcher *>(arg);

    while ( !m_shouldExit )
    {
        pthread_mutex_lock(&self->m_queNotifyMutex);

        // 等待队列非空
        while ( self->m_queNotifyEvent.empty() && !m_shouldExit )
        {
            pthread_cond_wait(&self->m_queNotifyCond, &self->m_queNotifyMutex);
        }

        if ( m_shouldExit )
        {
            pthread_mutex_unlock(&self->m_queNotifyMutex);
            break;
        }

        // 出队
        ESFEvent *event = self->m_queNotifyEvent.front();
        self->m_queNotifyEvent.pop();

        pthread_mutex_unlock(&self->m_queNotifyMutex);

        self->handleNotifyEvent(event->client, event->message);
        m_notifyEventsProcessed.fetch_add(1);

        es_release_message(event->message);
        free(event);
    }

    return nullptr;
}

void *CEsfDispatcher::authWorkerThreadFunc(void *arg)
{
    pthread_t tid = pthread_self();
    LOG_INFO("Auth worker thread started, tid={}", (void*)tid);
    CEsfDispatcher *self = static_cast<CEsfDispatcher *>(arg);

    while (!m_shouldExit) {
        pthread_mutex_lock(&m_queAuthMutex);

        // 等待队列非空，单个事件立即处理
        while (m_queAuthEvent.empty() && !m_shouldExit) {
            pthread_cond_wait(&m_queAuthCond, &m_queAuthMutex);
        }

        if (m_shouldExit) {
            pthread_mutex_unlock(&m_queAuthMutex);
            LOG_DEBUG("Auth worker thread exiting, tid={}", (void*)tid);
            break;
        }

        // 立即取出一个事件处理，无批量等待
        ESFEvent *event = m_queAuthEvent.front();
        m_queAuthEvent.pop();
        size_t queueSize = m_queAuthEvent.size();
        pthread_mutex_unlock(&m_queAuthMutex);

        if (queueSize > kAuthThreadPoolSize * 10) {
            LOG_DEBUG("Auth queue size high: {}, worker_tid={}", queueSize, (void*)tid);
        }

        // 立即处理事件，减少响应延迟
        try {
            handleAuthEvent(event->client, event->message);
            m_authEventsProcessed.fetch_add(1);
        } catch (const std::exception& e) {
            LOG_ERROR("Exception in auth worker thread: {}, tid={}", e.what(), (void*)tid);
        } catch (...) {
            LOG_ERROR("Unknown exception in auth worker thread, tid={}", (void*)tid);
        }

        es_release_message(event->message);
        free(event);
    }

    LOG_INFO("Auth worker thread terminated, tid={}", (void*)tid);
    return nullptr;
}

void CEsfDispatcher::LogPerformanceStats()
{
    pthread_mutex_lock(&m_queNotifyMutex);
    size_t notifyQueueSize = m_queNotifyEvent.size();
    pthread_mutex_unlock(&m_queNotifyMutex);

    pthread_mutex_lock(&m_queAuthMutex);
    size_t authQueueSize = m_queAuthEvent.size();
    pthread_mutex_unlock(&m_queAuthMutex);

    LOG_INFO("ESF Dispatcher Performance Stats:");
    LOG_INFO("  Auth Events: processed={}, queue_size={}, overflows={}, thread_pool_size={}",
             m_authEventsProcessed.load(), authQueueSize, m_authQueueOverflows.load(), kAuthThreadPoolSize);
    LOG_INFO("  Notify Events: processed={}, queue_size={}, overflows={}",
             m_notifyEventsProcessed.load(), notifyQueueSize, m_notifyQueueOverflows.load());
}

