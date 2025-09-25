#ifndef CFILETHREATDETECT_T
#define CFILETHREATDETECT_T

#include "IESFEventObserver.h"
#include "../common/macro.h"
#include "../common/SystemUtils.h"
#include <unordered_map>
#include <mutex>
#include <string>

class CFileThreatDetect: public IESFEventObserver
{
public:
    static CFileThreatDetect *shared();

    /// 处理Auth事件（需要返回决策）
    /// @param eventType 事件类型
    /// @param message ESF消息
    /// @return true允许，false拒绝
    bool OnAuthEventReceived(es_event_type_t eventType, const es_message_t *message) override;

    /// 处理Notify事件（仅记录，不拦截）
    /// @param eventType 事件类型
    /// @param message ESF消息
    void OnNotifyEventReceived(es_event_type_t eventType, const es_message_t *message) override;

    /// 获取本模块关心的事件类型（自注册）
    std::vector<es_event_type_t> GetSubscribedEventTypes() const override;

private:
    CFileThreatDetect();
    ~CFileThreatDetect();
    bool handleAuthCreateEvent(const es_message_t *message);
    bool handleAuthRenameEvent(const es_message_t *message);
    void handleNotifyCloseEvent(const es_message_t *message);

    struct FileCreateCacheEntry
    {
        std::string path;         // 目标文件完整路径
        int32_t     createUtc;    // 创建事件时间
        pid_t       pid;          // 创建进程PID
    };

    std::unordered_map<std::string, FileCreateCacheEntry> m_createCache;  // key: 路径
    std::mutex                                            m_cacheMutex;
};

#endif
