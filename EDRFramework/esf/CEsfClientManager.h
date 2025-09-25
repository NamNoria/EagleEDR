#ifndef CESFCLIENTMANAGER_H
#define CESFCLIENTMANAGER_H

#include <EndpointSecurity/EndpointSecurity.h>

class CEsfDispatcher;

class CEsfClientManager
{
public:
    static CEsfClientManager *shared();
    // 初始化ES客户端管理器
    bool Initialize();

    void SetDefaultSubscription();

private:
    // 禁用拷贝构造和赋值
    CEsfClientManager();
    ~CEsfClientManager();
    CEsfClientManager(const CEsfClientManager &)             = delete;
    CEsfClientManager &operator= (const CEsfClientManager &) = delete;

    // 初始化客户端
    bool initializeNotifyClient();
    bool initializeAuthClient();

    // 反初始客户端
    bool unInitializeNotifyClient();
    bool unInitializeAuthClient();

    // 设置订阅
    bool setNotifySubscription();
    bool setAuthSubscription();

    // 设置回调函数
    void setNotifyCallback(es_handler_block_t callback);
    void setAuthCallback(es_handler_block_t callback);

private:
    CEsfDispatcher *m_pEsfDispatcher;     // ESF分发器

    es_client_t *m_pNotifyClient;         // Notify客户端
    es_client_t *m_pAuthClient;           // Auth客户端

    es_handler_block_t m_notifyCallback;  // Notify回调函数
    es_handler_block_t m_authCallback;    // Auth回调函数
};

#endif
