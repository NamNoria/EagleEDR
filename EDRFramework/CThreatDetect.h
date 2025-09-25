#ifndef CTHREATDETECT_H
#define CTHREATDETECT_H

#include <queue>
#import <Foundation/Foundation.h>

class CThreatEvent;  // 前向声明

class CThreatDetect
{
public:
    /**
    获取威胁检测单例
    返回威胁检测单例
     */
    static CThreatDetect *Shared();

    /**
    初始化威胁检测
    返回是否成功初始化
     */
    bool Initialize();

    /**
    反初始化威胁检测
    返回是否成功反初始化
     */
    bool UnInitialize();

    /**
    启用威胁检测
    返回是否成功启用
     */
    bool Enable();

    /**
    禁用威胁检测
    返回是否成功禁用
     */
    bool Disable();

    /**
    获取威胁检测状态
    返回是否启用
     */
    bool IsEnabled();

    /**
    启用指定子功能
    @param features 子功能开关位掩码
    注意：使用EDR_FEATURE_TREE_ONLY时，会监听进程事件维护进程树但不进行威胁检测
    返回是否成功启用
     */
    bool EnableFeatures(uint32_t features);

    /**
    禁用指定子功能
    @param features 子功能开关位掩码
    返回是否成功禁用
     */
    bool DisableFeatures(uint32_t features);

    /**
    获取当前启用的子功能
    返回子功能开关位掩码
     */
    uint32_t GetEnabledFeatures();

    /**
    打印执行PID为根节点的进程树
     */
    void PrintTree(pid_t pid);

    void Report(CThreatEvent *event);

private:
    CThreatDetect();
    ~CThreatDetect();
    // 禁用拷贝构造和赋值
    CThreatDetect(const CThreatDetect &)             = delete;
    CThreatDetect &operator= (const CThreatDetect &) = delete;

    static void *reportThreadFunc(void *arg);
    static void *rulesUpdateThreadFunc(void *arg);

    // 打印上报数据的详细信息
    void printReportDetails(NSData *data, const CThreatEvent *event, const std::string& reportTypeStr);

    // 获取规则配置文件
    void fetchRulesConfig();

private:
    bool                   m_bEnabled;
    uint32_t              m_enabledFeatures;    // 当前启用的子功能位掩码
    static pthread_mutex_t m_switchMutex;
    bool                   m_bInitialized;

    class Impl;
    std::unique_ptr<Impl> m_pImpl;

    pthread_t                                        m_reportThread;
    pthread_t                                        m_rulesUpdateThread;
    static pthread_mutex_t                           m_queMutex;
    static pthread_cond_t                            m_queCond;
    static std::queue<CThreatEvent*> m_queEvents;  // 待上报事件队列
};
#endif
