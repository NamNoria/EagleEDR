#include <iostream>

#include "CNetThreatDetect.h"
#include "NetworkAudit.h"
#include "../CThreatDetect.h"
#include "../common/Logger.h"

CNetThreatDetect::CNetThreatDetect(): m_networkAudit(nil)
{
}

CNetThreatDetect::~CNetThreatDetect()
{
    if ( m_networkAudit )
    {
        m_networkAudit = nil;  // ARC会自动释放
    }
}

CNetThreatDetect *CNetThreatDetect::shared()
{
    static CNetThreatDetect instance;
    return &instance;
}

bool CNetThreatDetect::Initialize()
{
    // 使用云枢 NetworkAudit 采集网络事件
    LOG_INFO("Initializing network threat detection module...");

    if ( !m_networkAudit )
    {
        m_networkAudit = [[NetworkAudit alloc] init];
        if ( m_networkAudit )
        {
            [m_networkAudit start];
            LOG_INFO("NetworkAudit initialized and started successfully");
        }
        else
        {
            LOG_ERROR("NetworkAudit initialization failed");
            return false;
        }
    }
    else
    {
        LOG_INFO("NetworkAudit is already running");
    }

    return true;
}

bool CNetThreatDetect::UnInitialize()
{
    // 依据NetworkAudit实现进行停止（若有stop接口则调用）
    if ( m_networkAudit )
    {
        LOG_INFO("Stopping NetworkAudit...");
        // 调用stop方法正确停止监控
        [m_networkAudit stop];
        m_networkAudit = nil;  // 释放实例
        LOG_INFO("NetworkAudit stopped successfully");
    }
    LOG_INFO("Network threat detection uninitialized");
    return true;
}
