#include "CProcessTree.h"
#include "CThreatEvent.h"  // EAGLE_THREAT_PROCESS_INFO
#include "../common/SystemUtils.h"
#include "../common/Logger.h"
#include <CommonCrypto/CommonCrypto.h>
#include <cstdio>
#include <libproc.h>
#include <sys/sysctl.h>
#include <algorithm>
#include <iostream>
#include <vector>
#include <unordered_set>

// operator== 与 hash 实现在头文件内联，避免重复定义

CProcessTree::CProcessTree()
{
}

CProcessTree *CProcessTree::shared()
{
    static CProcessTree instance;
    return &instance;
}

bool CProcessTree::BuildProcessTree()
{
    std::lock_guard<std::mutex> lock(treeMutex);

    // Step 1: 获取所有进程 PID
    std::vector<pid_t> vecPid;
    if ( !SystemUtils::GetAllProcessID(vecPid) )
    {
        return false;
    }

    // Step 2: 清空之前的数据（确保清理干净）
    // 清理现有进程树数据
    for ( auto &kv: ProcTreeMap )
    {
        delete kv.second;  // 释放 EAGLE_THREAT_PROCESS_INFO 对象
    }
    ProcTreeMap.clear();
    agingList.clear();

    // Step 3: 构建进程树填充map（使用完整复合 Key 存储）
    for ( const auto &pid: vecPid )
    {
        if ( pid <= 0 )
        {
            continue;
        }

        // 仅保留当前需要的核心字段，避免大量系统调用
        EAGLE_THREAT_PROCESS_INFO *procInfo = new EAGLE_THREAT_PROCESS_INFO();
        procInfo->UtcTime                   = (int32_t)SystemUtils::GetCreateTime(pid);
        // 获取进程文件大小
        procInfo->FileSize = (int32_t)SystemUtils::GetFileSize(pid);
        // 获取签名状态

        // 获取SID
        procInfo->SID = std::to_string(SystemUtils::GetSID(pid));
        // 获取USER
        procInfo->User = SystemUtils::GetUser(pid);
        // 获取命令行
        procInfo->CommandLine = SystemUtils::GetCMD(pid);
        // 获取pwd
        procInfo->CurrentDirectory = SystemUtils::GetPWD(pid);
        // 获取签名信息
        procInfo->ProcessId         = (int32_t)pid;
        procInfo->CreateTime        = (int32_t)SystemUtils::GetCreateTime(pid);
        procInfo->ImagePath         = SystemUtils::GetImage(pid);
        procInfo->Hash              = SystemUtils::GetSHA256(pid);
        procInfo->ProcessGuid       = SystemUtils::GetGUID(pid);
        pid_t ppid                  = SystemUtils::GetPPid(pid);
        procInfo->ParentProcessGuid = (ppid > 0) ? SystemUtils::GetGUID(ppid) : std::string("");

        ProcTreeKey key;
        key.PID        = procInfo->ProcessId;
        key.PPID       = (int32_t)ppid;
        key.CreateTime = procInfo->CreateTime;
        // 移除 ImagePath，仅保留核心标识
        key.type = KeyType::FullKey;

        ProcTreeMap[key] = procInfo;
        //        procInfo->PrintProcess();
    }

    return true;
}

void CProcessTree::StartAging()
{
    if ( agingThread.joinable() )
    {
        return;
    }
    agingThread = std::thread(
            [this]()
            {
                while ( true )
                {
                    std::this_thread::sleep_for(std::chrono::seconds(5));
                    this->agingCleanup();
                }
            });
}

void CProcessTree::PrintTree(pid_t iPid, int depth)
{
    try
    {
        // 收集该 PID 对应的所有 GUID（可能 PID 复用产生多个 GUID）
        std::unordered_set<std::string> guidSet;
        {
            std::lock_guard<std::mutex> lock(treeMutex);
            for ( const auto &kv: ProcTreeMap )
            {
                if ( kv.first.PID == iPid && kv.second )
                {
                    guidSet.insert(kv.second->ProcessGuid);
                }
            }
        }

        if ( guidSet.empty() )
        {
            if ( depth == 0 )
            {
                LOG_WARN("Process {} not found in tree", iPid);
            }
            return;
        }

        bool first = true;
        for ( const auto &guid: guidSet )
        {
            // 找到该 PID + GUID 的进程信息，并快照必要字段，避免长时间持锁
            EAGLE_THREAT_PROCESS_INFO procSnap;
            bool                      found = false;
            std::vector<pid_t>        children;
            {
                std::lock_guard<std::mutex> lock(treeMutex);
                for ( const auto &kv: ProcTreeMap )
                {
                    if ( kv.first.PID == iPid && kv.second && kv.second->ProcessGuid == guid )
                    {
                        procSnap = *kv.second;  // 拷贝快照
                        found    = true;
                        break;
                    }
                }
                if ( found )
                {
                    for ( const auto &kv: ProcTreeMap )
                    {
                        if ( kv.first.PPID == procSnap.ProcessId )
                        {
                            children.push_back(kv.first.PID);
                        }
                    }
                }
            }

            if ( !found )
            {
                continue;
            }

            // 缩进显示层级
            // std::cout << std::string(depth * 4, ' '); // 暂时注释，格式化输出用LOG_DEBUG

            // PID 复用标记
            if ( guidSet.size() > 1 )
            {
                LOG_DEBUG("{}|- PID: {} [{}]", std::string(depth * 4, ' '), procSnap.ProcessId, (first ? "老" : "新"));
                first = false;
            }
            else
            {
                LOG_DEBUG("{}|- PID: {}", std::string(depth * 4, ' '), procSnap.ProcessId);
            }

            // 去重并递归打印子进程
            std::sort(children.begin(), children.end());
            children.erase(std::unique(children.begin(), children.end()), children.end());
            for ( size_t idx = 0; idx < children.size(); ++idx )
            {
                pid_t childPid = children[idx];
                PrintTree(childPid, depth + 1);
            }
        }
    }
    catch ( const std::exception &e )
    {
        LOG_ERROR("Exception during tree print: {}, target_pid={}", e.what(), iPid);
    }
}

bool CProcessTree::insertNode(EAGLE_THREAT_PROCESS_INFO *procInfo)
{
    if ( !procInfo )
    {
        return false;
    }

    if ( procInfo->ProcessId <= 0 )
    {
        return false;
    }

    std::lock_guard<std::mutex> lock(treeMutex);

    // 插入当前节点（只插入一次，两个 key 都指向同一个对象）
    ProcTreeKey keyFull;
    keyFull.PID        = procInfo->ProcessId;
    keyFull.PPID       = procInfo->ParentId;
    keyFull.CreateTime = procInfo->CreateTime;
    keyFull.type       = KeyType::FullKey;
    ProcTreeKey keyPidOnly;
    keyPidOnly.PID  = procInfo->ProcessId;
    keyPidOnly.type = KeyType::PIDOnly;

    // 检查两个 key 是否都不存在
    bool needInsert =
            (ProcTreeMap.find(keyFull) == ProcTreeMap.end()) && (ProcTreeMap.find(keyPidOnly) == ProcTreeMap.end());
    if ( needInsert )
    {
        EAGLE_THREAT_PROCESS_INFO *copy = new EAGLE_THREAT_PROCESS_INFO(*procInfo);
        ProcTreeMap[keyFull]            = copy;
        ProcTreeMap[keyPidOnly]         = copy;
    }
    // 如果有一个 key 已存在，另一个不存在，则补充映射（都指向同一个对象）
    else
    {
        EAGLE_THREAT_PROCESS_INFO *ptr    = nullptr;
        auto                       itFull = ProcTreeMap.find(keyFull);
        auto                       itPid  = ProcTreeMap.find(keyPidOnly);
        if ( itFull != ProcTreeMap.end() )
        {
            ptr = itFull->second;
        }
        else if ( itPid != ProcTreeMap.end() )
        {
            ptr = itPid->second;
        }
        if ( itFull == ProcTreeMap.end() && ptr )
        {
            ProcTreeMap[keyFull] = ptr;
        }
        if ( itPid == ProcTreeMap.end() && ptr )
        {
            ProcTreeMap[keyPidOnly] = ptr;
        }
    }

    return true;
}

// 与insert对应，传入procInfo，需要释放procInfo

bool CProcessTree::deleteNode(EAGLE_THREAT_PROCESS_INFO *procInfo)
{
    if ( !procInfo )
    {
        return false;
    }

    ProcTreeKey keyFull;
    keyFull.PID        = procInfo->ProcessId;
    keyFull.PPID       = procInfo->ParentId;
    keyFull.CreateTime = procInfo->CreateTime;
    keyFull.type       = KeyType::FullKey;
    ProcTreeKey keyPidOnly;
    keyPidOnly.PID  = procInfo->ProcessId;
    keyPidOnly.type = KeyType::PIDOnly;

    std::lock_guard<std::mutex> lock(treeMutex);
    auto                        itFull  = ProcTreeMap.find(keyFull);
    auto                        itPid   = ProcTreeMap.find(keyPidOnly);
    bool                        deleted = false;
    EAGLE_THREAT_PROCESS_INFO  *ptr     = nullptr;

    if ( itFull != ProcTreeMap.end() )
    {
        ptr = itFull->second;
        ProcTreeMap.erase(itFull);
        deleted = true;
    }
    if ( itPid != ProcTreeMap.end() )
    {
        // 只在第一次 delete
        if ( !deleted )
        {
            ptr     = itPid->second;
            deleted = true;
        }
        ProcTreeMap.erase(itPid);
    }

    if ( deleted && ptr )
    {
        delete ptr;
        return true;
    }
    else
    {
        LOG_WARN(
                "Process not found in tree, cannot delete - ProcessId: {}, ParentId: {}, CreateTime: {}, ImagePath: {}",
                procInfo->ProcessId, procInfo->ParentId, procInfo->CreateTime, procInfo->ImagePath);
    }
    return false;
}

bool CProcessTree::markExit(const ProcTreeKey &key)
{
    std::lock_guard<std::mutex> lock(treeMutex);
    //    LOG_DEBUG("[CProcessTree] 标记进程退出: PID={}, CreateTime={}", key.PID, key.CreateTime);
    agingList.push_back({ key, std::chrono::steady_clock::now() });
    return true;
}

void CProcessTree::agingCleanup()
{
    const auto now = std::chrono::steady_clock::now();
    const auto ttl = std::chrono::seconds(30);  // 退出30秒后清理

    std::lock_guard<std::mutex> lock(treeMutex);
    for ( auto it = agingList.begin(); it != agingList.end(); )
    {
        if ( now - it->exitTime >= ttl )
        {
            // 检查是否有子进程还在运行
            bool hasActiveChildren = false;
            for ( const auto &kv: ProcTreeMap )
            {
                if ( kv.first.PPID == it->key.PID )
                {
                    // 打印退出进程（父）与阻挡清理的子进程号
                    //                    LOG_DEBUG("[CProcessTree] 退出进程: {} 存在活跃子进程:", it->key.PID);
                    //                    << kv.first.PID << std::endl;
                    hasActiveChildren = true;
                    break;
                }
            }

            // 没有活跃子进程才清理，需要打印日志，和清除释放内存
            if ( !hasActiveChildren )
            {
                //                LOG_DEBUG("[CProcessTree] 清理进程: {}", it->key.PID);
                // 释放存储的对象，防止泄漏
                // 先通过全key找到对象并释放
                auto                       fullKeyIter = ProcTreeMap.find(it->key);
                EAGLE_THREAT_PROCESS_INFO *objPtr      = nullptr;
                if ( fullKeyIter != ProcTreeMap.end() )
                {
                    objPtr = fullKeyIter->second;
                    ProcTreeMap.erase(fullKeyIter);
                }

                // 然后删除对应的PID-only key（如果存在）
                ProcTreeKey pidOnlyKey;
                pidOnlyKey.PID  = it->key.PID;
                pidOnlyKey.type = KeyType::PIDOnly;
                auto pidKeyIter = ProcTreeMap.find(pidOnlyKey);
                if ( pidKeyIter != ProcTreeMap.end() && pidKeyIter->second == objPtr )
                {
                    ProcTreeMap.erase(pidKeyIter);
                }

                // 最后释放对象内存（确保只释放一次）
                if ( objPtr )
                {
                    delete objPtr;
                }

                it = agingList.erase(it);
            }
            else
            {
                ++it;
            }
        }
        else
        {
            ++it;
        }
    }
}

EAGLE_THREAT_PROCESS_INFO *CProcessTree::FindByPid(pid_t pid)
{
    std::lock_guard<std::mutex> lock(treeMutex);
    ProcTreeKey                 pidKey;
    pidKey.PID  = pid;
    pidKey.type = KeyType::PIDOnly;
    auto it     = ProcTreeMap.find(pidKey);
    if ( it != ProcTreeMap.end() )
    {
        return it->second;
    }
    return nullptr;
}

std::vector<EAGLE_THREAT_PROCESS_INFO *> CProcessTree::FindByImagePath(const std::string &imagePath)
{
    std::vector<EAGLE_THREAT_PROCESS_INFO *> results;
    std::lock_guard<std::mutex>              lock(treeMutex);
    for ( auto &kv: ProcTreeMap )
    {
        if ( kv.second && kv.second->ImagePath == imagePath )
        {
            results.push_back(kv.second);
        }
    }
    return results;
}

std::vector<EAGLE_THREAT_PROCESS_INFO *> CProcessTree::GetProcessChain(pid_t pid)
{
    std::vector<EAGLE_THREAT_PROCESS_INFO *> chain;
    std::lock_guard<std::mutex>              lock(treeMutex);

    pid_t currentPid = pid;
    int   guard      = 64;  // 防环

    while ( currentPid > 0 && guard-- > 0 )
    {
        EAGLE_THREAT_PROCESS_INFO *proc = nullptr;

        // 按 PID 查找任意进程
        for ( auto &kv: ProcTreeMap )
        {
            if ( kv.first.PID == currentPid && kv.second )
            {
                proc = kv.second;
                break;
            }
        }

        if ( proc )
        {
            chain.push_back(proc);
            // 获取父进程ID，并立即检查有效性
            pid_t parentPid = SystemUtils::GetPPid(currentPid);
            if ( parentPid <= 0 )
            {
                break;  // 到达进程树顶端，停止追踪
            }
            currentPid = parentPid;
        }
        else
        {
            break;  // 未找到进程信息，停止追踪
        }
    }

    return chain;
}

void CProcessTree::AgingCallback()
{
    agingCleanup();
}
