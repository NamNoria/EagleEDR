#ifndef CPROCESSTREE_H
#define CPROCESSTREE_H

#include "../common/SystemUtils.h"

#include <unistd.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <list>
#include <mutex>
#include <chrono>
#include <thread>
#include <cstdint>
#include <ctime>

struct EAGLE_THREAT_PROCESS_INFO;

enum class KeyType
{
    FullKey,
    PIDOnly,
    UUIDOnly,
    ImagePathOnly
};

struct ProcTreeKey
{
    int32_t     PID        = 0;
    int32_t     PPID       = 0;
    time_t      CreateTime = 0;
    // 移除 ImagePath，仅保留核心标识
    KeyType type = KeyType::FullKey;

    bool operator== (const ProcTreeKey &other) const
    {
        switch ( type )
        {
            case KeyType::FullKey:
                return PID == other.PID && PPID == other.PPID && CreateTime == other.CreateTime;
            case KeyType::PIDOnly:
                return PID == other.PID;
            case KeyType::UUIDOnly:
                return false;  // 未使用 UUID 作为 Key
            case KeyType::ImagePathOnly:
                return false;  // 不再支持 ImagePath 作为 Key
        }
        return false;
    }
};

struct ProcTreeKeyHash
{
    size_t operator() (const ProcTreeKey &k) const
    {
        switch ( k.type )
        {
            case KeyType::FullKey:
            {
                // 与 operator== 一致：PID, PPID, CreateTime 共同决定 Key
                size_t h1 = std::hash<int32_t>()(k.PID);
                size_t h2 = std::hash<int32_t>()(k.PPID);
                size_t h3 = std::hash<time_t>()(k.CreateTime);
                // 组合哈希
                size_t seed = h1;
                seed ^= h2 + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
                seed ^= h3 + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
                return seed;
            }
            case KeyType::PIDOnly:
                return std::hash<int32_t>()(k.PID);
            case KeyType::UUIDOnly:
                return 0;  // 未使用 UUID 作为 Key
            case KeyType::ImagePathOnly:
                return 0;  // 不再支持 ImagePath 作为 Key
        }
        return 0;
    }
};

// 老化队列条目
struct AgingEntry
{
    ProcTreeKey                           key;
    std::chrono::steady_clock::time_point exitTime;
};

class CProcessTree
{
public:
    static CProcessTree *shared();

    /// 构建整棵进程树（可选实现）
    bool BuildProcessTree();

    /// 启动老化线程
    void StartAging();

    /// 打印树（或指定 PID 链路）
    void PrintTree(pid_t iPid, int depth = 0);
    
    /// 查询方法
    EAGLE_THREAT_PROCESS_INFO *FindByPid(pid_t pid);
    std::vector<EAGLE_THREAT_PROCESS_INFO *> FindByImagePath(const std::string &imagePath);
    std::vector<EAGLE_THREAT_PROCESS_INFO *> GetProcessChain(pid_t pid);

    /// 插入/删除/退出标记
    bool insertNode(EAGLE_THREAT_PROCESS_INFO *procInfo);
    bool deleteNode(EAGLE_THREAT_PROCESS_INFO *procInfo);
    bool markExit(const ProcTreeKey &key);

    /// Aging 清理接口
    void AgingCallback();

private:
    /// 单例
    CProcessTree();
    CProcessTree(const CProcessTree &)             = delete;
    CProcessTree &operator= (const CProcessTree &) = delete;
    friend class CProcessThreatDetect;

private:
    /// 内部老化扫描
    void agingCleanup();
    void printSubtree(pid_t pid, int depth);

private:
    std::unordered_map<ProcTreeKey, EAGLE_THREAT_PROCESS_INFO *, ProcTreeKeyHash> ProcTreeMap;
    std::list<AgingEntry>                                                         agingList;  // 仅保存已退出节点
    std::mutex                                                                    treeMutex;

    std::thread agingThread;
};

#endif  // CPROCESSTREE_H
