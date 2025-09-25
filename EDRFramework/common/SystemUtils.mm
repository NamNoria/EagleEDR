#include <CommonCrypto/CommonCrypto.h>
#include <cstring>
#include <iostream>
#include <IOKit/IOKitLib.h>
#include <libproc.h>
#include <pwd.h>
#include <sstream>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <unordered_set>
#include <chrono>
#include <algorithm>

#include "../module/CFilterRule.h"
#include "SystemUtils.h"
#include "Logger.h"

void SystemUtils::GetProcInfo(pid_t pid, THREAT_PROC_INFO *info)
{
    info->pid = pid;

    std::string image = GetImage(pid);
    if ( !image.empty() )
    {
        char *buf = (char *)malloc(image.size() + 1);
        memcpy(buf, image.c_str(), image.size() + 1);
        info->image = buf;
    }
    else
    {
        info->image = nullptr;
    }

    std::string cmd = GetCMD(pid);
    if ( !cmd.empty() )
    {
        char *buf = (char *)malloc(cmd.size() + 1);
        memcpy(buf, cmd.c_str(), cmd.size() + 1);
        info->cmd = buf;
    }
    else
    {
        info->cmd = nullptr;
    }

    std::string pwd = GetPWD(pid);
    if ( !pwd.empty() )
    {
        char *buf = (char *)malloc(pwd.size() + 1);
        memcpy(buf, pwd.c_str(), pwd.size() + 1);
        info->pwd = buf;
    }
    else
    {
        info->pwd = nullptr;
    }

    std::string guid = GetGUID(pid);
    if ( !guid.empty() )
    {
        char *buf = (char *)malloc(guid.size() + 1);
        memcpy(buf, guid.c_str(), guid.size() + 1);
        info->guid = buf;
    }
    else
    {
        info->guid = nullptr;
    }

    std::string sha256 = GetSHA256(pid);
    if ( !sha256.empty() )
    {
        char *buf = (char *)malloc(sha256.size() + 1);
        memcpy(buf, sha256.c_str(), sha256.size() + 1);
        info->sha256 = buf;
    }
    else
    {
        info->sha256 = nullptr;
    }
}

void SystemUtils::FreeReportProcInfo(THREAT_PROC_INFO *info)
{
    if ( !info )
    {
        return;
    }

    if ( info->guid )
    {
        free((void *)info->guid);
        info->guid = nullptr;
    }

    if ( info->image )
    {
        free((void *)info->image);
        info->image = nullptr;
    }

    if ( info->cmd )
    {
        free((void *)info->cmd);
        info->cmd = nullptr;
    }

    if ( info->pwd )
    {
        free((void *)info->pwd);
        info->pwd = nullptr;
    }

    if ( info->sha256 )
    {
        free((void *)info->sha256);
        info->sha256 = nullptr;
    }

    if ( info->signer )
    {
        free((void *)info->signer);
        info->signer = nullptr;
    }

    if ( info->orig_file )
    {
        free((void *)info->orig_file);
        info->orig_file = nullptr;
    }

    if ( info->company )
    {
        free((void *)info->company);
        info->company = nullptr;
    }

    if ( info->parent_guid )
    {
        free((void *)info->parent_guid);
        info->parent_guid = nullptr;
    }

    if ( info->source )
    {
        free((void *)info->source);
        info->source = nullptr;
    }
}

pid_t SystemUtils::GetPPid(pid_t pid)
{
    if ( pid <= 0 )
    {
        return -1;
    }

    struct proc_bsdinfo info {};
    int                 ret = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
    if ( ret <= 0 )
    {
        LOG_WARN("proc_pidinfo failed to get parent pid, pid={}, ret={}, errno={}", pid, ret, errno);
        return -1;  // 获取失败
    }

    return info.pbi_ppid;
}

/// 获取系统所有进程 ID 列表
/// @param vecPid 输出参数，返回所有进程ID列表
/// @return 成功返回 true，失败返回 false
bool SystemUtils::GetAllProcessID(std::vector<pid_t> &vecPid)
{
    vecPid.clear();

    size_t             estimatedCount = 4096;
    std::vector<pid_t> tempPids;
    int                numBytes = 0;

    while ( true )
    {
        tempPids.resize(estimatedCount);

        numBytes = proc_listpids(PROC_ALL_PIDS, 0, tempPids.data(), (int)(tempPids.size() * sizeof(pid_t)));
        if ( numBytes <= 0 )
        {
            return false;  // 查询失败
        }

        int pidCount = numBytes / sizeof(pid_t);
        if ( pidCount < static_cast<int>(estimatedCount) )
        {
            tempPids.resize(pidCount);
            break;
        }

        // PID数量超过预估，扩大缓冲区
        estimatedCount *= 2;
    }
    vecPid.swap(tempPids);
    return true;
}

std::string SystemUtils::GetImage(pid_t pid)
{
    if ( pid <= 0 )
    {
        return "";
    }

    char pathbuf[PATH_MAX] = { 0 };
    int  ret               = proc_pidpath(pid, pathbuf, sizeof(pathbuf));
    if ( ret <= 0 )
    {
        // 可选：打印错误信息
        // LOG_ERROR("proc_pidpath failed, errno: {}", errno);
        return "";
    }

    return std::string(pathbuf);
}

#include <sys/sysctl.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <mutex>


// 智能缓存结构
struct CmdCacheEntry {
    std::string cmdline;
    std::chrono::steady_clock::time_point lastAccess;
    uint32_t accessCount;
    bool isWhitelistedProcess;  // 是否为白名单进程（编译器等）

    CmdCacheEntry(const std::string& cmd, bool isWhitelisted = false)
        : cmdline(cmd), lastAccess(std::chrono::steady_clock::now()),
          accessCount(1), isWhitelistedProcess(isWhitelisted) {}
};

static std::unordered_map<pid_t, CmdCacheEntry> g_cmdCache;
static std::mutex g_cmdCacheMutex;
static const size_t kCmdCacheMaxEntries = 2000; // 增加缓存大小
static const size_t kCmdCacheCleanupThreshold = 1800; // 清理阈值

// 编译器和开发工具白名单（快速路径处理）
static const std::unordered_set<std::string> g_compilerProcesses = {
    "clang", "clang++", "gcc", "g++", "ld", "as", "swift", "swiftc",
    "xcodebuild", "cc", "c++", "ar", "ranlib", "strip", "dsymutil",
    "libtool", "lipo", "codesign", "actool", "ibtool", "texturetool"
};

static const std::unordered_set<std::string> g_devToolProcesses = {
    "Unity", "UnityEditor", "UnityHub", "UE4Editor", "UE5Editor",
    "Visual Studio", "Xcode", "CLion", "IntelliJ", "Android Studio",
    "gradle", "gradlew", "maven", "mvn", "npm", "yarn", "node",
    "python", "java", "javac", "kotlinc", "rustc", "cargo", "go"
};

// 从进程路径中提取进程名
static std::string extractProcessName(const std::string& cmdline) {
    if (cmdline.empty()) return "";

    size_t spacePos = cmdline.find(' ');
    std::string execPath = (spacePos != std::string::npos) ? cmdline.substr(0, spacePos) : cmdline;

    size_t lastSlash = execPath.find_last_of('/');
    return (lastSlash != std::string::npos) ? execPath.substr(lastSlash + 1) : execPath;
}

// 检查进程是否为编译器或开发工具
static bool isCompilerOrDevTool(const std::string& processName) {
    return g_compilerProcesses.count(processName) > 0 || g_devToolProcesses.count(processName) > 0;
}

// 智能缓存清理 - 使用LRU + 进程类型优先级
static void smartCacheCleanup() {
    if (g_cmdCache.size() < kCmdCacheCleanupThreshold) return;

    auto now = std::chrono::steady_clock::now();
    std::vector<std::pair<pid_t, std::chrono::steady_clock::duration>> candidates;

    // 收集清理候选者 - 优先清理非白名单进程且最久未访问的
    for (const auto& entry : g_cmdCache) {
        auto age = now - entry.second.lastAccess;

        // 白名单进程和高频访问进程的保护策略
        if (entry.second.isWhitelistedProcess && entry.second.accessCount > 10) {
            continue;  // 保护高频访问的白名单进程
        }

        // 非白名单进程更容易被清理
        if (!entry.second.isWhitelistedProcess || age > std::chrono::minutes(5)) {
            candidates.emplace_back(entry.first, age);
        }
    }

    // 按年龄排序，优先清理最老的
    std::sort(candidates.begin(), candidates.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    // 清理最老的25%条目，但至少保留1500个
    size_t targetSize = std::max(kCmdCacheMaxEntries * 3 / 4, size_t(1500));
    size_t toRemove = g_cmdCache.size() > targetSize ? g_cmdCache.size() - targetSize : 0;
    toRemove = std::min(toRemove, candidates.size());

    for (size_t i = 0; i < toRemove; ++i) {
        g_cmdCache.erase(candidates[i].first);
    }

    LOG_DEBUG("Smart cache cleanup: removed {} entries, remaining {}", toRemove, g_cmdCache.size());
}

// 原始 sysctl 实现，不做任何改动
static std::string fetchCMD_sysctl(pid_t pid)
{
    if (pid <= 0)
        return "";

    static size_t argmax = 0;
    if (argmax == 0) {
        size_t size = sizeof(argmax);
        if (sysctlbyname("kern.argmax", &argmax, &size, nullptr, 0) != 0) {
            return "";
        }
    }

    int mib[3] = {CTL_KERN, KERN_PROCARGS2, pid};
    std::vector<char> buf(argmax);
    size_t size = argmax;

    if (sysctl(mib, 3, buf.data(), &size, nullptr, 0) != 0)
        return "";

    char *p = buf.data();
    char *end = buf.data() + size;

    int argc = 0;
    if ((p + sizeof(int)) > end)
        return "";
    memcpy(&argc, p, sizeof(int));
    p += sizeof(int);

    while (p < end && *p != '\0') ++p;
    while (p < end && *p == '\0') ++p;

    std::vector<std::string> argvList;
    for (int i = 0; i < argc && p < end; ++i) {
        std::string arg(p);
        argvList.push_back(arg);
        p += arg.size() + 1;
    }

    if (argvList.empty())
        return "";

    std::string cmdline;
    for (size_t i = 0; i < argvList.size(); ++i) {
        if (i > 0)
            cmdline += " ";
        cmdline += argvList[i];
    }

    return cmdline;
}

// 带缓存的版本
std::string SystemUtils::GetCMD(pid_t pid)
{
    if (pid <= 0)
        return "";

    // 缓存查找和访问统计更新
    {
        std::lock_guard<std::mutex> lock(g_cmdCacheMutex);
        auto it = g_cmdCache.find(pid);
        if (it != g_cmdCache.end() && !it->second.cmdline.empty()) {
            // 更新访问统计（只有非空命令行才返回）
            it->second.lastAccess = std::chrono::steady_clock::now();
            it->second.accessCount++;
            return it->second.cmdline;  // 命中缓存，直接返回
        }
    }

    // 未命中缓存，调用原始 sysctl 实现
    std::string cmdline = fetchCMD_sysctl(pid);

    if (!cmdline.empty()) {
        std::lock_guard<std::mutex> lock(g_cmdCacheMutex);

        // 检查是否为编译器或开发工具
        std::string processName = extractProcessName(cmdline);
        bool isWhitelisted = isCompilerOrDevTool(processName);

        // 检查是否已存在（可能是空的占位符）
        auto it = g_cmdCache.find(pid);
        if (it != g_cmdCache.end()) {
            // 更新现有条目的命令行
            it->second.cmdline = cmdline;
            it->second.lastAccess = std::chrono::steady_clock::now();
            it->second.accessCount++;
            it->second.isWhitelistedProcess = isWhitelisted;
        } else {
            // 智能缓存清理
            if (g_cmdCache.size() >= kCmdCacheMaxEntries) {
                smartCacheCleanup();
            }
            // 创建新条目
            g_cmdCache.emplace(pid, CmdCacheEntry(cmdline, isWhitelisted));
        }

        // 为编译器进程添加调试日志
        if (isWhitelisted) {
            LOG_DEBUG("Cached compiler/dev tool process: {} (pid={})", processName, pid);
        }
    }

    return cmdline;
}

// 快速检查进程是否为编译器/开发工具 - 避免昂贵的CMD获取
bool SystemUtils::IsCompilerOrDevToolProcess(pid_t pid)
{
    if (pid <= 0) return false;

    // 首先检查缓存中是否已经有这个进程的信息
    {
        std::lock_guard<std::mutex> lock(g_cmdCacheMutex);
        auto it = g_cmdCache.find(pid);
        if (it != g_cmdCache.end()) {
            return it->second.isWhitelistedProcess;
        }
    }

    // 快速获取进程名（不获取完整命令行）- 使用proc_name代替昂贵的sysctl
    char processName[PROC_PIDPATHINFO_MAXSIZE] = {0};
    if (proc_name(pid, processName, sizeof(processName)) <= 0) {
        return false;  // 获取失败，可能进程已退出
    }

    // 检查进程名是否在白名单中
    std::string procName(processName);
    bool isWhitelisted = isCompilerOrDevTool(procName);

    // 如果是编译器进程，记录到缓存中(但不获取完整CMD)
    if (isWhitelisted) {
        std::lock_guard<std::mutex> lock(g_cmdCacheMutex);
        // 使用空的命令行占位，标记为白名单进程
        g_cmdCache.emplace(pid, CmdCacheEntry("", true));
        LOG_DEBUG("Fast-detected compiler/dev tool: {} (pid={})", procName, pid);
    }

    return isWhitelisted;
}

// 在进程退出时调用，清理缓存，避免无限增长
void RemoveCMDFromCache(pid_t pid)
{
    std::lock_guard<std::mutex> lock(g_cmdCacheMutex);
    g_cmdCache.erase(pid);
}
/*
std::string SystemUtils::GetCMD(pid_t pid)
{
    if ( pid <= 0 )
    {
        return "";
    }

    int    mib[3] = { CTL_KERN, KERN_PROCARGS2, pid };
    size_t argmax = 0;

    // 获取 buffer 大小
    size_t size = sizeof(argmax);
    if ( sysctlbyname("kern.argmax", &argmax, &size, nullptr, 0) != 0 )
    {
        return "";
    }

    std::vector<char> buf(argmax);
    if ( sysctl(mib, 3, buf.data(), &argmax, nullptr, 0) != 0 )
    {
        return "";
    }

    // buf 中是 '\0' 分隔的 argv
    char                    *p = buf.data() + sizeof(int);  // 前面 4 字节是 argc
    std::vector<std::string> argvList;
    while ( *p != '\0' )
    {
        argvList.emplace_back(p);
        p += strlen(p) + 1;
    }

    std::string cmdline;
    for ( size_t i = 0; i < argvList.size(); i++ )
    {
        if ( i > 0 )
        {
            cmdline += " ";
        }
        cmdline += argvList[i];
    }

    return cmdline;
}
*/
std::string SystemUtils::GetPWD(pid_t pid)
{
    if ( pid <= 0 )
    {
        return "";
    }

    struct proc_vnodepathinfo vnodeInfo;
    if ( proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &vnodeInfo, sizeof(vnodeInfo)) <= 0 )
    {
        return "";
    }

    return std::string(vnodeInfo.pvi_cdir.vip_path);
}

time_t SystemUtils::GetCreateTime(pid_t pid)
{
    if ( pid <= 0 )
    {
        return 0;
    }

    struct proc_bsdinfo info {};
    int                 ret = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
    if ( ret <= 0 )
    {
        return 0;  // 获取失败
    }

    return static_cast<time_t>(info.pbi_start_tvsec);
}

size_t SystemUtils::GetFileSize(pid_t pid)
{
    char pathbuf[PATH_MAX] = { 0 };
    int  ret               = proc_pidpath(pid, pathbuf, sizeof(pathbuf));
    if ( ret <= 0 )
    {
        // 可选：打印错误信息
        // LOG_ERROR("proc_pidpath failed, errno: {}", errno);
        return -1;
    }

    struct stat st {};
    if ( stat(pathbuf, &st) == 0 )
    {
        return (uint64_t)st.st_size;
    }
    return -1;
}

uid_t SystemUtils::GetSID(pid_t pid)
{
    struct kinfo_proc kp;
    size_t            len    = sizeof(kp);
    int               mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };

    if ( sysctl(mib, 4, &kp, &len, NULL, 0) == -1 )
    {
        perror("sysctl");
        return (uid_t)-1;
    }

    return kp.kp_eproc.e_ucred.cr_uid;  // 实际用户 ID
}

std::string SystemUtils::GetUser(pid_t pid)
{
    struct kinfo_proc kp;
    size_t            len    = sizeof(kp);
    int               mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };

    if ( sysctl(mib, 4, &kp, &len, NULL, 0) == -1 || len == 0 )
    {
        return "unknown";  // 查询失败
    }

    uid_t          uid = kp.kp_eproc.e_ucred.cr_uid;
    struct passwd *pw  = getpwuid(uid);
    if ( !pw || !pw->pw_name )
    {
        return "unknown";  // 找不到用户名
    }

    return std::string(pw->pw_name);
}

std::string SystemUtils::GetGUID(pid_t pid)
{
    if ( pid <= 0 )
    {
        return "";
    }

    // 获取进程信息（ppid 和启动时间）
    struct proc_bsdinfo info {};
    int                 ret = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
    if ( ret <= 0 )
    {
        return "";
    }

    pid_t    ppid       = info.pbi_ppid;
    uint64_t start_time = info.pbi_start_tvsec;

    // 获取进程镜像路径
    char procPath[PATH_MAX] = { 0 };
    if ( proc_pidpath(pid, procPath, sizeof(procPath)) <= 0 )
    {
        procPath[0] = '\0';
    }

    // 获取硬件 UUID
    char                hardwareUUID[128] = { 0 };
    io_registry_entry_t ioRegistryRoot    = IORegistryEntryFromPath(kIOMainPortDefault, "IOService:/");
    if ( ioRegistryRoot )
    {
        CFTypeRef uuidCF =
                IORegistryEntryCreateCFProperty(ioRegistryRoot, CFSTR("IOPlatformUUID"), kCFAllocatorDefault, 0);
        IOObjectRelease(ioRegistryRoot);
        if ( uuidCF && CFGetTypeID(uuidCF) == CFStringGetTypeID() )
        {
            CFStringGetCString((CFStringRef)uuidCF, hardwareUUID, sizeof(hardwareUUID), kCFStringEncodingUTF8);
        }
        if ( uuidCF )
        {
            CFRelease(uuidCF);
        }
    }

    // 拼接唯一标识字符串
    char inputString[PATH_MAX + 256] = { 0 };
    snprintf(inputString, sizeof(inputString), "%d|%d|%llu|%s|%s", pid, ppid, start_time, procPath, hardwareUUID);

    // 计算 SHA256
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256((const unsigned char *)inputString, (CC_LONG)strlen(inputString), hash);

    // 转成 std::string
    char guidStr[CC_SHA256_DIGEST_LENGTH * 2 + 1] = { 0 };
    for ( int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++ )
    {
        snprintf(guidStr + i * 2, 3, "%02x", hash[i]);
    }

    return std::string(guidStr);
}

#include <unordered_map>
#include <mutex>
#include <sys/stat.h>
#include <vector>
#include <string>
#include <CommonCrypto/CommonDigest.h>  // CC_SHA256_xxx

// ===================== 原始 SHA256 实现（不改动） =====================
static std::string fetchSHA256(const std::string &path)
{
    FILE *file = fopen(path.c_str(), "rb");
    if (!file) {
        return "";
    }

    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);

    const size_t bufSize = 4096;
    std::vector<unsigned char> buffer(bufSize);

    size_t bytesRead = 0;
    while ((bytesRead = fread(buffer.data(), 1, bufSize, file)) > 0) {
        CC_SHA256_Update(&ctx, buffer.data(), (CC_LONG)bytesRead);
    }
    fclose(file);

    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(hash, &ctx);

    char hexStr[CC_SHA256_DIGEST_LENGTH * 2 + 1] = {0};
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        snprintf(hexStr + i * 2, 3, "%02x", hash[i]);
    }

    return std::string(hexStr);
}

// ===================== 缓存结构体 =====================
struct FileHashCacheEntry {
    std::string sha256;
    time_t mtime;  // 文件最后修改时间
};

// 缓存表：path -> {sha256, mtime}
static std::unordered_map<std::string, FileHashCacheEntry> g_sha256Cache;
static std::mutex g_sha256CacheMutex;
static const size_t kSHA256CacheMaxEntries = 1000; // 限制缓存大小

// ===================== 对外接口 =====================
std::string SystemUtils::GetSHA256(pid_t pid)
{
    char pathbuf[PATH_MAX] = {0};
    if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) <= 0) {
        return "";
    }

    std::string path(pathbuf);

    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        return "";
    }

    {
        std::lock_guard<std::mutex> lock(g_sha256CacheMutex);
        auto it = g_sha256Cache.find(path);
        if (it != g_sha256Cache.end() && it->second.mtime == st.st_mtime) {
            return it->second.sha256; // 命中缓存
        }
    }

    // 未命中缓存，重新计算
    std::string result = fetchSHA256(path);

    if (!result.empty()) {
        std::lock_guard<std::mutex> lock(g_sha256CacheMutex);
        // 检查缓存大小限制
        if (g_sha256Cache.size() >= kSHA256CacheMaxEntries) {
            // 简单FIFO策略：删除最老的条目
            auto it = g_sha256Cache.begin();
            if (it != g_sha256Cache.end()) {
                g_sha256Cache.erase(it);
            }
        }
        g_sha256Cache[path] = {result, st.st_mtime};  // 写入缓存
    }

    return result;
}

// 手动移除某个进程的缓存（通过 pid 找路径再删）
void RemoveSHA256FromCache(pid_t pid)
{
    char pathbuf[PATH_MAX] = {0};
    if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) > 0) {
        std::lock_guard<std::mutex> lock(g_sha256CacheMutex);
        g_sha256Cache.erase(std::string(pathbuf));
    }
}

// 清空所有缓存
void ClearAllSHA256Cache()
{
    std::lock_guard<std::mutex> lock(g_sha256CacheMutex);
    g_sha256Cache.clear();
}

/*
std::string SystemUtils::GetSHA256(pid_t pid)
{
    char pathbuf[PATH_MAX] = { 0 };
    if ( proc_pidpath(pid, pathbuf, sizeof(pathbuf)) <= 0 )
    {
        return "";  // 获取路径失败
    }

    FILE *file = fopen(pathbuf, "rb");
    if ( !file )
    {
        return "";  // 打开文件失败
    }

    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);

    const size_t               bufSize = 4096;
    std::vector<unsigned char> buffer(bufSize);

    size_t bytesRead = 0;
    while ( (bytesRead = fread(buffer.data(), 1, bufSize, file)) > 0 )
    {
        CC_SHA256_Update(&ctx, buffer.data(), (CC_LONG)bytesRead);
    }

    fclose(file);

    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(hash, &ctx);

    char hexStr[CC_SHA256_DIGEST_LENGTH * 2 + 1] = { 0 };
    for ( int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++ )
    {
        snprintf(hexStr + i * 2, 3, "%02x", hash[i]);
    }

    return std::string(hexStr);
}
*/
static std::unordered_map<std::string, std::string> g_signerCache;
static std::mutex                                   g_cacheMutex;
static const size_t                                 kSignerCacheMaxEntries = 390;

// 生成缓存键（路径 + 修改时间）
static std::string MakeCacheKey(const std::string &path)
{
    struct stat st {};
    if ( stat(path.c_str(), &st) != 0 )
    {
        return "";
    }
    std::ostringstream oss;
    oss << path << "_" << st.st_mtime;
    return oss.str();
}

// 外部调用接口
std::string SystemUtils::GetSignerName(const std::string &path)
{
    std::string cacheKey = MakeCacheKey(path);

    // 检查缓存
    {
        std::lock_guard<std::mutex> lock(g_cacheMutex);
        auto                        it = g_signerCache.find(cacheKey);
        if ( it != g_signerCache.end() )
        {
            // LOG_DEBUG("[SignerCache] size={}", g_signerCache.size());
            return it->second;
        }
    }

    // 使用 SecStaticCode + SecStaticCodeCopySigningInformation 获取签名者信息
    std::string authority;
    CFURLRef    url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)path.c_str(), path.size(), false);
    if ( url )
    {
        SecStaticCodeRef staticCode = nullptr;
        OSStatus         status     = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &staticCode);
        CFRelease(url);

        if ( status == errSecSuccess && staticCode )
        {
            CFDictionaryRef signingInfo = nullptr;
            status                      = SecCodeCopySigningInformation(staticCode,
                                                                        kSecCSSigningInformation | kSecCSRequirementInformation
                                                                                | kSecCSDynamicInformation | kSecCSContentInformation,
                                                                        &signingInfo);
            if ( status == errSecSuccess && signingInfo )
            {
                if ( CFGetTypeID(signingInfo) == CFDictionaryGetTypeID() )
                {
                    // 从证书数组提取首个证书的主题摘要（常用于显示 Authority）
                    CFArrayRef certificates =
                            (CFArrayRef)CFDictionaryGetValue((CFDictionaryRef)signingInfo, kSecCodeInfoCertificates);
                    if ( certificates && CFGetTypeID(certificates) == CFArrayGetTypeID()
                         && CFArrayGetCount(certificates) > 0 )
                    {
                        SecCertificateRef cert = (SecCertificateRef)CFArrayGetValueAtIndex(certificates, 0);
                        if ( cert )
                        {
                            CFStringRef summary = SecCertificateCopySubjectSummary(cert);
                            if ( summary )
                            {
                                char buff[512] = { 0 };
                                if ( CFStringGetCString(summary, buff, sizeof(buff), kCFStringEncodingUTF8) )
                                {
                                    authority.assign(buff);
                                }
                                CFRelease(summary);
                            }
                        }
                    }
                }
                CFRelease(signingInfo);
            }

            CFRelease(staticCode);
        }
    }

    // 缓存结果（即使为空也缓存，避免频繁系统调用），并限制缓存大小
    {
        std::lock_guard<std::mutex> lock(g_cacheMutex);
        if ( g_signerCache.size() >= kSignerCacheMaxEntries )
        {
            // 简单 FIFO：删除 map 的第一个元素（近似）
            auto it = g_signerCache.begin();
            if ( it != g_signerCache.end() )
            {
                g_signerCache.erase(it);
            }
        }
        g_signerCache[cacheKey] = authority;
        // LOG_DEBUG("[SignerCache] size={}", g_signerCache.size());
    }

    return authority;
}

std::string SystemUtils::GetConfigFilePath(const std::string &configFileName)
{
    LOG_INFO("Looking for config file: {}", configFileName);

    // 优先级顺序：
    // 1. App Bundle Resources 目录
    // 2. /opt/.yunshu/EDR/config/ 目录
    // 3. 开发时的相对路径

    @autoreleasepool {
        NSBundle *mainBundle = [NSBundle mainBundle];

        // 1. 尝试从 App Bundle Resources 目录加载
        if (mainBundle) {
            NSString *resourcePath = [mainBundle pathForResource:@(configFileName.c_str()) ofType:nil];
            LOG_INFO("App bundle resource path attempt: {}", resourcePath ? resourcePath.UTF8String : "null");
            if (resourcePath && [[NSFileManager defaultManager] fileExistsAtPath:resourcePath]) {
                LOG_INFO("Found config file in app bundle: {}", resourcePath.UTF8String);
                return std::string(resourcePath.UTF8String);
            }
        }

        // 2. 尝试从系统配置目录加载
        std::string systemConfigPath = "/opt/.yunshu/EDR/config/" + configFileName;
        LOG_INFO("Checking system config path: {}", systemConfigPath);
        if ([[NSFileManager defaultManager] fileExistsAtPath:@(systemConfigPath.c_str())]) {
            LOG_INFO("Found config file in system directory: {}", systemConfigPath);
            return systemConfigPath;
        }

        // 3. 尝试开发时的相对路径（兼容性）
        std::string devPath = "config/" + configFileName;
        LOG_INFO("Checking development path: {}", devPath);
        if ([[NSFileManager defaultManager] fileExistsAtPath:@(devPath.c_str())]) {
            LOG_INFO("Found config file in development path: {}", devPath);
            return devPath;
        }

        LOG_ERROR("Config file '{}' not found in any expected locations", configFileName);
        return "";
    }
}
