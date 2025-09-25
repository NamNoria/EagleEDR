#ifndef SYSTEMUTILS_H
#define SYSTEMUTILS_H

#include <Foundation/Foundation.h>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "macro.h"

// ================== 签名状态缓存 ==================
static std::unordered_map<std::string, int> g_signStatusCache;
static std::mutex                           g_signStatusMutex;
static const size_t                         kSignStatusCacheMaxEntries = 390;

// ================== 签名者缓存 ==================
static std::unordered_map<std::string, std::string> g_signerNameCache;
static std::mutex                                   g_signerNameMutex;

struct THREAT_PROC_INFO;

namespace SystemUtils
{
/// 通过进程ID获取进程信息
/// @param pid 入参：进程id
/// @param info 出参：进程信息
void GetProcInfo(pid_t pid, THREAT_PROC_INFO *info);
void FreeReportProcInfo(THREAT_PROC_INFO *info);

bool GetAllProcessID(std::vector<pid_t> &vecPid);

std::string GetImage(pid_t pid);  // 指定 PID 的进程可执行文件路径
pid_t       GetPPid(pid_t pid);   // 指定进程的父进程ID
std::string GetCMD(pid_t pid);    // 指定进程的命令行
std::string GetPWD(pid_t pid);    // 指定进程的工作目录
time_t      GetCreateTime(pid_t pid);
size_t      GetFileSize(pid_t pid);
uid_t       GetSID(pid_t pid);
std::string GetUser(pid_t pid);
std::string GetGUID(pid_t pid);   // 指定进程的GUID  pid+ppid+UTC+image+uuid
std::string GetSHA256(pid_t pid);
std::string GetSignerName(const std::string &path);
bool        IsCompilerOrDevToolProcess(pid_t pid);  // 快速检查是否为编译器/开发工具进程

// 配置文件路径管理
std::string GetConfigFilePath(const std::string &configFileName);  // 智能获取配置文件路径
}  // namespace SystemUtils

#endif
