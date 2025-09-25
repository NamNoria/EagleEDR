#ifndef ESFUTILS_H
#define ESFUTILS_H

#include <EndpointSecurity/EndpointSecurity.h>
#include <Foundation/Foundation.h>

#include "SystemUtils.h"
struct EAGLE_THREAT_PROCESS_INFO;
struct EAGLE_THREAT_CREATE_FILE_INFO;
struct EAGLE_THREAT_RENAME_FILE_INFO;
union EventInfoUnion;

namespace EsfUtils
{
// 通用事件信息获取接口：根据事件类型填充联合体
bool GetEventInfo(const es_message_t *msg, EVENTID eventId, EventInfoUnion *out);

// 细分填充接口（可选暴露）
bool      FillProcessStart(const es_message_t *msg, EAGLE_THREAT_PROCESS_INFO *out);
bool      FillCreateFileEvent(const es_message_t *msg, EAGLE_THREAT_CREATE_FILE_INFO *out);
bool      FillRenameFileEvent(const es_message_t *msg, EAGLE_THREAT_RENAME_FILE_INFO *out);
void      GetProcInfo(const es_message_t *msg, pid_t pid, THREAT_PROC_INFO *info);
NSString *GetProcessName(const es_message_t *msg);
NSString *GetProcessPath(const es_message_t *msg);
pid_t     GetPid(const es_message_t *msg);
pid_t     GetPPid(const es_message_t *msg);
uid_t     GetUid(const es_message_t *msg);
NSString *GetUser(const es_message_t *msg);
time_t    GetUtcTime(const es_message_t *msg);     // 获取事件时间
time_t    GetCreateTime(const es_message_t *msg);  // 获取进程启动时间
NSString *GetCMD(const es_message_t *msg);         // 获取进程命令行
NSString *GetPWD(const es_message_t *msg);         // 获取工作路径
uint64_t  GetFileSize(const es_message_t *msg);
NSString *GetSHA256(const es_message_t *msg);
NSString *GetGUID(const es_message_t *msg);

// 获取主机名与主 IPv4 地址（最佳努力）
std::string GetHostName();
std::string GetPrimaryIPv4();
}  // namespace ESFUtils
#endif  // ESFUTILS_H
