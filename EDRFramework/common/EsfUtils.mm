#include <arpa/inet.h>
#include <CommonCrypto/CommonDigest.h>
#include <bsm/libbsm.h>
#include <ifaddrs.h>
#include <libproc.h>
#include <netinet/in.h>
#include <sys/proc_info.h>
#include <sys/sysctl.h>
#include <pwd.h>

#include "../module/CThreatEvent.h"
#include "EsfUtils.h"
#include "SystemUtils.h"

bool EsfUtils::FillProcessStart(const es_message_t *msg, EAGLE_THREAT_PROCESS_INFO *out)
{
    if ( !msg || !out )
    {
        return false;
    }
    out->UtcTime           = (int32_t)GetUtcTime(msg);
    out->ProcessId         = (int32_t)GetPid(msg);

    // 安全的字符串赋值 - 防止null pointer crash
    NSString *pathStr = GetProcessPath(msg);
    if (pathStr && pathStr != nil) {
        const char *pathCStr = [pathStr UTF8String];
        if (pathCStr && pathCStr[0] != '\0') {
            out->ImagePath = std::string(pathCStr);
        } else {
            out->ImagePath = std::string("");
        }
    } else {
        out->ImagePath = std::string("");
    }

    NSString *hashStr = GetSHA256(msg);
    if (hashStr && hashStr != nil) {
        const char *hashCStr = [hashStr UTF8String];
        if (hashCStr && hashCStr[0] != '\0') {
            out->Hash = std::string(hashCStr);
        } else {
            out->Hash = std::string("");
        }
    } else {
        out->Hash = std::string("");
    }

    NSString *userStr = GetUser(msg);
    if (userStr && userStr != nil) {
        const char *userCStr = [userStr UTF8String];
        if (userCStr && userCStr[0] != '\0') {
            out->User = std::string(userCStr);
        } else {
            out->User = std::string("");
        }
    } else {
        out->User = std::string("");
    }

    out->SID = std::to_string((int)GetUid(msg));

    NSString *cmdStr = GetCMD(msg);
    if (cmdStr && cmdStr != nil) {
        const char *cmdCStr = [cmdStr UTF8String];
        if (cmdCStr && cmdCStr[0] != '\0') {
            out->CommandLine = std::string(cmdCStr);
        } else {
            out->CommandLine = std::string("");
        }
    } else {
        out->CommandLine = std::string("");
    }

    NSString *pwdStr = GetPWD(msg);
    if (pwdStr && pwdStr != nil) {
        const char *pwdCStr = [pwdStr UTF8String];
        if (pwdCStr && pwdCStr[0] != '\0') {
            out->CurrentDirectory = std::string(pwdCStr);
        } else {
            out->CurrentDirectory = std::string("");
        }
    } else {
        out->CurrentDirectory = std::string("");
    }

    NSString *guidStr = GetGUID(msg);
    if (guidStr && guidStr != nil) {
        const char *guidCStr = [guidStr UTF8String];
        if (guidCStr && guidCStr[0] != '\0') {
            out->ProcessGuid = std::string(guidCStr);
        } else {
            out->ProcessGuid = std::string("");
        }
    } else {
        out->ProcessGuid = std::string("");
    }
    pid_t pid              = GetPPid(msg);
    out->ParentProcessGuid = SystemUtils::GetGUID(pid);
    out->ProcFileId        = "";
    out->SignerName        = SystemUtils::GetSignerName(out->ImagePath);
    out->CreateTime = (int32_t)GetCreateTime(msg);
    out->FileSize   = (int32_t)GetFileSize(msg);
    out->SignStatus = 0;
    out->fileguid   = "";
    return true;
}

bool EsfUtils::FillCreateFileEvent(const es_message_t *msg, EAGLE_THREAT_CREATE_FILE_INFO *out)
{
    if ( !msg || !out )
    {
        return false;
    }
    out->UtcTime     = (int32_t)GetUtcTime(msg);
    out->ProcessGuid = GetGUID(msg) ? [GetGUID(msg) UTF8String] : "";
    out->CreateTime  = (int32_t)GetCreateTime(msg);
    out->FileSize    = (int32_t)GetFileSize(msg);
    out->SignStatus  = 0;
    out->SignerName  = "";
    out->FileHash    = "";

    return true;
}

bool EsfUtils::FillRenameFileEvent(const es_message_t *msg, EAGLE_THREAT_RENAME_FILE_INFO *out)
{
    if ( !msg || !out )
    {
        return false;
    }

    // 基本信息填充
    out->UtcTime = (int32_t)GetUtcTime(msg);
    out->ProcessGuid = GetGUID(msg) ? [GetGUID(msg) UTF8String] : "";

    // 路径信息需要在调用方已经解析并填充
    // 这个函数主要负责基本字段的填充

    return true;
}

void EsfUtils::GetProcInfo(const es_message_t *msg, pid_t pid, THREAT_PROC_INFO *info)
{
    info->pid         = pid;
    NSString *strGuid = EsfUtils::GetGUID(msg);
    info->guid        = strGuid ? strdup([strGuid UTF8String]) : nullptr;

    NSString *strImage = EsfUtils::GetProcessPath(msg);
    info->image        = strImage ? strdup([strImage UTF8String]) : nullptr;

    std::string strCMD = SystemUtils::GetCMD(pid);
    info->cmd = strdup(strCMD.c_str());
//    NSString *strCMD = EsfUtils::GetCMD(msg);
//    info->cmd        = strCMD ? strdup([strCMD UTF8String]) : nullptr;

    NSString *strPWD = EsfUtils::GetPWD(msg);
    info->pwd        = strPWD ? strdup([strPWD UTF8String]) : nullptr;

    std::string strSha256 = SystemUtils::GetSHA256(pid);
    info->sha256 = strdup(strSha256.c_str());
//    NSString *strSha256 = EsfUtils::GetSHA256(msg);
//    info->sha256        = strSha256 ? strdup([strSha256 UTF8String]) : nullptr;
}

bool EsfUtils::GetEventInfo(const es_message_t *msg, EVENTID eventId, EventInfoUnion *out)
{
    if ( !out )
    {
        return false;
    }
    switch ( eventId )
    {
        case EDR_EVENT_PROCESSSTAR:
            return FillProcessStart(msg, out->pProcess);
        case EDR_EVENT_CREATEFILE:
            return FillCreateFileEvent(msg, out->pCreate);
        case EDR_EVENT_FILERENAME:
            return FillRenameFileEvent(msg, out->pRename);
        default:
            return false;
    }
}

std::string EsfUtils::GetHostName()
{
    char buf[256] = { 0 };
    if ( gethostname(buf, sizeof(buf) - 1) == 0 )
    {
        return std::string(buf);
    }
    return std::string("");
}

std::string EsfUtils::GetPrimaryIPv4()
{
    // 简化实现：尝试解析 en0 的 IPv4
    char            addrBuf[INET_ADDRSTRLEN] = { 0 };
    struct ifaddrs *ifaddr                   = nullptr;
    if ( getifaddrs(&ifaddr) == 0 )
    {
        for ( struct ifaddrs *ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next )
        {
            if ( !ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET )
            {
                continue;
            }
            if ( strcmp(ifa->ifa_name, "en0") != 0 )
            {
                continue;
            }
            struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &(sa->sin_addr), addrBuf, sizeof(addrBuf));
            break;
        }
        freeifaddrs(ifaddr);
    }
    return std::string(addrBuf);
}

NSString *EsfUtils::GetProcessName(const es_message_t *msg)
{
    if ( !msg || !msg->process )
    {
        return nil;
    }

    pid_t               pid = audit_token_to_pid(msg->process->audit_token);
    struct proc_bsdinfo info;

    if ( proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) <= 0 )
    {
        return nil;
    }

    // pbi_name 是 BSD 层注册的进程名
    return [NSString stringWithUTF8String:info.pbi_name];
}

NSString *EsfUtils::GetProcessPath(const es_message_t *msg)
{
    if ( !msg )
    {
        return nil;
    }

    // 只处理 exec 事件
    if ( msg->event_type != ES_EVENT_TYPE_AUTH_EXEC && msg->event_type != ES_EVENT_TYPE_NOTIFY_EXEC )
    {
        return nil;
    }

    const es_process_t *proc = msg->event.exec.target;
    if ( !proc || !proc->executable || !proc->executable->path.data )
    {
        return nil;
    }

    return [NSString stringWithUTF8String:proc->executable->path.data];
}

pid_t EsfUtils::GetPid(const es_message_t *msg)  // 获取事件发生的进程id
{
    if ( msg == nullptr || msg->process == nullptr )
    {
        return -1;
    }
    const audit_token_t token = msg->process->audit_token;
    pid_t               pid   = audit_token_to_pid(token);
    return pid;
}

pid_t EsfUtils::GetPPid(const es_message_t *msg)  // 获取事件发生的父进程id
{
    if ( msg == nullptr || msg->process == nullptr )
    {
        return -1;
    }
    pid_t ppid = msg->process->ppid;
    return (ppid < 0) ? -1 : ppid;
}

uid_t EsfUtils::GetUid(const es_message_t *msg)  // 获取事件进程的实际用户 ID
{
    if ( msg == nullptr || msg->process == nullptr )
    {
        return -1;
    }

    const audit_token_t token = msg->process->audit_token;
    uid_t               uid   = audit_token_to_ruid(token);
    return uid;
}

NSString *EsfUtils::GetUser(const es_message_t *msg)  // 获取事件进程的实际用户名
{
    if ( msg == nullptr || msg->process == nullptr )
    {
        return @"unknown";  // 返回常量字符串，不需要释放
    }

    @autoreleasepool
    {
        // 获取触发事件进程的实际用户 ID
        uid_t uid = GetUid(msg);

        // 转换为用户名
        struct passwd *pw = getpwuid(uid);
        if ( !pw || !pw->pw_name )
        {
            return @"unknown";  // 安全兜底
        }

        // NSString stringWithUTF8String 会返回 autorelease 对象
        NSString *userName = [NSString stringWithUTF8String:pw->pw_name];
        if ( !userName )
        {
            return @"unknown";  // 转换失败兜底
        }

        // 返回 autorelease 对象，外层 autoreleasepool 会托管它的释放
        return userName;
    }
}

time_t EsfUtils::GetUtcTime(const es_message_t *msg)  // 获取事件发生的UTC时间
{
    if ( msg == nullptr || msg->process == nullptr )
    {
        return 0;
    }

    return msg->time.tv_sec;
}

time_t EsfUtils::GetCreateTime(const es_message_t *msg)  // 触发事件进程的创建时间
{
    if ( msg == nullptr || msg->process == nullptr )
    {
        return 0;
    }

    time_t seconds = msg->process->start_time.tv_sec;
    return (seconds > 0) ? static_cast<uint64_t>(seconds) : 0;
}

NSString *EsfUtils::GetCMD(const es_message_t *msg)
{
    if ( !msg || !msg->process )
    {
        return nil;
    }

    // 从 audit_token 里取 PID
    pid_t pid = audit_token_to_pid(msg->process->audit_token);
    if ( pid <= 0 )
    {
        return nil;
    }

    // sysctl MIB
    int mib[3] = { CTL_KERN, KERN_PROCARGS2, pid };

    size_t argmax = 0;
    if ( sysctl(mib, 3, NULL, &argmax, NULL, 0) == -1 )
    {
        return nil;
    }

    char *procargs = (char *)malloc(argmax);
    if ( !procargs )
    {
        return nil;
    }

    if ( sysctl(mib, 3, procargs, &argmax, NULL, 0) == -1 )
    {
        free(procargs);
        return nil;
    }

    // 取 argc
    int argc = 0;
    memcpy(&argc, procargs, sizeof(argc));
    char *p   = procargs + sizeof(argc);
    char *end = procargs + argmax;

    // 跳过 exec path
    while ( p < end && *p != '\0' )
    {
        p++;
    }
    while ( p < end && *p == '\0' )
    {
        p++;
    }

    // argv[0..argc-1]
    NSMutableArray<NSString *> *argvList = [NSMutableArray array];
    for ( int i = 0; i < argc && p < end; i++ )
    {
        NSString *arg = [NSString stringWithUTF8String:p];
        if ( arg )
        {
            [argvList addObject:arg];
        }
        p += strlen(p) + 1;
    }

    free(procargs);

    if ( argvList.count == 0 )
    {
        return nil;
    }

    // 拼接成完整命令行
    return [argvList componentsJoinedByString:@" "];
}

NSString *EsfUtils::GetPWD(const es_message_t *msg)  // 触发事件进程工作目录
{
    if ( !msg || !msg->process )
    {
        return nil;
    }

    pid_t pid = audit_token_to_pid(msg->process->audit_token);
    if ( pid <= 0 )
    {
        return nil;
    }

    struct proc_vnodepathinfo vnodeinfo;
    if ( proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &vnodeinfo, sizeof(vnodeinfo)) <= 0 )
    {
        return nil;
    }

    return [NSString stringWithUTF8String:vnodeinfo.pvi_cdir.vip_path];
}

uint64_t EsfUtils::GetFileSize(const es_message_t *msg)  // 获取触发事件进程的程序文件大小
{
    if ( !msg || !msg->process || !msg->process->executable )
    {
        return 0;
    }

    const es_file_t *exeFile = msg->process->executable;

    // es_string_token_t 不一定以 '\0' 结尾，需要手动处理
    char   path[PATH_MAX] = { 0 };
    size_t len            = exeFile->path.length;
    if ( len >= PATH_MAX )
    {
        len = PATH_MAX - 1;
    }
    memcpy(path, exeFile->path.data, len);
    path[len] = '\0';

    struct stat st {};
    if ( stat(path, &st) == 0 )
    {
        return (uint64_t)st.st_size;
    }

    return 0;
}

NSString *EsfUtils::GetSHA256(const es_message_t *msg)
{
    if ( !msg || !msg->process || !msg->process->executable )
    {
        return nil;
    }

    // 拿到进程可执行文件路径
    const es_file_t *exeFile = msg->process->executable;
    size_t           len     = exeFile->path.length;
    if ( len == 0 )
    {
        return nil;
    }
    char path[PATH_MAX] = { 0 };
    if ( len >= PATH_MAX )
    {
        len = PATH_MAX - 1;
    }
    memcpy(path, exeFile->path.data, len);

    // 打开文件计算 SHA256
    FILE *fp = fopen(path, "rb");
    if ( !fp )
    {
        return nil;
    }

    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);

    unsigned char buffer[4096];
    size_t        bytesRead;
    while ( (bytesRead = fread(buffer, 1, sizeof(buffer), fp)) > 0 )
    {
        CC_SHA256_Update(&ctx, buffer, (CC_LONG)bytesRead);
    }
    fclose(fp);

    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(hash, &ctx);

    // 转 hex string
    NSMutableString *hashString = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for ( int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++ )
    {
        [hashString appendFormat:@"%02x", hash[i]];
    }

    return hashString;
}

NSString *EsfUtils::GetGUID(const es_message_t *msg)
{
    if ( !msg || !msg->process )
    {
        return @"";
    }

    // 获取 PID、PPID、进程启动时间
    pid_t pid   = audit_token_to_pid(msg->process->audit_token);
    pid_t ppid  = msg->process->ppid;
    int   ctime = (int)msg->process->start_time.tv_sec;

    if ( pid <= 0 )
    {
        return @"";
    }

    // --- 获取进程镜像路径 ---
    char procPath[PATH_MAX] = { 0 };
    if ( proc_pidpath(pid, procPath, sizeof(procPath)) <= 0 )
    {
        procPath[0] = '\0';
    }

    // --- 获取硬件 UUID ---
    char                hardwareUUID[128] = { 0 };
    io_registry_entry_t ioRegistryRoot    = IORegistryEntryFromPath(kIOMainPortDefault, "IOService:/");
    if ( ioRegistryRoot )
    {
        CFTypeRef uuidCF =
                IORegistryEntryCreateCFProperty(ioRegistryRoot, CFSTR("IOPlatformUUID"), kCFAllocatorDefault, 0);
        IOObjectRelease(ioRegistryRoot);
        if ( uuidCF && CFGetTypeID(uuidCF) == CFStringGetTypeID() )
        {
            CFStringRef cfStr = (CFStringRef)uuidCF;
            CFStringGetCString(cfStr, hardwareUUID, sizeof(hardwareUUID), kCFStringEncodingUTF8);
        }
        if ( uuidCF )
        {
            CFRelease(uuidCF);
        }
    }

    // --- 拼接唯一标识字符串 ---
    char inputString[PATH_MAX + 256] = { 0 };
    snprintf(inputString, sizeof(inputString), "%d|%d|%d|%s|%s", pid, ppid, ctime, procPath, hardwareUUID);

    // --- 计算 SHA256 ---
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256((const unsigned char *)inputString, (CC_LONG)strlen(inputString), hash);

    // --- 转成 NSString ---
    NSMutableString *guid = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for ( int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++ )
    {
        [guid appendFormat:@"%02x", hash[i]];
    }

    return guid;
}
