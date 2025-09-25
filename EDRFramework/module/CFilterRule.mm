#include <dlfcn.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include <chrono>
#include <Foundation/Foundation.h>

#include "CFilterRule.h"
#include "../3rd/cJSON.h"
#include "../common/macro.h"
#include "../common/CodeUtils.h"
#include "../common/SystemUtils.h"
#include "../common/Logger.h"

bool            CFilterRule::m_libInited        = false;
bool            CFilterRule::m_configLoaded     = false;
void           *CFilterRule::m_libHandle        = nullptr;
init_fn         CFilterRule::m_initengine_macos = nullptr;
onfilecreate_fn CFilterRule::m_onfilecreate     = nullptr;
onfilerename_fn CFilterRule::m_onfilerename     = nullptr;
onprocstart_fn  CFilterRule::m_onprocstart      = nullptr;
freeresult_fn   CFilterRule::m_freeresult       = nullptr;

extern uint64_t gSilentStartUtc;  // 全局静默开始时间

bool SilentProcessRule::Matches(const std::string &procName) const
{
    const uint64_t now = static_cast<uint64_t>(time(nullptr));

    // 确定静默开始时间：规则未设置则用全局的
    const uint64_t effectiveStart = (silentStartUtc == 0) ? gSilentStartUtc : silentStartUtc;

    // 还没到静默开始时间
    if ( now < effectiveStart )
    {
        return false;
    }

    // 静默持续时间为 0 表示永久静默
    if ( silentDuration == 0 || (now - effectiveStart) < silentDuration )
    {
        // 进程名必须匹配
        return process == procName;
    }

    // 超过静默时间
    return false;
}

void FilterRuleData::Clear()
{
    version.clear();
    lastUpdated = 0;
    silentProcesses.clear();
    fileFilters.clear();
    // netFilters.clear();
}

CFilterRule::CFilterRule()
{
}

CFilterRule::~CFilterRule()
{
    if ( m_libHandle )
    {
        dlclose(m_libHandle);
        m_libHandle = nullptr;
    }
}

CFilterRule *CFilterRule::shared()
{
    static CFilterRule instance;
    return &instance;
}

bool CFilterRule::Initialize()
{
    std::string configPath = SystemUtils::GetConfigFilePath("filterjson.cfg");
    if (!configPath.empty()) {
        loadConfigFile(configPath);
    } else {
        LOG_ERROR("Failed to locate filterjson.cfg config file");
    }
    static std::once_flag libFlag;
    std::call_once(libFlag,
                   []()
                   {
                        auto start = std::chrono::high_resolution_clock::now();
                        LOG_INFO("Starting rule engine initialization...");

                        // 直接通过 NSBundle 获取 EDRFramework 的路径
                        NSBundle *frameworkBundle = [NSBundle bundleWithIdentifier:@"com.yourcompany.EDRFramework"];
                        if (!frameworkBundle) {
                            // 如果通过 identifier 找不到，尝试通过路径查找
                            NSString *mainBundlePath = [[NSBundle mainBundle] bundlePath];
                            NSString *frameworksPath = [mainBundlePath stringByAppendingPathComponent:@"Contents/Frameworks"];
                            NSString *edrFrameworkPath = [frameworksPath stringByAppendingPathComponent:@"EDRFramework"];
                            frameworkBundle = [NSBundle bundleWithPath:edrFrameworkPath];
                        }

                        if (frameworkBundle) {
                            NSString *libPath = [frameworkBundle pathForResource:@"librule_engine_lib" ofType:@"dylib" inDirectory:@"Frameworks"];
                            if (!libPath) {
                                // 如果通过资源方式找不到，直接构建路径
                                NSString *frameworksPath = [frameworkBundle.bundlePath stringByAppendingPathComponent:@"Frameworks"];
                                libPath = [frameworksPath stringByAppendingPathComponent:@"librule_engine_lib.dylib"];
                            }

                            LOG_INFO("EDRFramework bundle path: {}", frameworkBundle.bundlePath.UTF8String);
                            LOG_INFO("Target library path: {}", libPath.UTF8String);

                            // 检查文件是否存在
                            if (![[NSFileManager defaultManager] fileExistsAtPath:libPath]) {
                                LOG_ERROR("Rule engine library file does not exist: {}", libPath.UTF8String);
                                return;
                            }

                            LOG_INFO("Loading rule engine library: {}", libPath.UTF8String);
                            m_libHandle = dlopen(libPath.UTF8String, RTLD_LAZY);
                        } else {
                            LOG_ERROR("Could not find EDRFramework bundle");
                            return;
                        }
//                       m_libHandle = dlopen("/Users/jt/Desktop/EDR/EDR/3rd/librule_engine_lib.dylib", RTLD_LAZY);
                       if ( !m_libHandle )
                       {
                           LOG_ERROR("Failed to load rule engine library: {}", dlerror());
                           return;
                       }

                       LOG_INFO("Rule engine library loaded successfully");
                       m_initengine_macos = (init_fn)dlsym(m_libHandle, "initengine_macos");
                       m_onfilecreate     = (onfilecreate_fn)dlsym(m_libHandle, "onfilecreate");
                       m_onfilerename     = (onfilerename_fn)dlsym(m_libHandle, "onfilerename");
                       m_onprocstart      = (onprocstart_fn)dlsym(m_libHandle, "onprocstart");
                       m_freeresult       = (freeresult_fn)dlsym(m_libHandle, "freeresult");

                       // 详细的符号解析错误检查
                       if (!m_initengine_macos) {
                           LOG_ERROR("Failed to resolve symbol 'initengine_macos': {}", dlerror() ? dlerror() : "Unknown error");
                       }
                       if (!m_onfilecreate) {
                           LOG_ERROR("Failed to resolve symbol 'onfilecreate': {}", dlerror() ? dlerror() : "Unknown error");
                       }
                       if (!m_onfilerename) {
                           LOG_ERROR("Failed to resolve symbol 'onfilerename': {}", dlerror() ? dlerror() : "Unknown error");
                       }
                       if (!m_onprocstart) {
                           LOG_ERROR("Failed to resolve symbol 'onprocstart': {}", dlerror() ? dlerror() : "Unknown error");
                       }
                       if (!m_freeresult) {
                           LOG_WARN("Failed to resolve symbol 'freeresult': {}", dlerror() ? dlerror() : "Unknown error");
                       }

                       if ( !m_initengine_macos || !m_onfilecreate || !m_onfilerename || !m_onprocstart )
                       {
                           LOG_ERROR("Critical symbols missing in rule engine library, cannot proceed");
                           dlclose(m_libHandle);
                           m_libHandle = nullptr;
                           // 重置函数指针
                           m_initengine_macos = nullptr;
                           m_onfilecreate = nullptr;
                           m_onfilerename = nullptr;
                           m_onprocstart = nullptr;
                           m_freeresult = nullptr;
                           return;
                       }
                       // 初始化引擎
                       auto config_start = std::chrono::high_resolution_clock::now();
                       LOG_INFO("Decrypting config file: {}", [kYunshuConfigUserInfoPath UTF8String]);

                       NSString     *json     = CODEUtils::DecryptConfig(kYunshuConfigUserInfoPath);
                       NSData       *jsonData = [json dataUsingEncoding:NSUTF8StringEncoding];
                       NSError      *err      = nil;
                       NSDictionary *userInfo = [NSJSONSerialization JSONObjectWithData:jsonData
                                                                                options:NSJSONReadingMutableContainers
                                                                                  error:&err];

                       auto config_end = std::chrono::high_resolution_clock::now();
                       auto config_duration = std::chrono::duration_cast<std::chrono::milliseconds>(config_end - config_start);
                       LOG_INFO("Config decryption completed in {}ms", config_duration.count());
                       if ( err )
                       {
                           LOG_ERROR("Config JSON parse failed: {}, config_path={}", [[err description] UTF8String], [kYunshuConfigUserInfoPath UTF8String]);
                           userInfo = @ {};
                       }
                       NSString   *token       = [userInfo objectForKey:@"token"];
                       NSString   *server_host = [userInfo objectForKey:@"apiDomain"];

                       // 检查关键参数是否有效，避免崩溃
                       if (!token || ![token isKindOfClass:[NSString class]] || token.length == 0) {
                           LOG_ERROR("Engine initialization failed: token is invalid or empty, config_path={}", [kYunshuConfigUserInfoPath UTF8String]);
                           return;
                       }

                       if (!server_host || ![server_host isKindOfClass:[NSString class]] || server_host.length == 0) {
                           LOG_ERROR("Engine initialization failed: server_host is invalid or empty, config_path={}", [kYunshuConfigUserInfoPath UTF8String]);
                           return;
                       }

                       const char *pToken      = [token UTF8String];
                       const char *pServerHost = [server_host UTF8String];

                       // 再次检查转换后的 C 字符串
                       if (!pToken || !pServerHost) {
                           LOG_ERROR("Engine initialization failed: unable to convert config strings to UTF8");
                           return;
                       }

                       auto engine_start = std::chrono::high_resolution_clock::now();
                       LOG_INFO("Initializing rule engine with server: {}", pServerHost);

                       bool        bInit       = m_initengine_macos ? m_initengine_macos(pToken, pServerHost) : false;

                       auto engine_end = std::chrono::high_resolution_clock::now();
                       auto engine_duration = std::chrono::duration_cast<std::chrono::milliseconds>(engine_end - engine_start);

                       if ( bInit )
                       {
                           LOG_INFO("Rule engine initialized successfully in {}ms, token_len={}, server_host={}", engine_duration.count(), strlen(pToken), pServerHost);
                           m_libInited = true;
                       }
                       else
                       {
                           LOG_ERROR("Rule engine initialization failed in {}ms, token_len={}, server_host={}", engine_duration.count(), strlen(pToken), pServerHost);
                       }

                       auto total_end = std::chrono::high_resolution_clock::now();
                       auto total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(total_end - start);
                       LOG_INFO("Rule engine setup completed in {}ms total", total_duration.count());
                   });
    return true;
}

void CFilterRule::UnInitialize()
{
    // 库清理环境（预支持热更新逻辑，瀚榕：不太好做，暂时不考虑）
    if ( m_libInited )
    {
        m_libInited = false;
    }
}

bool CFilterRule::loadConfigFile(const std::string &configPath)
{
    if ( m_configLoaded )
    {
        return true;
    }

    std::ifstream file(configPath);
    if ( !file.is_open() )
    {
        LOG_ERROR("Cannot open config file: {}", configPath);
        return false;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    file.close();

    cJSON *root = cJSON_Parse(buffer.str().c_str());
    if ( !root )
    {
        LOG_ERROR("JSON parsing failed: {}, config_path={}", cJSON_GetErrorPtr(), configPath);
        return false;
    }

    bool success = ParseConfig(root);
    cJSON_Delete(root);

    if ( success )
    {
        m_configPath   = configPath;
        m_configLoaded = true;
        LOG_INFO("Config file loaded successfully: {}", configPath);
    }
    return success;
}

bool CFilterRule::ParseConfig(const cJSON *root)
{
    if ( root == nullptr || !cJSON_IsObject(root) )
    {
        return false;
    }

    m_rule.Clear();

    // 1. 解析 version
    const cJSON *verItem = cJSON_GetObjectItem(root, "version");
    if ( cJSON_IsString(verItem) )
    {
        m_rule.version = verItem->valuestring;
    }

    // 2. 解析 last_updated（需要从 ISO8601 转换成 UTC 秒）
    const cJSON *lastItem = cJSON_GetObjectItem(root, "last_updated");
    if ( cJSON_IsString(lastItem) )
    {
        // 格式固定 "YYYY-MM-DDTHH:MM:SSZ"
        struct tm tmUtc {};
        if ( strptime(lastItem->valuestring, "%Y-%m-%dT%H:%M:%SZ", &tmUtc) )
        {
            m_rule.lastUpdated = static_cast<uint64_t>(timegm(&tmUtc));
        }
    }

    // 3. 解析 silent_processes
    const cJSON *spArray = cJSON_GetObjectItem(root, "silent_processes");
    if ( cJSON_IsArray(spArray) )
    {
        cJSON *spItem = nullptr;
        cJSON_ArrayForEach(spItem, spArray)
        {
            if ( !cJSON_IsObject(spItem) )
            {
                continue;
            }

            SilentProcessRule spRule;

            const cJSON *procItem = cJSON_GetObjectItem(spItem, "process");
            if ( cJSON_IsString(procItem) )
            {
                spRule.process = procItem->valuestring;
            }

            const cJSON *pidItem = cJSON_GetObjectItem(spItem, "pid");
            if ( cJSON_IsString(pidItem) && strlen(pidItem->valuestring) > 0 )
            {
                spRule.pid = static_cast<pid_t>(atoi(pidItem->valuestring));
            }
            else
            {
                spRule.pid = 0;
            }

            const cJSON *ppidItem = cJSON_GetObjectItem(spItem, "ppid");
            if ( cJSON_IsString(ppidItem) && strlen(ppidItem->valuestring) > 0 )
            {
                spRule.ppid = static_cast<pid_t>(atoi(ppidItem->valuestring));
            }
            else
            {
                spRule.ppid = 0;
            }

            const cJSON *startItem = cJSON_GetObjectItem(spItem, "silent_start_utc");
            if ( cJSON_IsNumber(startItem) )
            {
                spRule.silentStartUtc = static_cast<uint64_t>(startItem->valuedouble);
            }

            const cJSON *durItem = cJSON_GetObjectItem(spItem, "silent_duration");
            if ( cJSON_IsNumber(durItem) )
            {
                spRule.silentDuration = static_cast<uint64_t>(durItem->valuedouble);
            }

            const cJSON *descItem = cJSON_GetObjectItem(spItem, "description");
            if ( cJSON_IsString(descItem) )
            {
                spRule.description = descItem->valuestring;
            }

            m_rule.silentProcesses.push_back(std::move(spRule));
        }
    }

    // 4. 解析 file_filters
    const cJSON *ffArray = cJSON_GetObjectItem(root, "file_filters");
    if ( cJSON_IsArray(ffArray) )
    {
        cJSON *ffItem = nullptr;
        cJSON_ArrayForEach(ffItem, ffArray)
        {
            if ( !cJSON_IsObject(ffItem) )
            {
                continue;
            }

            FileFilterRule ffRule;

            // 文件路径
            const cJSON *srcPathItem = cJSON_GetObjectItem(ffItem, "src_path");
            if ( cJSON_IsString(srcPathItem) )
            {
                ffRule.srcPath = srcPathItem->valuestring;
            }

            const cJSON *dstPathItem = cJSON_GetObjectItem(ffItem, "dst_path");
            if ( cJSON_IsString(dstPathItem) )
            {
                ffRule.dstPath = dstPathItem->valuestring;
            }

            // 静默开始时间（JSON 里没有，默认 0）
            const cJSON *startItem = cJSON_GetObjectItem(ffItem, "silent_start_utc");
            if ( cJSON_IsNumber(startItem) )
            {
                ffRule.silentStartUtc = static_cast<uint64_t>(startItem->valuedouble);
            }
            else
            {
                ffRule.silentStartUtc = 0;
            }

            // 静默持续时间（JSON 里没有，默认 0）
            const cJSON *durItem = cJSON_GetObjectItem(ffItem, "silent_duration");
            if ( cJSON_IsNumber(durItem) )
            {
                ffRule.silentDuration = static_cast<uint64_t>(durItem->valuedouble);
            }
            else
            {
                ffRule.silentDuration = 0;
            }

            // 描述（优先 reason）
            const cJSON *descItem = cJSON_GetObjectItem(ffItem, "reason");
            if ( cJSON_IsString(descItem) )
            {
                ffRule.description = descItem->valuestring;
            }
            else
            {
                const cJSON *desc2 = cJSON_GetObjectItem(ffItem, "description");
                if ( cJSON_IsString(desc2) )
                {
                    ffRule.description = desc2->valuestring;
                }
            }

            m_rule.fileFilters.push_back(std::move(ffRule));
        }
    }

    return true;
}

void CFilterRule::initRuleOnce() const
{
    std::call_once(m_initFlag,
                   [this]()
                   {
                       LOG_DEBUG("Initializing rule mapping once");
                       if ( !m_configLoaded && !m_configPath.empty() )
                       {
                           const_cast<CFilterRule *>(this)->loadConfigFile(m_configPath);
                       }

                       m_ruleMap[std::type_index(typeid(SilentProcessRule))] = &m_rule.silentProcesses;
                       m_ruleMap[std::type_index(typeid(FileFilterRule))]    = &m_rule.fileFilters;
                       // ruleMap[std::type_index(typeid(NetFilterRule))]     = &rule.netFilters;

                       LOG_INFO("Rule mapping initialization completed");
                   });
}

bool CFilterRule::IsConfigLoaded() const
{
    return m_configLoaded;
}

bool CFilterRule::IsLibraryLoaded() const
{
    return m_libHandle && m_libInited &&
           m_initengine_macos && m_onfilecreate &&
           m_onfilerename && m_onprocstart;
}

ActionStatus CFilterRule::FileRenameFilterAllow(FILE_RENAME_INFO *pEventInfo, THREAT_PROC_INFO *pProcInfo,
                                                std::string *outThreatInfo) const
{
    ActionStatus          retStatus = RULE_ACTION_PASS;
    const BehaviorResult *pResult   = nullptr;

    if (!IsLibraryLoaded()) {
        LOG_ERROR("Rule engine library is not properly loaded - cannot process file rename events");
        return RULE_ACTION_PASS;
    }

    if (!pEventInfo || !pProcInfo) {
        LOG_ERROR("Invalid parameters: pEventInfo={}, pProcInfo={}", (void*)pEventInfo, (void*)pProcInfo);
        return RULE_ACTION_PASS;
    }

    m_onfilerename("", pProcInfo, pEventInfo, &pResult);
    if ( pResult )
    {
        if ( outThreatInfo )
        {
            *outThreatInfo = pResult->threat_info ? pResult->threat_info : "";
        }
        retStatus = (ActionStatus)pResult->action;
        if ( m_freeresult )
        {
            m_freeresult(const_cast<BehaviorResult *>(pResult));
        }
    }
    else
    {
        LOG_WARN("Filter result is null, cannot process file rename event");
    }
    // 实际匹配规则逻辑可按需实现
    return retStatus;
}

ActionStatus CFilterRule::FileCreateFilterAllow(FILE_CREATE_INFO *pEventInfo, THREAT_PROC_INFO *pProcInfo,
                                                std::string *outThreatInfo) const
{
    ActionStatus          retStatus = RULE_ACTION_PASS;
    const BehaviorResult *pResult   = nullptr;

    if (!IsLibraryLoaded()) {
        LOG_ERROR("Rule engine library is not properly loaded - cannot process file create events");
        return RULE_ACTION_PASS;
    }

    if (!pEventInfo || !pProcInfo) {
        LOG_ERROR("Invalid parameters: pEventInfo={}, pProcInfo={}", (void*)pEventInfo, (void*)pProcInfo);
        return RULE_ACTION_PASS;
    }

    m_onfilecreate("", pProcInfo, pEventInfo, &pResult);
    if ( pResult )
    {
        if ( outThreatInfo )
        {
            *outThreatInfo = pResult->threat_info ? pResult->threat_info : "";
        }
        retStatus = (ActionStatus)pResult->action;
        if ( m_freeresult )
        {
            m_freeresult(const_cast<BehaviorResult *>(pResult));
        }
    }
    else
    {
        LOG_WARN("Filter result is null, cannot process file create event");
    }
    // 实际匹配规则逻辑可按需实现
    return retStatus;
}

ActionStatus CFilterRule::ProcessFilterAllow(THREAT_PROC_INFO *pEventInfo, THREAT_PROC_INFO *pParentInfo,
                                             std::string *outThreatInfo) const
{
    //    LOG_DEBUG("ProcessFilterAllow");
    ActionStatus          retStatus = RULE_ACTION_PASS;
    const BehaviorResult *pResult   = nullptr;

    if (!IsLibraryLoaded()) {
        LOG_ERROR("Rule engine library is not properly loaded - cannot process process start events");
        return RULE_ACTION_PASS;
    }

    if (!pEventInfo) {
        LOG_ERROR("Invalid parameter: pEventInfo is null");
        return RULE_ACTION_PASS;
    }

    m_onprocstart("", pParentInfo, pEventInfo, &pResult);
    if ( pResult )
    {
        if ( outThreatInfo )
        {
            *outThreatInfo = pResult->threat_info ? pResult->threat_info : "";
        }
        retStatus = (ActionStatus)pResult->action;
        // 释放BehaviorResult
        if ( m_freeresult )
        {
            m_freeresult(const_cast<BehaviorResult *>(pResult));
        }
    }
    else
    {
        LOG_WARN("Filter result is null, cannot process process start event");
    }
    //    LOG_DEBUG("ProcessFilterAllow end");
    return retStatus;
}
