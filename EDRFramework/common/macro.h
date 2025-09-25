#ifndef MACRO_H
#define MACRO_H

#pragma mark  -Length
#define USER_LENGTH         32
#define SIGNERNAME_LENGTH   128
#define SHA256_LENGTH       65
#define COMMANDLINE_LENGTH  4096
#define PROCESS_LENGTH_1024 1024
#define PROCESS_LENGTH_4096 4096


#pragma mark -YunShuCommon
#define kYunshuConfigUserInfoPath               @"/opt/.yunshu/config/agent_config"
// FILTERRULE_PATH 已移除硬编码，改为使用 SystemUtils::GetConfigFilePath("filterjson.cfg")


#endif
