#ifndef YSHTTP_H
#define YSHTTP_H

#import <Foundation/Foundation.h>

namespace YSCODEUtils
{
NSString * getUUID();
NSString *getYunshuVersion();
NSString *getOSVersion();
NSData   *toJsonData(NSArray *array);
NSData   *base64DecodeWithString(NSString *sourceString);
NSData   *aes128ParmDecryptWithKey(NSString *key, NSData *text);
NSString *decryptConfig(NSString *path);
}

@interface YSHttpClient: NSObject
/// @brief 上报EDR日志
/// @param data 事件内容
/// @param remoteURL 接口地址
/// @param complate 回调block。
+ (void)reportEDRLog:(NSData *)data remoteURL:(NSString *)remoteURL complate:(void (^)(NSError *error))complate;

/// @brief 上报EDR事件
/// @param data 事件内容
/// @param remoteURL 接口地址
/// @param complate 回调block。
+ (void)reportEDREvent:(NSData *)data remoteURL:(NSString *)remoteURL complate:(void (^)(NSError *error))complate;

/// @brief 更新http接口参数
/// @param token 用户认证成功后的凭证。
/// @param domain 当前网关地址。
/// @param corpCode 企业标识符。
+ (void)updateGatewayWithToken:(NSString*)token domain:(NSString*)domain corpCode:(NSString*)corpCode;

@end

#endif

