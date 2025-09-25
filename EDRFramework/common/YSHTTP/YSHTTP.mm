#include <CommonCrypto/CommonCrypto.h>
#include <iostream>

#include "YSHTTP.h"
#include "HTTPS/YSHTTPGateway.h"

#define SafeString(x) x ?: @""

NSString * YSCODEUtils::getUUID()
{
    NSString *ret = nil;
    io_service_t platformExpert;
    platformExpert = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOPlatformExpertDevice"));

    if (platformExpert) {
        CFTypeRef serialNumberAsCFString;
        serialNumberAsCFString = IORegistryEntryCreateCFProperty(platformExpert, CFSTR("IOPlatformUUID"), kCFAllocatorDefault, 0);
        if (serialNumberAsCFString) {
            ret = CFBridgingRelease(serialNumberAsCFString);
        }
        IOObjectRelease(platformExpert);
    }
    return ret;
}

NSString *YSCODEUtils::getYunshuVersion()
{
    NSString *brizooInfoPlistPath = @"";
#if SDK  || DLP_ONLY
        NSArray *supportSearch = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSSystemDomainMask, YES);
        NSString *brizooDir =[supportSearch.firstObject stringByAppendingPathComponent:@"Brizoo/Yunshu.app"];
        brizooDir = [NSString stringWithFormat:@"%@/Contents/Info.plist", brizooDir];
        brizooInfoPlistPath = brizooDir;
        DDLogInfo(@"daemon, Brizoo app infoPlist path: %@", brizooDir);
#else
        brizooInfoPlistPath = @"/Library/Application Support/Yunshu/Yunshu.app/Contents/Info.plist";
#endif
    
    NSDictionary *infos = [NSDictionary dictionaryWithContentsOfFile:brizooInfoPlistPath];
    NSString *buildVersion = infos[@"CFBundleVersion"];
    return buildVersion;
}

NSString *YSCODEUtils::getOSVersion()
{
    NSOperatingSystemVersion os = [[NSProcessInfo processInfo] operatingSystemVersion];
    NSString *osVersion;
    osVersion = [NSString stringWithFormat:@"%ld.%ld.%ld", os.majorVersion, os.minorVersion, os.patchVersion];
    return osVersion;
}

NSData *YSCODEUtils::toJsonData(NSArray *array)
{
    NSError *error = nil;
    @try
    {
        NSData *data = [NSJSONSerialization dataWithJSONObject:array options:kNilOptions error:&error];
        return error ? nil : data;
    }
    @catch ( NSException *exception )
    {
        error = [NSError errorWithDomain:@"JSONSerialization" code:-1 userInfo:@ { @"exception" : exception }];
        return nil;
    }
}

// AES 解密
NSData *YSCODEUtils::aes128ParmDecryptWithKey(NSString *key, NSData *text)
{
    char keyPtr[kCCKeySizeAES128 + 1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    NSUInteger dataLength = [text length];
    size_t     bufferSize = dataLength + kCCBlockSizeAES128;
    void      *buffer     = malloc(bufferSize);
    NSData    *data       = nil;
    if ( buffer )
    {
        size_t          numBytesDecrypted = 0;
        void           *iv                = keyPtr;
        CCCryptorStatus cryptStatus =
                CCCrypt(kCCDecrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding, keyPtr, kCCBlockSizeAES128, iv,
                        [text bytes], dataLength, buffer, bufferSize, &numBytesDecrypted);
        if ( cryptStatus == kCCSuccess )
        {
            data = [NSData dataWithBytes:buffer length:numBytesDecrypted];
        }
        free(buffer);
    }
    return data;
}

NSData *YSCODEUtils::base64DecodeWithString(NSString *sourceString)
{
    if ( !sourceString )
    {
        return nil;
    }
    // 解密
    NSData *resultData = [[NSData alloc] initWithBase64EncodedString:sourceString
                                                             options:NSDataBase64DecodingIgnoreUnknownCharacters];
    //    NSLog(@"%@",resultData);
    return resultData;
}

NSString *YSCODEUtils::decryptConfig(NSString *path)
{
    @autoreleasepool
    {
        NSData   *fileData  = [NSData dataWithContentsOfFile:path];
        NSData   *kd        = base64DecodeWithString(@"eXVuc2h1YWdlbnQ=");
        NSString *k         = [[NSString alloc] initWithData:kd encoding:NSUTF8StringEncoding];
        NSData   *pDate     = aes128ParmDecryptWithKey(k, fileData);
        NSString *decString = [[NSString alloc] initWithData:pDate encoding:NSUTF8StringEncoding];
        return decString;
    }
}
@implementation YSHttpClient

+ (void)updateGatewayWithToken:(NSString*)token domain:(NSString*)domain corpCode:(NSString*)corpCode
{
    YSHTTPGateway* service = YSHTTPGateway.instance;
    [service setupWithHost:domain];
    NSString* devSN = SafeString(YSCODEUtils::getUUID());
    NSString* AppVersion = SafeString(YSCODEUtils::getYunshuVersion());
    NSString* OsVersion = SafeString(YSCODEUtils::getOSVersion());
    if (token.length > 0) {
        NSString* hostToken= @"__Host-brizoo-token";
        NSString *cookie = [NSString stringWithFormat:@"%@=%@;%@=%@;%@=%@",hostToken,token,@"devSerialId",devSN,@"osType", @"mac"];
        NSString *Authorization = [NSString stringWithFormat:@"Bearer %@", token];
        [service setupHeaderFields:@{@"Cookie" : cookie,@"Authorization" : Authorization}];
    }
    
    NSDictionary* headers = @{
        @"OsType" : @"mac",
        @"OsVersion" :OsVersion,
        @"DevSN" : devSN,
        @"AppVersion" : AppVersion,
        @"corp_code" : SafeString(corpCode),
        @"supported_features": @"4",
    };
    [service setupHeaderFields:headers];
}

+ (void)reportEDRLog:(NSData *)data remoteURL:(NSString *)remoteURL complate:(void (^)(NSError *error))complate
{
    YSHTTPGateway *service = YSHTTPGateway.instance;
    YSHTTPRequest *request = [[YSHTTPRequest alloc] init];
    request.method         = YSHTTPMethodPOST_Body;
    request.URL            = remoteURL;
    request.apiName        = @"/api/agent/v1/edr/audit_log/report_logs";
    request.body           = data;
    [service startRequest:request
            successBlock:^(YSHTTPResponse *response) {
                complate(nil);
            }
            failureBlock:^(YSHTTPResponse *response) {
                complate(response.error);
            }];
}

+ (void)reportEDREvent:(NSData *)data remoteURL:(NSString *)remoteURL complate:(void (^)(NSError *error))complate
{
    YSHTTPGateway *service = YSHTTPGateway.instance;
    YSHTTPRequest *request = [[YSHTTPRequest alloc] init];
    request.method         = YSHTTPMethodPOST_Body;
    request.URL            = remoteURL;
    request.apiName        = @"/api/agent/v1/edr/threat_detect/report_threat";
    request.body           = data;
    [service startRequest:request
            successBlock:^(YSHTTPResponse *response) {
                complate(nil);
            }
            failureBlock:^(YSHTTPResponse *response) {
                complate(response.error);
            }];
}

@end
