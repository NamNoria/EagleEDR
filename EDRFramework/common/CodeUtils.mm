#include <CommonCrypto/CommonCrypto.h>
#include <Foundation/Foundation.h>

#include "CodeUtils.h"

#pragma mark -YunShuCode

NSString *CODEUtils::GetYunshuVersion()
{
    NSString *brizooInfoPlistPath = @"";
#if SDK || DLP_ONLY
    NSArray *supportSearch =
            NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSSystemDomainMask, YES);
    NSString *brizooDir = [supportSearch.firstObject stringByAppendingPathComponent:@"Brizoo/Yunshu.app"];
    brizooDir           = [NSString stringWithFormat:@"%@/Contents/Info.plist", brizooDir];
    brizooInfoPlistPath = brizooDir;
    DDLogInfo(@"daemon, Brizoo app infoPlist path: %@", brizooDir);
#else
    brizooInfoPlistPath = @"/Library/Application Support/Yunshu/Yunshu.app/Contents/Info.plist";
#endif

    NSDictionary *infos        = [NSDictionary dictionaryWithContentsOfFile:brizooInfoPlistPath];
    NSString     *buildVersion = infos[@"CFBundleVersion"];
    return buildVersion;
}

NSString *CODEUtils::GetOSVersion()
{
    NSOperatingSystemVersion os = [[NSProcessInfo processInfo] operatingSystemVersion];
    NSString                *osVersion;
    osVersion = [NSString stringWithFormat:@"%ld.%ld.%ld", os.majorVersion, os.minorVersion, os.patchVersion];
    return osVersion;
}

NSData *CODEUtils::ToJsonData(NSArray *array)
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

NSData *CODEUtils::Base64DecodeWithString(NSString *sourceString)
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

NSData *CODEUtils::Aes128ParmDecryptWithKey(NSString *key, NSData *text)
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

NSString *CODEUtils::DecryptConfig(NSString *path)
{
    @autoreleasepool
    {
        NSData   *fileData  = [NSData dataWithContentsOfFile:path];
        NSData   *kd        = Base64DecodeWithString(@"eXVuc2h1YWdlbnQ=");
        NSString *k         = [[NSString alloc] initWithData:kd encoding:NSUTF8StringEncoding];
        NSData   *pDate     = Aes128ParmDecryptWithKey(k, fileData);
        NSString *decString = [[NSString alloc] initWithData:pDate encoding:NSUTF8StringEncoding];
        return decString;
    }
}
