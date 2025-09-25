#ifndef CODEUTILS_H
#define CODEUTILS_H

#pragma mark -YunShuCode
namespace CODEUtils
{
NSString * GetYunshuVersion();
NSString * GetOSVersion();
NSData   * ToJsonData(NSArray *array);
NSData   * Base64DecodeWithString(NSString *sourceString);
NSData   * Aes128ParmDecryptWithKey(NSString *key, NSData *text);
NSString * DecryptConfig(NSString *path);
}

#endif
