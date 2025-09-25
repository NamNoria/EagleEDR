#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSUInteger, YSHTTPMethod) {
    YSHTTPMethodGET,
    YSHTTPMethodPOST,
    YSHTTPMethodPOST_MultiPart,
    YSHTTPMethodPOST_Body,
    YSHTTPMethodPUT_Body,
};


@class YSHTTPResponse;

@interface YSHTTPRequest : NSObject

@property (nonatomic, copy) NSString *apiName;
@property (nonatomic, copy) NSString *URL; // 直接完整URL调用，如果设置URL，不使用APIName
@property (nonatomic, strong) NSDictionary *paramters;
@property (nonatomic, strong) NSData *body;
@property (nonatomic, strong) NSString *filename;
@property (nonatomic, strong) NSString *mimeType;
@property (nonatomic, strong) NSString *formDataName;

@property (nonatomic, assign) YSHTTPMethod method;
@property (nonatomic, strong) NSDictionary *extraHTTPHeader;

@end

NS_ASSUME_NONNULL_END
