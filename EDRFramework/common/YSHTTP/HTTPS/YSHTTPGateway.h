//
//  HTTPGateway.h
//  Garden
//
//  Created by chenhanrong on 2022/11/11.
//

#import <Foundation/Foundation.h>
#import "YSHTTPRequest.h"
#import "YSHTTPResponse.h"
#import "../../Consts.h"

NS_ASSUME_NONNULL_BEGIN

@class YSHTTPRequest;
@class YSHTTPResponse;

typedef void (^YSHTTPRequestSuccessBlock)(YSHTTPResponse *response);
typedef void (^YSHTTPRequestFailureBlock)(YSHTTPResponse *response);


@interface YSHTTPGateway : NSObject

@property (nonatomic,strong)  id  rootCert;

+(NSSet *)getSHA1Set;

+(NSURLSessionAuthChallengeDisposition)vaildCertWithSession:(NSURLSession *)session challenge:(NSURLAuthenticationChallenge *)challenge credential:( NSURLCredential *__autoreleasing *)credential;

+(NSURLSessionAuthChallengeDisposition (^)(NSURLSession *session, NSURLAuthenticationChallenge *challenge, NSURLCredential * _Nullable __autoreleasing * _Nullable credential))getCertVeryBlock;

+ (YSHTTPGateway *)instance;

/**
 * 设置网关地址
 */
- (void)setupWithHost:(NSString *)host;

/**
 * 设置http header
 */
- (void)setupHeaderFields:(NSDictionary *)header;

/**
 * 获取当前网关环境
 */
- (NSString *)getCurrentHttpApiEnv;
/**
 * 删除token
 */
-(void)removeToken;
/**
 * 开始一个HTTP请求
 */
- (void)startRequest:(YSHTTPRequest*)request
        successBlock:(YSHTTPRequestSuccessBlock)successBlock
        failureBlock:(YSHTTPRequestFailureBlock)failureBlock;
/**
 * 获取当前http头
 */
-(NSDictionary *)getHeaderFileds;
@end

NS_ASSUME_NONNULL_END
