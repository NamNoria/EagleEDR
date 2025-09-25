#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class YSHTTPRequest;

@interface YSHTTPResponse : NSObject

@property (nonatomic, assign) BOOL succeed;
@property (nonatomic, copy) NSString* configVersion;
@property (nonatomic, strong) id error; // BZHTTPError
@property (nonatomic, strong) id data;

@end

NS_ASSUME_NONNULL_END
