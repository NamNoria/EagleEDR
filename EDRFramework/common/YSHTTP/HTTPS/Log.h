#ifndef log_h
#define log_h

#define DDLogInfo
#define DDLogDebug
#define DDLogError
#if 0
#import <Foundation/Foundation.h>
#import <CocoaLumberjack/CocoaLumberjack.h>

extern DDLogLevel ddLogLevel;

void initLumberjackLogger(NSString *logDir);

@interface CustomLogFormatter : NSObject <DDLogFormatter>{
    NSDateFormatter *dateFormatter;
}
@end
#endif
#endif /* log_h */
