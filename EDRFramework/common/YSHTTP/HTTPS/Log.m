#import "Log.h"

#if 0
DDLogLevel ddLogLevel = DDLogLevelInfo;

void initLumberjackLogger(NSString *logDir)
{
    DDLogFileManagerDefault *fm = [[DDLogFileManagerDefault alloc] initWithLogsDirectory:logDir];
    
    DDFileLogger *fileLogger = [[DDFileLogger alloc] initWithLogFileManager: fm];
    fileLogger.rollingFrequency = 60*60*24;
    fileLogger.logFileManager.logFilesDiskQuota = 30*1024*1024;
    fileLogger.logFileManager.maximumNumberOfLogFiles = 7;
    fileLogger.maximumFileSize = 10*1024*1024;
    fileLogger.logFormatter = [[CustomLogFormatter alloc]init];
    
    if(@available(macOS 10.12, *)){
        [DDLog addLogger:[DDOSLogger sharedInstance]];
    }else{
        [DDLog addLogger:[DDTTYLogger sharedInstance]];
    }
    [DDLog addLogger:fileLogger];
    return;
}

@implementation CustomLogFormatter

- (id)init {
    if((self = [super init])) {
        dateFormatter = [[NSDateFormatter alloc] init];
        [dateFormatter setDateFormat:@"yyyy/MM/dd HH:mm:ss:SSS"];
    }
    return self;
}

- (NSString *)formatLogMessage:(DDLogMessage *)logMessage {
    NSString *logLevel;
    switch (logMessage->_flag) {
        case DDLogFlagError    : logLevel = @"Error"; break;
        case DDLogFlagWarning  : logLevel = @"Warn"; break;
        case DDLogFlagInfo     : logLevel = @"Info"; break;
        case DDLogFlagDebug    : logLevel = @"Debug"; break;
        default                : logLevel = @"Verbose"; break;
    }
    
    return [NSString stringWithFormat:@"%@ %@ %@:%ld %@ | %@",
            [dateFormatter stringFromDate:logMessage->_timestamp], logMessage->_threadID,
            logMessage->_fileName, logMessage->_line, logLevel, logMessage->_message];
}

@end
#endif
