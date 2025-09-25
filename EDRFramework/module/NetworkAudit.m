//
//  NetstatAudit.m
//  Garden
//
//  Created by chenhanrong on 2022/11/24.
//

#import "NetworkAudit.h"
#import "NetworkStatistics.h"
#import <arpa/inet.h>
#import <netinet/in.h>
// #import "EventMonitor.h"

// NetworkAudit - 专注于新TCP连接的实时监控

@interface                                 NetworkAudit ()
@property(nullable) dispatch_queue_t       queue;
@property(nullable) NStatManagerRef        manager;
@property(nonatomic, assign) BOOL          isMonitoring;
@property(nonatomic, strong) NSMutableSet *processedSources;

- (NSDictionary *)parseNetworkAddress:(NSData *)addressData;

@end

// 添加缺失的函数声明
void NStatSourceQueryDescription(NStatSourceRef source);

@implementation NetworkAudit

- (instancetype)init
{
    if ( self = [super init] )
    {
        self.queue            = dispatch_queue_create("com.eagleyun.sase.edr.netmonitor", DISPATCH_QUEUE_SERIAL);
        self.isMonitoring     = NO;
        self.processedSources = [[NSMutableSet alloc] init];

        self.manager = NStatManagerCreate(kCFAllocatorDefault, self.queue, ^(NStatSourceRef source, void *unknown) {
            if ( source )
            {
//                NSLog(@"🔥 NetworkAudit: 检测到新TCP连接 (source=%p)", source);
                //  使用source指针作为唯一标识符
                NSValue *sourceKey = [NSValue valueWithPointer:source];

                if ( [self.processedSources containsObject:sourceKey] )
                {
                    // 这个source已经处理过了，跳过
                    return;
                }

                // 标记为已处理
                [self.processedSources addObject:sourceKey];

                // NSLog(@"🔥 NetworkAudit: 检测到新TCP连接 (source=%p)", source);

                NStatSourceSetDescriptionBlock(source, ^(NSDictionary *description) {
                    // 直接处理新连接信息
                    [self processNetworkDescription:description];
                });

                // 立即请求连接详情
                NStatSourceQueryDescription(source);
            }
        });

        if ( self.manager )
        {
            NSLog(@"NetworkAudit: 初始化成功");
        }
        else
        {
            NSLog(@"NetworkAudit: 初始化失败 - NetworkStatistics框架不可用");
            return self;
        }
    }
    return self;
}

- (void)start
{
    if ( !self.manager )
    {
        NSLog(@"❌ NetworkAudit: NStatManager未初始化");
        return;
    }

    if ( self.isMonitoring )
    {
        NSLog(@"⚠️ NetworkAudit: 已经在监控中，跳过重复启动");
        return;
    }

    self.isMonitoring = YES;

    // 设置管理器标志
    NStatManagerSetFlags(self.manager, 0);

    // 启用TCP新连接监控
    NStatManagerAddAllTCP(self.manager);

    NSLog(@"NetworkAudit: TCP新连接监控已启动");
}

- (void)processNetworkDescription:(NSDictionary *)description
{
    @try
    {
        NSNumber *pid      = description[kNStatSrcKeyPID];
        NSString *process  = description[kNStatSrcKeyProcessName];
        id        local    = description[kNStatSrcKeyLocal];
        id        remote   = description[kNStatSrcKeyRemote];
        NSNumber *provider = description[kNStatSrcKeyProvider];
        NSNumber *txBytes  = description[kNStatSrcKeyTxBytes];
        NSNumber *rxBytes  = description[kNStatSrcKeyRxBytes];
        NSNumber *tcpState = description[kNStatSrcKeyTCPState];
        NSString *iface    = description[kNStatSrcKeyInterface];
        NSString *uuid     = description[kNStatSrcKeyUUID];

        // 安全地解析地址和端口
        NSString *localIP    = nil;
        NSNumber *localPort  = nil;
        NSString *remoteIP   = nil;
        NSNumber *remotePort = nil;

        // 处理本地地址
        if ( [local isKindOfClass:[NSDictionary class]] )
        {
            NSDictionary *localDict = (NSDictionary *)local;
            localIP                 = localDict[@"Address"];
            localPort               = localDict[@"Port"];
        }
        else if ( [local isKindOfClass:[NSData class]] )
        {
            NSDictionary *parsedLocal = [self parseNetworkAddress:(NSData *)local];
            localIP                   = parsedLocal[@"Address"];
            localPort                 = parsedLocal[@"Port"];
        }

        // 处理远程地址
        if ( [remote isKindOfClass:[NSDictionary class]] )
        {
            NSDictionary *remoteDict = (NSDictionary *)remote;
            remoteIP                 = remoteDict[@"Address"];
            remotePort               = remoteDict[@"Port"];
        }
        else if ( [remote isKindOfClass:[NSData class]] )
        {
            NSDictionary *parsedRemote = [self parseNetworkAddress:(NSData *)remote];
            remoteIP                   = parsedRemote[@"Address"];
            remotePort                 = parsedRemote[@"Port"];
        }

        // 创建连接的唯一标识符
        NSString *connectionId = [NSString stringWithFormat:@"%@:%@->%@:%@[%@]", localIP ?: @"N/A", localPort ?: @"N/A",
                                                            remoteIP ?: @"N/A", remotePort ?: @"N/A", pid ?: @"?"];

//        NSLog(@"========== 新TCP连接 ==========");
//        NSLog(@"进程: %@ (PID: %@)", process ?: @"未知", pid ?: @"未知");
//        NSLog(@"本地: %@:%@", localIP ?: @"N/A", localPort ?: @"N/A");
//        NSLog(@"远程: %@:%@", remoteIP ?: @"N/A", remotePort ?: @"N/A");
//        NSLog(@"连接ID: %@", connectionId);
//        NSLog(@"================================");
    }
    @catch ( NSException *exception )
    {
        NSLog(@"NetworkAudit: 处理网络描述时发生异常: %@", exception);
    }
}

- (NSDictionary *)parseNetworkAddress:(NSData *)addressData
{
    if ( !addressData || addressData.length == 0 )
    {
        return @{ @"Address" : @"空数据", @"Port" : @0 };
    }

    const uint8_t *bytes  = (const uint8_t *)addressData.bytes;
    NSUInteger     length = addressData.length;

    // 地址数据解析（移除调试输出）

    NSString *address = @"未知";
    NSNumber *port    = @0;

    if ( length >= 16 )
    {
        // 检查是否是sockaddr_in结构 (IPv4)
        if ( length >= 16 && bytes[1] == 0x02 )
        {  // AF_INET = 2
            // IPv4地址格式: [len][family][port][addr][zero_pad]
            // port是网络字节序，需要转换
            uint16_t networkPort = *(uint16_t *)(bytes + 2);
            uint16_t hostPort    = ntohs(networkPort);

            // IPv4地址在偏移4的位置
            uint32_t       ipAddr = *(uint32_t *)(bytes + 4);
            struct in_addr addr;
            addr.s_addr = ipAddr;
            char *ipStr = inet_ntoa(addr);

            if ( ipStr )
            {
                address = [NSString stringWithUTF8String:ipStr];
                port    = @(hostPort);
            }
        }
        // 检查是否是IPv6地址
        else if ( length >= 28 && bytes[1] == 0x1e )
        {  // AF_INET6 = 30 (0x1e)
            // IPv6地址格式: [len][family][port][flowinfo][addr16][scopeid]
            uint16_t networkPort = *(uint16_t *)(bytes + 2);
            uint16_t hostPort    = ntohs(networkPort);

            // IPv6地址在偏移8的位置，16字节
            const uint8_t *ipv6Bytes = bytes + 8;
            char           ipv6Str[INET6_ADDRSTRLEN];

            if ( inet_ntop(AF_INET6, ipv6Bytes, ipv6Str, INET6_ADDRSTRLEN) )
            {
                address = [NSString stringWithUTF8String:ipv6Str];
                port    = @(hostPort);
            }
        }
    }

    // 如果解析失败，提供原始数据的十六进制表示
    if ( [address isEqualToString:@"未知"] && length > 0 )
    {
        NSMutableString *hexAddress = [NSMutableString stringWithString:@"0x"];
        for ( NSUInteger i = 0; i < MIN(length, 8); i++ )
        {
            [hexAddress appendFormat:@"%02x", bytes[i]];
        }
        address = hexAddress;
    }

    return @{ @"Address" : address, @"Port" : port };
}

- (void)stop
{
    self.isMonitoring = NO;
    if ( self.manager )
    {
        self.manager = NULL;
    }
}

- (void)dealloc
{
    [self stop];
    NSLog(@"🗑️ NetworkAudit: 实例已释放");
}

@end
