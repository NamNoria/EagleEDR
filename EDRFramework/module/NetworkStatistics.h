//
//  NetworkStatistics.h
//  Garden
//
//  Created by chenhanrong on 2022/11/24.
//

// mahalo J. Levin:
//   https://twitter.com/Morpheus______
//   http://newosxbook.com/src.jl?tree=listings&file=netbottom.c

#ifndef NetworkStatistics_h
#define NetworkStatistics_h

// 私有接口回调传入的字典的key
/**
 进程id
 */
extern NSConstantString *kNStatSrcKeyPID;
/**
 UUID
 */
extern NSConstantString *kNStatSrcKeyUUID;
/**
 本地地址
 */
extern NSConstantString *kNStatSrcKeyLocal;
/**
 远程地址
 */
extern NSConstantString *kNStatSrcKeyRemote;
/**
 发送速率
 */
extern NSConstantString *kNStatSrcKeyTxBytes;
/**
 接收速率
 */
extern NSConstantString *kNStatSrcKeyRxBytes;
/**
 协议
 */
extern NSConstantString *kNStatSrcKeyProvider;
/**
 TCP状态
 */
extern NSConstantString *kNStatSrcKeyTCPState;
/**
 接口
 */
extern NSConstantString *kNStatSrcKeyInterface;
/**
 进程名
 */
extern NSConstantString *kNStatSrcKeyProcessName;

typedef void     *NStatSourceRef;
typedef NSObject *NStatManagerRef;

NStatManagerRef NStatManagerCreate(const struct __CFAllocator *, dispatch_queue_t, void (^)(void *, void *));

void NStatSourceSetDescriptionBlock(NStatSourceRef arg, void (^)(NSDictionary *));
void NStatSourceSetRemovedBlock(NStatSourceRef arg, void (^)(void));

void NStatManagerSetInterfaceTraceFD(NStatSourceRef arg, int fd);

void NStatManagerAddAllTCP(NStatManagerRef manager);
void NStatManagerAddAllTCPWithFilter(NStatManagerRef, int, int);
void NStatManagerAddAllUDP(NStatManagerRef manager);
void NStatManagerAddAllUDPWithFilter(NStatManagerRef, int, int);

void NStatManagerQueryAllSources(NStatManagerRef manager, void (^)(void));
void NStatManagerQueryAllSourcesDescriptions(NStatManagerRef manager, void (^)(void));

void NStatManagerDestroy(NStatManagerRef manager);
int  NStatManagerSetFlags(NStatManagerRef, int Flags);

#endif /* NetworkStatistics_h */
