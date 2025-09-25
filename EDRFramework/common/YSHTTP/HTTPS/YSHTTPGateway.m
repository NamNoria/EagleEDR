//
//  HTTPGateway.m
//  Garden
//
//  Created by chenhanrong on 2022/11/11.
//
#import "YSHTTPGateway.h"
#import "YSHTTPRequest.h"
#import "YSHTTPResponse.h"
#import "YSHTTPGateway.h"
#import "MOLCertificate.h"
#include "../AFNetworking/AFURLRequestSerialization.h"
#include "../AFNetworking/AFURLSessionManager.h"
#include "../AFNetworking/AFHTTPSessionManager.h"

//#import <AFNetworking/AFNetworking.h>
#import "Log.h"
#define WEAK_SELF __weak typeof(self) weakSelf = self;
#define STRONG_SELF __strong typeof(self) strongSelf = weakSelf;
#define SASE_CERT @"MIIDGDCCAgCgAwIBAgIUTA97/dvw6MeufNFermI7aDYBIHQwDQYJKoZIhvcNAQEL\nBQAwJDELMAkGA1UEBhMCQ04xFTATBgNVBAMTDFNBU0UgUm9vdCBDQTAeFw0yMzA1\nMTIxMTQ4MDBaFw0yODA1MTAxMTQ4MDBaMCQxCzAJBgNVBAYTAkNOMRUwEwYDVQQD\nEwxTQVNFIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/\nUzSmD9PEIgQG8PAcDy1FnVXt73wgXnju+LSawRrM3tYuRnNv9dCDzrTgXLJs8hYP\nW9eDsPRBSoYmJUBw4IKpGnAqSEH+kpj2+BgOtbP+782+esT2Mi0JvgHzQseTI9ya\n5BhMKolQr008s/ZruohTh+f/7oq7nOvNkqSOO0K4b6ueeMsbrEtNxPHB+g/pnttb\nkBZz1P9Lx6HS/PRBYbNX4v1kCoB1FY/fGW74F50VHRbN8rZM0pYEWDPIh+8I0AjV\nAPjbBnIcDqdwBwTZF1AthsUp9hjpwjH1HEWztNg2cEg5yP9xnB39JrPT92R8iM8d\ngzcyrmy5Wk7W1e2UBN0hAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMB\nAf8EBTADAQH/MB0GA1UdDgQWBBRJB9W4YArlzlsGQbuXXZdatdyjuzANBgkqhkiG\n9w0BAQsFAAOCAQEAEQYwlV0h1sqKz3CPFQZtpiuZmYh5xPDy3YOwFqLJNi/96j8d\ntgUGKSmUxzu1h9qliqlXWQp5hQOB7enoLG2NYOvq0NScI0JNtVtrjFUe73S/Pm9U\nSU3sGnAuMC6mBLQmgGLv09CJVxBU3c/ey7PCC9qNd8hqgf0N4aP1JM03w4TDo0qj\n0ohDDYT+X/FiLB8em8PvGmcDb0NGle/EBMNdH1e1WPxFvfSWmwF4uP5ft/m/NiPd\nmZx4QM22brhyHMeFpjYVaZHG5HQZvwU+ugJdPkQs9Ys4ncLnNhKeE/fuYEjA6HB8\nX0l1hWt7ysAdBw9hBuPFZpdAsnlVaMpu7hqTGg==\n"

@interface YSHTTPGateway ()
@property (nonatomic, strong) NSMutableDictionary *headerFields;
@property (nonatomic, copy) NSString *host;
@property (nonatomic,strong)  AFHTTPSessionManager *httpSessionManager;
@property (nonatomic,strong)  AFHTTPSessionManager *postFormDataSessionManager;
@property (nonatomic,strong)  AFURLSessionManager *urlSessionManager;
@end

@implementation YSHTTPGateway

+ (YSHTTPGateway *)instance {
    static YSHTTPGateway* instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[YSHTTPGateway alloc] init];
    });
    return instance;
}

+(NSSet *)getSHA1Set{
    return [NSSet setWithArray:@[
        @"14884E862637B026AF59625C4077EC3529BA9601",
        @"8AC7AD8F73AC4EC1B5754DA540F4FCCF7CB58E8C",
        @"3043FA4FF257DCA0C380EE2E58EA78B23FE6BBC1",
        @"E72EF1DFFCB20928CF5DD4D56737B151CB864F01",
        @"B6AF43C29B81537DF6EF6BC31F1F60150CEE4866",
        @"26F993B4ED3D2827B0B94BA7E9151DA38D92E532",
        @"B49082DD450CBE8B5BB166D3E2A40826CDED42CF",
        @"0BBEC2272249CB39AADB355C53E38CAE78FFB6FE",
        @"2F8F364FE1589744215987A52A9AD06995267FB5",
        @"E7F3A3C8CF6FC3042E6D0E6732C59E68950D5ED2",
        @"62FFD99EC0650D03CE7593D2ED3F2D32C9E3E54A",
        @"841A69FBF5CD1A2534133DE3F8FCB899D0C914B7",
        @"F69CDBB0FCF60213B65232A6A3913F1670DAC3E1",
        @"743AF0529BD032A0F44A83CDD4BAA97B7C2EC49A",
        @"6A92E4A8EE1BEC964537E3295749CD96E3E5D260",
        @"E011845E34DEBE8881B99CF61626D1961FC3B931",
        @"89D483034F9E9A48805F7237D4A9A6EFCB7C1FD1",
        @"AEC5FB3FC8E1BFC4E54F03075A9AE800B7F7B6FA",
        @"B561EBEAA4DEE4254B691A98A55747C234C7D971",
        @"FAB7EE36972662FB2DB02AF6BF03FDE87C4B2F9B",
        @"07E032E020B72C3F192F0628A2593A19A70F069E",
        @"D067C11351010CAAD0C76A65373116264F5371A2",
        @"6631BF9EF74F9EB6C9D5A60CBA6ABED1F7BDEF7B",
        @"9F744E9F2B4DBAEC0F312C50B6563B8E2D93C311",
        @"58E8ABB0361533FB80F79B1B6D29D3FF8D5F00F0",
        @"96C91B0B95B4109842FAD0D82279FE60FAB91683",
        @"B31EB1B740E36C8402DADC37D44DF5D4674952F9",
        @"503006091D97D4F5AE39F7CBE7927D7D652D3431",
        @"67650DF17E8E7E5B8240A4F4564BCFE23D69C6F0",
        @"51C6E70849066EF392D45CA00D6DA3628FC35239",
        @"0D44DD8C3C8C1A1A58756481E90F2E2AFFB3D26E",
        @"0F36385B811A25C39B314E83CAE9346670CC74B4",
        @"5A8CEF45D7A69859767A8C8B4496B578CF474B1A",
        @"8DA7F965EC5EFC37910F1C6E59FDC1CC6A6EDE16",
        @"D69B561148F01C77C54578C10926DF5B856976AD",
        @"B1BC968BD4F49D622AA89A81F2150152A41D829C",
        @"2796BAE63F1801E277261BA0D77770028F20EEE4",
        @"47BEABC922EAE80E78783462A79F45C254FDE68B",
        @"D6DAA8208D09D2154D24B52FCB346EB258B28A58",
        @"89DF74FE5CF40F4A80F9E3377D54DA91E101318E",
        @"06083F593F15A104A069A46BA903D006B7970991",
        @"F6108407D6F8BB67980CC2E244C2EBAE1CEF63BE",
        @"010C0695A6981914FFBF5FC6B0B695EA29E912A6",
        @"53A2B04BCA6BD645E6398A8EC40DD2BF77C3A290",
        @"39B46CD5FE8006EBE22F4ABB0833A0AFDBB9DD84",
        @"E9A85D2214521C5BAA0AB4BE246A238AC9BAE2A9",
        @"8A2FAF5753B1B0E6A104EC5B6A69716DF61CE284",
        @"1B8EEA5796291AC939EAB80A811A7373C0937967",
        @"CA3AFBCF1240364B44B216208880483919937CF7",
        @"093C61F38B8BDC7D55DF7538020500E125F5C836",
        @"1F4914F7D874951DDDAE02C0BEFD3A2D82755185",
        @"4812BD923CA8C43906E7306D2796E6A4CF222E7D",
        @"3A44735AE581901F248661461E3B9CC45FF53A1B",
        @"3BC49F48F8F373A09C1EBDF85BB1C365C7D811B3",
        @"8782C6C304353BCFD29692D2593E7D44D934FF11",
        @"36B12B49F9819ED74C9EBC380FC6568F5DACB2F7",
        @"5F3B8CF2F810B37D78B4CEEC1919C37334B9C774",
        @"A050EE0F2871F427B2126D6F509625BACC8642AF",
        @"F9E16DDC0189CFD58245633EC5377DC2EB936F2B",
        @"AD7E1C28B064EF8F6003402014C3D0E3370EB58A",
        @"B51C067CEE2B0C3DF855AB2D92F4FE39D4E70F0E",
        @"925A8F8D2C6D04E0665F596AFF22D863E8256F3F",
        @"D8C5388AB7301B1B6ED47AE645253A6F9F1A2761",
        @"9BAAE59F56EE21CB435ABE2593DFA7F040D11DCB",
        @"5B6E68D0CC15B6A05F1EC15FAE02FC6B2F5D6F74",
        @"4313BB96F1D5869BC14E6A92F6CFF63469878237",
        @"590D2D7D884F402E617EA562321765CF17D894E9",
        @"55A6723ECBF2ECCDC3237470199D2ABE11E381D1",
        @"9CBB4853F6A4F6D352A4E83252556013F5ADAF65",
        @"CF9E876DD3EBFC422697A3B5A37AA076A9062348",
        @"8094640EB5A7A1CA119C1FDDD59F810263A7FBD1",
        @"CFE970840FE0730F9DF60C7F2C4BEE2046349CBB",
        @"B80186D1EB9C86A54104CF3054F34C52B7E558C6",
        @"9FF1718D92D59AF37D7497B4BC6F84680BBAB666",
        @"61DB8C2159690390D87C9C128654CF9D3DF4DD07",
        @"58D1DF9595676B63C0F05B1C174D8B840BC878BD",
        @"B8BE6DCB56F155B963D412CA4E0634C794B21CC0",
        @"022D0582FA88CE140C0679DE7F1410E945D7A56D",
        @"BCB0C19DE9989270193857E98DA7B45D6EEE0148",
        @"FFBDCDE782C8435E3C6F26865CCAA83A455BC30A",
        @"A3A1B06F2461234AE336A5C237FCA6FFDDF0D73A",
        @"28F97816197AFF182518AA44FEC1A0CE5CB64C8A",
        @"4CDD51A3D1F5203214B0C6C532230391C746426D",
        @"C3197C3924E654AF1BC4AB20957AE2C30E13026A",
        @"B7AB3308D1EA4477BA1480125A6FBDA936490CBB",
        @"B80E26A9BFD2B23BC0EF46C9BAC7BBF61D0D4141",
        @"C303C8227492E561A29C5F79912B1E441391303A",
        @"AFE5D244A8D1194230FF479FE2F897BBCD7A8CB4",
        @"2B8F1B57330DBBA2D07A6C51F70EE90DDAB9AD8E",
        @"D1CBCA5DB2D52A7F693B674DE5F05A1D0C957DF0",
        @"1F24C630CDA418EF2069FFAD4FDD5F463A1B69AA",
        @"DF717EAA4AD94EC9558499602D48DE5FBCF03A25",
        @"BA29416077983FF4F3EFF231053B2EEA6D4D45FD",
        @"BDB1B93CD5978D45C6261455F8DB95C75AD153AF",
        @"8CF427FD790C3AD166068DE81E57EFBB932272D4",
        @"20D80640DF9B25F512253A11EAF7598AEB14B547",
        @"EC503507B215C4956219E2A89A5B42992C4C2C20",
        @"F33E783CACDFF4A2CCAC67556956D7E5163CE1ED",
        @"C88344C018AE9FCCF187B78F22D1C5D74584BAE5",
        @"3143649BECCE27ECED3A3F0B8F0DE4E891DDEECA",
        @"CABD2A79A1076A31F21D253635CB039D4329A5E8",
        @"B999CDD173508AC44705089C8C88FBBEA02B40CD",
        @"0FF9407618D3D76A4B98F0A8359E0CFD27ACCCED",
        @"D1EB23A46D17D68FD92564C2F1F1601764D8E349",
        @"93057A8815C64FCE882FFA9116522878BC536417",
        @"F373B387065A28848AF2F34ACE192BDDC78E9CAC",
        @"F9B5B632455F9CBEEC575F80DCE96E2CC7B278B7",
        @"293621028B20ED02F566C532D1D6ED909F45002F",
        @"D8A6332CE0036FB185F6634F7D6A066526322827",
        @"B8236B002F1D16865301556C11A437CAEBFFC3BB",
        @"2BB1F53E550C1DC5F1D4E6B76A464B550602AC21",
        @"E252FA953FEDDB2460BD6E28F39CCCCF5EB33FDE",
        @"D3DD483E2BBF4C05E8AF10F5FA7626CFD3DC3092",
        @"DAFAF7FA6684EC068F1450BDC7C281A5BCA96457",
        @"E2B8294B5584AB6B58C290466CAC3FB8398F8483",
        @"490A7574DE870A47FE58EEF6C76BEBC60B124099",
        @"58A2D0EC2052815BC1F3F86402244EC28E024B02",
        @"8F6BF2A9274ADA14A0C4F48E6127F9C01E785DD1",
        @"D4DE20D05E66FC53FE1A50882C78DB2852CAE474",
        @"0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43",
        @"A14B48D943EE0A0E40904F3CE0A4C09193515D3F",
        @"F517A24F9A48C6C9F8A200269FDC0F482CAB3089",
        @"A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436",
        @"DF3C24F9BFD666761B268073FE06D1CC8D4F82A4",
        @"7E04DE896A3E666D00E687D33FFAD93BE83D349E",
        @"5FB7EE0633E259DBAD0C4C9AE6D38F1A61C7DC25",
        @"DDFB16CD4931C973A2037D3FC83A4D7D775D05E4",
        @"2F783D255218A74A653971B52CA29C45156FE919",
        @"77D30367B5E00C15F60C3861DF7CE13B92464D47",
        @"E58C1CC4913B38634BE9106EE3AD8E6B9DD9814A",
        @"9A44497632DBDEFAD0BCFB5A7B17BD9E56092494",
        @"EDE571802BC892B95B833CD232683F09CDA01E46",
        @"6BA0B098E171EF5AADFE4815807710F4BD6F0B28",
        @"999A64C37FF47D9FAB95F14769891460EEC4C3C5",
        @"73A5E64A3BFF8316FF0EDCCC618A906E4EAE4D74",
        @"1F5B98F0E3B5F7743CEDE6B0367D32CDF4094167",
        @"2D0D5214FF9EAD9924017420476E6C852727F543",
        @"B12E13634586A46F1AB2606837582DC4ACFD9497",
        @"A78849DC5D7C758C8CDE399856B3AAD0B2A57135",
        @"17F3DE5E9F0F19E98EF61F32266E20C407AE30EE",
        @"A6CA674362BCBBC2180AF7E91B79A929DCD91BCA",
        @"130C724E0BBCA079B3EAEC8F581759FACF85CD0B",
        @"56E0FAC03B8F18235518E5D311CAE8C24331AB66",
        @"339B6B1450249B557A01877284D9E02FC3D2D8E9",
        @"5922A1E15AEA163521F898396A4646B0441B0FA9",
        @"6C7CCCE7D4AE515F9908CD3FF6E8C378DF6FEF97",
        @"14698989BFB2950921A42452646D37B50AF017E2",
        @"31F1FD68226320EEC63B3F9DEA4A3E537C7C3917",
        @"4EB6D578499B1CCF5F581EAD56BE3D9B6744A5E5",
        @"132D0D45534B6997CDB2D5C339E25576609B5CC6",
        @"B52CB02FD567E0359FE8FA4D4C41037970FE01B0",
        @"3B166C3B7DC4B751C9FE2AFAB9135641E388E186",
        @"FE45659B79035B98A161B5512EACDA580948224D",
        @"517F611E29916B5382FB72E744D98DC3CC536D64",
        @"182E1F324F89DFBEFE8889F093C2C4A02B677521",
        @"74F8A3C3EFE7B390064B83903C21646020E5DFCE",
        @"5A4D0E8B5FDCFDF64E7299A36C060DB222CA78E4",
        @"3679CA35668772304D30A5FB873B0FA77BB70D54",
        @"40B331A0E9BFE855BC3993CA704F4EC251D41D8F",
        @"AE3B31BF8FD891079CF1DF34CBCE6E70D37FB5B0",
        @"61EF43D77FCAD46151BC98E0C35912AF9FEB6311",
        @"6969562E4080F424A1E7199F14BAF3EE58AB6ABB",
        @"6E3A55A4190C195C93843CC0DB722E313061F0B1",
        @"CB658264EA8CDA186E1752FB52C397367EA387BE",
        @"46C6900A773AB6BCF465ADACFCE3F707006EDE6E",
        @"D3EEFBCBBCF49867838626E23BB59CA01E305DB7",
        @"BE64D3DA144BD26BCDAF8FDBA6A672F8DE26F900",
        @"26CAFF09A7AFBAE96810CFFF821A94326D2845AA",
        @"22D5D8DF8F0231D18DF79DB7CF8A2D64C93F6C3A",
        @"204285DCF7EB764195578E136BD4B7D1E98E46A5",
        @"5CFB1F5DB732E4084C0DD4978574E0CBC093BEB3",
        @"91C6D6EE3E8AC86384E548C299295C756C817B81",
        @"E7A19029D3D552DC0D0FC692D3EA880D152E1A6B",
        @"580F804792ABC63BBB80154D4DFDDD8B2EF2674E",
        @"323C118E1BF7B8B65254E2E2100DD6029037F096",
        @"8D1784D537F3037DEC70FE578B519A99E610D7B0",
        @"039EEDB80BE7A03C6953893B20D2D9323A4C2AFD",
        @"77474FC630E40F4C47643F84BAB8C6954A8A41EC",
        @"611E5B662C593A08FF58D14AE22452D198DF6C60",
        @"786A74AC76AB147F9C6A3050BA9EA87EFE9ACE3C",
        @"7618D1F380243D5240C6116AAD5777097D8130A0",
        @"FAA7D9FB31B746F200A85E65797613D816E063B5",
        @"2A1D6027D94AB10A1C4D915CCD33A0CB3E2D54CB",
        @"4ABDEEEC950D359C89AEC752A12C5B29F6D6AA0C",
        @"F18B538D1BE903B6A6F056435B171589CAF36BF2",
        @"5F3AFC0A8B64F686673474DF7EA9A2FEF9FA7A51",
        @"DE990CED99E0431F60EDC3937E7CD5BF0ED9E5FA",
        @"30D4246F07FFDB91898A0BE9496611EB8C5E46E5",
        @"D273962A2A5E399F733FE1C71E643F033834FC4D",
        @"E1C950E6EF22F84C5645728B922060D7D5A7A3E8",
        @"6252DC40F71143A22FDE9EF7348E064251B18118",]];
}

+(NSURLSessionAuthChallengeDisposition)vaildCertWithSession:(NSURLSession *)session challenge:(NSURLAuthenticationChallenge *)challenge credential:( NSURLCredential *__autoreleasing *)credential{
    *credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
    if(*credential) {
        DDLogInfo(@"[TLS][Challege] match EagleCloud Root CA commonName Succeed,bypass!");
        return NSURLSessionAuthChallengeUseCredential;
    }
    NSSet * SHA1Set = [self getSHA1Set];
    //取得证书
    SecTrustRef serverTrust = [[challenge protectionSpace] serverTrust];
    if(serverTrust == nil){
        return NSURLSessionAuthChallengeCancelAuthenticationChallenge;
    }
    CFIndex certificateCount = SecTrustGetCertificateCount(serverTrust);
    if (certificateCount < 1) {
        DDLogInfo(@"[TLS][Challege] SecTrustGetCertificateCount %ld < 1",certificateCount);
        return NSURLSessionAuthChallengeCancelAuthenticationChallenge;
    }
    SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, certificateCount - 1);
    MOLCertificate *cert = [[MOLCertificate alloc] initWithSecCertificateRef:certificate];
    NSString *certSHA1 = [cert.SHA1 uppercaseString];
    NSString *commonName = cert.commonName;
    if([commonName isEqualToString:@"EagleCloud Root CA"]){
        if(credential){
            *credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
            if(*credential) {
                DDLogInfo(@"[TLS][Challege] match EagleCloud Root CA commonName Succeed,bypass!");
                return NSURLSessionAuthChallengeUseCredential;
            } else {
                DDLogInfo(@"[TLS][Challege]  use System settings!");
                return NSURLSessionAuthChallengePerformDefaultHandling;
            }
        }
    }
    if([SHA1Set containsObject:certSHA1]){
        if(credential){
            *credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
            if(*credential) {
                DDLogInfo(@"[TLS][Challege]  Succeed!");
                return NSURLSessionAuthChallengeUseCredential;
            } else {
                DDLogInfo(@"[TLS][Challege]  use System settings!");
                return NSURLSessionAuthChallengePerformDefaultHandling;
            }
        }
    }else{
        DDLogInfo(@"[TLS][Challege] CA cert commName:%@ Country:%@ Org:%@ SHA1: %@",cert.commonName,cert.countryName,cert.orgName,certSHA1);
        NSData * data = [[NSData alloc] initWithBase64EncodedData:[SASE_CERT dataUsingEncoding:NSUTF8StringEncoding]options:NSDataBase64DecodingIgnoreUnknownCharacters];
        if(data){
            SecCertificateRef cerRef = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)data);
            NSMutableArray *certArray = [NSMutableArray new];
            if(YSHTTPGateway.instance.rootCert){
                [certArray addObject:YSHTTPGateway.instance.rootCert];
            }
            if(cerRef){
                [certArray addObject:CFBridgingRelease(cerRef)];
                OSStatus status =   SecTrustSetAnchorCertificates(serverTrust,(__bridge CFArrayRef)certArray);
                if(status != ERR_SUCCESS){
                    NSString *err = (__bridge_transfer NSString *)SecCopyErrorMessageString(status, NULL);
                    DDLogInfo(@"[TLS][Challege]  SecTrustSetAnchorCertificates failed:%@",err);
                }
                status = SecTrustSetAnchorCertificatesOnly(serverTrust,YES);
                if(status != ERR_SUCCESS){
                    NSString *err = (__bridge_transfer NSString *)SecCopyErrorMessageString(status, NULL);
                    DDLogInfo(@"[TLS][Challege]  SecTrustSetAnchorCertificatesOnly failed:%@",err);
                }
                status = SecTrustSetPolicies(serverTrust, (__bridge CFArrayRef) @[(__bridge id)SecPolicyCreateBasicX509()]);
                if(status != ERR_SUCCESS){
                    NSString *err = (__bridge_transfer NSString *)SecCopyErrorMessageString(status, NULL);
                    DDLogInfo(@"[TLS][Challege]  SecTrustSetPolicies failed:%@",err);
                }
                BOOL succeed = NO;
                SecTrustResultType trustResult = kSecTrustResultInvalid;
                if (@available(macOS 10.14, *)){
                    CFErrorRef err;
                    succeed = SecTrustEvaluateWithError(serverTrust, &err);
                    DDLogInfo(@"[TLS][Challege] SecTrustEvaluateWithError error %@ ",(__bridge id)err);
                    if(err){
                        CFRelease(err);
                    }
                }else{
                    status = SecTrustEvaluate(serverTrust, &trustResult);
                }
                if((status == ERR_SUCCESS && ((trustResult == kSecTrustResultProceed) ||
                                              (trustResult == kSecTrustResultUnspecified))) || succeed){
                    if(credential){
                        *credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
                        if(*credential) {
                            DDLogInfo(@"[TLS][Challege]  Succeed!");
                            return NSURLSessionAuthChallengeUseCredential;
                        } else {
                            DDLogInfo(@"[TLS][Challege]  use System settings!");
                            return NSURLSessionAuthChallengePerformDefaultHandling;
                        }
                    }
                }else{
                    NSString *err = (__bridge_transfer NSString *)SecCopyErrorMessageString(status, NULL);
                    DDLogInfo(@"[TLS][Challege]  SecTrustEvaluate failed:%@ reustResult:%u",err,trustResult);
                }
            }
        }
    }
    DDLogInfo(@"[CertChallege] Reject!");
    //拒绝该证书
    return NSURLSessionAuthChallengeCancelAuthenticationChallenge;
}

+(NSURLSessionAuthChallengeDisposition (^)(NSURLSession *session, NSURLAuthenticationChallenge *challenge, NSURLCredential * _Nullable __autoreleasing * _Nullable credential))getCertVeryBlock{
    return  ^NSURLSessionAuthChallengeDisposition(NSURLSession *session, NSURLAuthenticationChallenge *challenge, NSURLCredential *__autoreleasing *credential){
        return [self vaildCertWithSession:session challenge:challenge credential:credential];
    };
}


- (instancetype)init {
    if (self = [super init]) {
        self.headerFields = [[NSMutableDictionary alloc] init];
        [self setupManager];
    }
    return self;
}

- (void)setupManager
{
    NSURLSessionConfiguration* sessionConfig = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    //忽略系统代理
    sessionConfig.connectionProxyDictionary = @{};
    AFSecurityPolicy *securityPolicy = [AFSecurityPolicy defaultPolicy];
    securityPolicy.validatesDomainName = NO;
    securityPolicy.allowInvalidCertificates = YES;
    
    self.httpSessionManager = [[AFHTTPSessionManager alloc]
                               initWithSessionConfiguration:sessionConfig];
    self.httpSessionManager.completionQueue = dispatch_queue_create(0, 0);
    self.httpSessionManager.requestSerializer = [AFJSONRequestSerializer serializer];
    [self.httpSessionManager.requestSerializer setTimeoutInterval:10];
    [self.httpSessionManager.requestSerializer setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    self.httpSessionManager.responseSerializer = [AFJSONResponseSerializer serializer];
    self.httpSessionManager.responseSerializer.acceptableContentTypes = [NSSet setWithObjects:@"text/plain",@"text/html",@"application/json", nil];
    self.httpSessionManager.securityPolicy = securityPolicy;
    
    self.postFormDataSessionManager = [[AFHTTPSessionManager alloc]
                                       initWithSessionConfiguration:sessionConfig];
    self.postFormDataSessionManager.completionQueue = dispatch_queue_create("postFormDataSessionManager", 0);
    self.postFormDataSessionManager.requestSerializer = [AFJSONRequestSerializer serializer];
    [self.postFormDataSessionManager.requestSerializer setTimeoutInterval:120];
    [self.postFormDataSessionManager.requestSerializer setValue:@"multipart/form-data" forHTTPHeaderField:@"Content-Type"];
    [self.postFormDataSessionManager.requestSerializer setHTTPShouldHandleCookies:YES];
    
    self.postFormDataSessionManager.responseSerializer = [AFJSONResponseSerializer serializer];
    self.postFormDataSessionManager.responseSerializer.acceptableContentTypes =[NSSet setWithObjects:@"text/plain",@"text/html",@"application/json", nil];
    self.postFormDataSessionManager.securityPolicy = securityPolicy;
    
    self.urlSessionManager = [[AFURLSessionManager alloc]
                              initWithSessionConfiguration:sessionConfig];
    self.urlSessionManager.completionQueue = dispatch_queue_create(0, 0);
    self.urlSessionManager.securityPolicy = securityPolicy;
    [self.postFormDataSessionManager setSessionDidReceiveAuthenticationChallengeBlock:[YSHTTPGateway getCertVeryBlock]];
    [self.urlSessionManager setSessionDidReceiveAuthenticationChallengeBlock:[YSHTTPGateway getCertVeryBlock]];
    [self.httpSessionManager setSessionDidReceiveAuthenticationChallengeBlock:[YSHTTPGateway getCertVeryBlock]];
}

- (void)setupWithHost:(NSString *)host
{
    DDLogInfo(@"[CertChallege] setupWithHost: %@",host);
    if(host.length>0){
        self.host = host;
    }
}

- (NSString *)getCurrentHttpApiEnv
{
    return self.host;
}

- (void)setupHeaderFields:(NSDictionary *)header
{

    [self.headerFields addEntriesFromDictionary:header];
    [self.headerFields enumerateKeysAndObjectsUsingBlock:^(id  _Nonnull key, id  _Nonnull obj, BOOL * _Nonnull stop) {
        NSString *headerKey = (NSString *)key;
        NSString *headerValue = (NSString *)obj;
        [self.httpSessionManager.requestSerializer setValue:headerValue forHTTPHeaderField:headerKey];
        [self.postFormDataSessionManager.requestSerializer setValue:headerValue forHTTPHeaderField:headerKey];
    }];
}

-(void)removeToken{
    [self.headerFields removeObjectsForKeys:@[@"Cookie" ,@"Authorization"]];
}


- (void)preHandleRequest:(YSHTTPRequest *)request
{
    NSMutableDictionary* params = [request.paramters mutableCopy];
    [params setObject:@"mac" forKey:@"osType"];
    [params setObject:@"mac" forKey:@"os_type"];
    request.paramters = params;
}

- (void)startRequest:(YSHTTPRequest*)request
        successBlock:(YSHTTPRequestSuccessBlock)successBlock
        failureBlock:(YSHTTPRequestFailureBlock)failureBlock
{
    [self preHandleRequest:request];
    //    DDLogInfo(@"[HTTPS] request %@ %@ %@",request.apiName ,request.paramters,self.headerFields);
    switch (request.method) {
        case YSHTTPMethodGET:
            [self handleGetRequest:request successBlock:successBlock failureBlock:failureBlock];
            break;
        case YSHTTPMethodPOST:
            [self handlePostRequest:request successBlock:successBlock failureBlock:failureBlock];
            break;
        case YSHTTPMethodPOST_MultiPart:
            [self handlePostFormDataRequest:request successBlock:successBlock failureBlock:failureBlock];
            break;
        case YSHTTPMethodPOST_Body:
            [self handlePostBodyRequest:request successBlock:successBlock failureBlock:failureBlock];
            break;
        case YSHTTPMethodPUT_Body:
            [self handlePutBodyRequest:request successBlock:successBlock failureBlock:failureBlock];
            break;
        default:
            break;
    }
}

- (void)handleGetRequest:(YSHTTPRequest *)request
            successBlock:(YSHTTPRequestSuccessBlock)successBlock
            failureBlock:(YSHTTPRequestFailureBlock)failureBlock {
    NSString *requestAPI = [NSString stringWithFormat:@"%@%@", self.host, request.apiName];
    if ([request.URL length] > 0) {
        requestAPI = request.URL;
    }
    WEAK_SELF
    [self.httpSessionManager GET:requestAPI
                      parameters:request.paramters
                         headers:request.extraHTTPHeader
                        progress:nil
                         success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        [weakSelf handleResponse:responseObject successBlock:successBlock failureBlock:failureBlock];
        
    }
                         failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        [weakSelf handleError:error failureBlock:failureBlock];
    }];
}

- (void)handlePostRequest:(YSHTTPRequest *)request
             successBlock:(YSHTTPRequestSuccessBlock)successBlock
             failureBlock:(YSHTTPRequestFailureBlock)failureBlock{
    NSString *requestAPI = [NSString stringWithFormat:@"%@%@", self.host, request.apiName];
    if ([request.URL length] > 0) {
        requestAPI = request.URL;
    }
    WEAK_SELF
    [self.httpSessionManager POST:requestAPI
                       parameters:request.paramters
                          headers:request.extraHTTPHeader
                         progress:nil
                          success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        [weakSelf handleResponse:responseObject successBlock:successBlock failureBlock:failureBlock];
    }
                          failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        [weakSelf handleError:error failureBlock:failureBlock];
    }];
}

- (void)handlePostFormDataRequest:(YSHTTPRequest *)request
                     successBlock:(YSHTTPRequestSuccessBlock)successBlock
                     failureBlock:(YSHTTPRequestFailureBlock)failureBlock{
    NSString *requestAPI = [NSString stringWithFormat:@"%@%@", self.host, request.apiName];
    if ([request.URL length] > 0) {
        requestAPI = request.URL;
    }
    WEAK_SELF
    NSData* fileData = request.body;
    NSString* fileName = request.filename;
    NSString* mimeType = request.mimeType;
    NSString* name = request.formDataName;
    
    [self.postFormDataSessionManager POST:requestAPI parameters:request.paramters headers:nil
                constructingBodyWithBlock:^(id<AFMultipartFormData>   formData) {
        [formData appendPartWithFileData:fileData
                                    name:name
                                fileName:fileName
                                mimeType:mimeType];
    } progress:nil success:^(NSURLSessionDataTask * task, id   responseObject) {
        [weakSelf handleResponse:responseObject successBlock:successBlock failureBlock:failureBlock];
    } failure:^(NSURLSessionDataTask *  task, NSError *  error) {
        [weakSelf handleError:error failureBlock:failureBlock];
    }];
}
- (void)handlePostBodyRequest:(YSHTTPRequest *)request
                 successBlock:(YSHTTPRequestSuccessBlock)successBlock
                 failureBlock:(YSHTTPRequestFailureBlock)failureBlock{
    NSString *requestAPI = [NSString stringWithFormat:@"%@%@", self.host, request.apiName];
    if ([request.URL length] > 0) {
        requestAPI = request.URL;
    }
    NSString *method = @"POST";
    NSMutableURLRequest *URLRequest = [[AFJSONRequestSerializer serializer]
                                       requestWithMethod:method URLString:requestAPI parameters:nil error:nil];
    
    URLRequest.timeoutInterval= 60;
    [URLRequest addValue:@"application/json;charset=utf-8" forHTTPHeaderField:@"Content-Type"];
    [URLRequest addValue:@"application/json" forHTTPHeaderField:@"Accept"];
    [URLRequest setAllHTTPHeaderFields:self.headerFields];
    [URLRequest setHTTPBody:request.body];
//    NSLog(@"请求 URL: %@", URLRequest.URL.absoluteString);
//    NSLog(@"请求头: %@", URLRequest.allHTTPHeaderFields);
    WEAK_SELF
    [[self.urlSessionManager dataTaskWithRequest:URLRequest
                                  uploadProgress:nil
                                downloadProgress:nil
                               completionHandler:^(NSURLResponse * _Nonnull response, id  _Nullable responseObject, NSError * _Nullable error) {
        if (!error) {
//            NSLog(@"请求成功: %@", responseObject);
            [weakSelf handleResponse:responseObject successBlock:successBlock failureBlock:failureBlock];
        } else {
            NSLog(@"请求失败: %@", error);
            [weakSelf handleError:error failureBlock:failureBlock];
        }
    }] resume];
}

- (void)handlePutBodyRequest:(YSHTTPRequest *)request
                successBlock:(YSHTTPRequestSuccessBlock)successBlock
                failureBlock:(YSHTTPRequestFailureBlock)failureBlock{
    NSString *requestAPI = [NSString stringWithFormat:@"%@%@", self.host, request.apiName];
    if ([request.URL length] > 0) {
        requestAPI = request.URL;
    }
    NSString *method = @"PUT";
    NSMutableURLRequest *URLRequest = [[AFJSONRequestSerializer serializer]
                                       requestWithMethod:method URLString:requestAPI parameters:nil error:nil];
    URLRequest.timeoutInterval= 60;
    [URLRequest setValue:@"" forHTTPHeaderField:@"Content-Type"];
    [URLRequest setHTTPBody:request.body];
    
    WEAK_SELF
    [[self.urlSessionManager dataTaskWithRequest:URLRequest
                                  uploadProgress:nil
                                downloadProgress:nil
                               completionHandler:^(NSURLResponse * _Nonnull response, id  _Nullable responseObject, NSError * _Nullable error) {
        if (!error) {
            [weakSelf handleResponse:responseObject successBlock:successBlock failureBlock:failureBlock];
        } else {
            [weakSelf handleError:error failureBlock:failureBlock];
        }
    }] resume];
}


- (void)handleResponse:(id)responseObj
          successBlock:(YSHTTPRequestSuccessBlock)successBlock
          failureBlock:(YSHTTPRequestFailureBlock)failureBlock{
    @autoreleasepool {
        NSDictionary *dict = (NSDictionary *)responseObj;
        // 业务错误
        NSInteger code = [dict[@"code"] intValue];
        if (code != 200 && code != 0) {
            NSError *error = [NSError errorWithDomain:dict[@"message"] code:code userInfo:nil];
            [self handleError:error failureBlock:failureBlock];
            NSLog(@"dict = %@", dict);
            NSLog(@"dict[@\"code\"] = %@", dict[@"code"]);
            NSLog(@"code(intValue) = %ld", (long)[dict[@"code"] intValue]);

        } else {
            if(successBlock){
                YSHTTPResponse *resposne = [[YSHTTPResponse alloc] init];
                resposne.configVersion = dict[@"config_version"]?:@"";
                resposne.succeed = YES;
                resposne.data = responseObj;
                successBlock(resposne);
            }
        }
    }
}

-(NSDictionary *)getHeaderFileds{
    return self.headerFields;
}

- (void)handleError:(NSError*)error failureBlock:(YSHTTPRequestFailureBlock)failureBlock{
    @autoreleasepool {
        if(failureBlock){
            YSHTTPResponse *resposne = [[YSHTTPResponse alloc] init];
            resposne.succeed = NO;
            resposne.error = error;
            failureBlock(resposne);
        }
    }
}

@end
