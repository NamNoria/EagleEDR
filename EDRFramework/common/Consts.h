//
//  Consts.h
//  Garden
//
//  Created by chenhanrong on 2022/10/27.
//

#ifndef Consts_h
#define Consts_h


#define YS_URL_DAILY    @"https://sp.daily.eagleyun.cn"
#define YS_URL_DEBUG    @"https://sp.debug.eagleyun.cn:8443"
#define YS_URL_PRE      @"https://sp.pre.eagleyun.cn"
#define YS_URL_RELEASE  @"https://sp.eagleyun.cn"

#define YS_PRIVATE_URL  @""

//根据不同配置修改host
#ifdef XHS
#define YS_URL_RELEASE  @"https://sp.eagleyun.cn"
#endif

#define MAX_CACHE_DLP_TMP_SIZE                  1024*1024*1024
#define kYunshuTeamID                           @"585Z2747F9"

#define kYunshuDataPath                         @"/opt/.yunshu/data"
#define kYunshuTmpDLPPath                       @"/opt/.yunshu/tmp/dlp/"
#define kYunshuConfigPath                       @"/opt/.yunshu/config"
#define kYunshuConfigRecordPolicyPath           @"/opt/.yunshu/config/record_config"
#define kYunshuConfigDLPChannelPath             @"/opt/.yunshu/config/channel_config"
#define kYunshuConfigDLPSensitivePath           @"/opt/.yunshu/config/sensitive_config"
#define kYunshuConfigPeripheralPath             @"/opt/.yunshu/config/peripheral_config"
#define kYunshuConfigModulePath                 @"/opt/.yunshu/config/module_config"
#define kYunshuConfigProcessPath                @"/opt/.yunshu/config/process_config"
#define kYunshuConfigLicensePath                @"/opt/.yunshu/config/fs_config"
#define kYunshuConfigUserInfoPath               @"/opt/.yunshu/config/agent_config"
#define kYunshuConfigIdaasInfoPath              @"/opt/.yunshu/config/idaas_config"
#define kYunshuConfigFDAPath                    @"/opt/.yunshu/config/fda"
#define kYunshuConfigScreenShotPath             @"/opt/.yunshu/config/srp"
#define kYunshuConfigFilewaterPath              @"/opt/.yunshu/config/file_water_config"
#define kYunshuConfigClipboardPoliciesPath      @"/opt/.yunshu/config/clipboard_policies_config"
#define kYunshuConfigAgentCertPath              @"/opt/.yunshu/config/agnetcert_config"
#define kYunshuConfigFWImagePath                @"/opt/.yunshu/config/FWImage"

#define kHelperConfigSDPPath                    @"/Library/Application Support/EagleCloud/config"
#define kHelperConfigSDPUserInfoPath            @"/Library/Application Support/EagleCloud/config/agent_config"
#define kHelperConfigModulePath                 @"/Library/Application Support/EagleCloud/config/module_config"
#define kHelperConfigSwitchPath                 @"/Library/Application Support/EagleCloud/config/switch_config"
#define kHelperConfigSDPConfigPath              @"/Library/Application Support/EagleCloud/config/sdp_config"

#define YUNSHU_WORKSPACE_PATH                   @"/opt/.yunshu"
#define YUNSHU_TEMP_DATA_PATH                   @"/opt/yunshu/"

#define YUNSHU_MANAGER_APP                      @"YunshuManager.app"
#define YUNSHU_AGENT_APP                        @"YunshuAgent.app"
#define YUNSHU_DIAGNOSE_APP                     @"YunshuDiagnose.app"
#define YUNSHU_MANAGER_PATH                     [NSString stringWithFormat:@"%@/%@",YUNSHU_WORKSPACE_PATH,YUNSHU_MANAGER_APP]
#define YUNSHU_AGENT_SHOW_NAME                  [Utility getLocalizedNameWithPath:[NSString stringWithFormat:@"%@/%@",YUNSHU_WORKSPACE_PATH,YUNSHU_AGENT_APP]]
#define YUNSHU_MANAGER_SHOW_NAME                [Utility getLocalizedNameWithPath:[NSString stringWithFormat:@"%@/%@",YUNSHU_WORKSPACE_PATH,YUNSHU_MANAGER_APP]]
#define YUNSHU_APP_LABEL                        @"com.eagleyun.sase"
#define YUNSHU_HELPER_LABEl                     @"com.eagleyun.sase.helper"
#define YUNSHU_MANAGER_LABEl                    @"com.eagleyun.sase.servicemanager"
#define YUNSHU_AGENT_LABEl                      @"com.eagleyun.endpoint.agent"
#define YUNSHU_SERVICE_LABEL                    @"com.eagleyun.sase.endpointservice"

#define LAUNCH_DISABLE_PLIST                    @"/private/var/db/com.apple.xpc.launchd/disabled.plist"
#define LAUNCH_DAEMON_PATH                      @"/Library/LaunchDaemons"
#define YUNSHU_DAEMON_HELPER_PATH               @"/Library/PrivilegedHelperTools/com.eagleyun.sase.helper"
#define YUNSHU_DLP_LOGS_PATH                    @"/opt/.yunshu/logs/"
#define YUNSHU_DATAMAP_LOGS_PATH                @"/opt/.yunshu/logs/datarun"
#define YUNSHU_MANAGER_LOGS_PATH                @"/opt/.yunshu/logs/manager"
#define YUNSHU_DATAMAP_BIN_LOGS_PATH            @"/opt/.yunshu/logs/databin"
#define YUNSHU_WATERMARK_LOGS_PATH              @"/opt/.yunshu/logs/watermark"
#define YUNSHU_WATERMARK_CACHE_PATH             @"/opt/.yunshu/wm"


#define kSigningIDOpenPanel                     @"com.apple.appkit.xpc.openAndSavePanelService"
#define kSigningIDWebContent                    @"com.apple.WebKit.WebContent"
#define kSigningIDWebNetworking                 @"com.apple.WebKit.Networking"
#define kSigningIDBluetoothFile                 @"com.apple.BluetoothFileExchange"
#define kSigningIDMount                         @"com.apple.mount_msdos"

#define kSigningIDChrome                        @"com.google.Chrome"
#define kSigningIDEdge                          @"com.microsoft.edgemac"
#define kSigningIDFirefox                       @"org.mozilla.firefox"
#define kSigningIDSafari                        @"com.apple.Safari"
#define kSigningIDOpera                         @"com.operasoftware.Opera"

#define kSigningIDImessage                      @"com.apple.MobileSMS"
#define kSigningIDFinder                        @"com.apple.finder"
#define kSigningIDDeskServiceHelper             @"com.apple.DesktopServicesHelper"
#define kSigningIDMountLifs                     @"com.apple.mount_lifs"
#define kSigningIDCopy                          @"com.apple.cp"
#define kSigningIDMV                            @"com.apple.mv"
#define kSigningIDAMPDevice                     @"com.apple.AMPDevicesAgent"
#define kDiagnosticdFilterPlist                 @"/Library/Preferences/Logging/com.apple.diagnosticd.filter.plist"


#define kGitUserName                            @"userName"
#define kGitUserEmail                           @"emailAddress"
#define kGitRepoUrl                             @"source"
#define kGitCodeBase                            @"baseUrl"
#define kGitPushTime                            @"pushTime"
#define kGitCommand                             @"command"
#define kGitLogOriginPath                       @".git/logs/refs/remotes/origin/"
#define kSvnWCDBPath                            @".svn/wc.db"
#define kSvnMetadataFileName                    @"wc.db"

#define kPrinterCpusdBundleID                   @"com.apple.cupsd"
#define kPrinterContainFileName                 @"/var/spool/cups/"

#define kevernoteCopyPath                       @"/Users/[^/]+/Library/Containers/com.yinxiang.Mac/Data/Library/Application Support/com.yinxiang.Mac/accounts/app.yinxiang.com/[0-9]+/(content|MaterialLibrary)/.+"
#define kevernoteWebDownCopyPath                @"/Users/[^/]+/Library/Application Support/com.yinxiang.Mac/accounts/app.yinxiang.com/[0-9]+/(content|MaterialLibrary)/[^/]+/.+"
#define kZhiyinlouPicPath                       @"/private/var/folders/.+/yach-screen/.+png"
#define kkakaoPicPath                           @"/Users/[^/]+/Library/Containers/com.kakao.KakaoTalkMac/Data/Library/Caches/Capture/[^/]+/KakaoTalk_Snapshot_.+png"
#define kLinePicPath                            @"/Users/[^/]+/Library/Containers/jp.naver.line.mac/Data/Library/Containers/jp.naver.line/Data/Cache.+jpg"
#define kLine2PicPath                           @"/Users/[^/]+/Library/Group Containers/VUTU7AKEUR.jp.naver.line.mac/Real/Library/Data/Caches/[^/]+/tmp/.+jpg"
#define kWhatsappCopyPath                       @"/Users/[^/]+/Library/Group Containers/group.net.whatsapp.WhatsApp.shared/Message/Media/.+"
#define kTencentMeetingPicPath                  @"/Users/[^/]+/Library/Containers/com.tencent.meeting/Data/Library/Global/Data/IM/image/[^/]+/[^/]+/[{][^}]+[}].png"
#define kZoomPicPath                            @"/Users/[^/]+/Library/Application Support/zoom.us/data/image/Screenshot.+jpg"
#define kRegxDingtalk                           @"/Users/[^/]+/Library/Application Support/DingTalkMac/.+/ImageFiles/.+png"
#define kRegxAliDingtalk                        @"/Users/[^/]+/Library/Application Support/iDingTalk/.+/ImageFiles/.+png"
#define kRegxDingtalkAppstore                   @"/Users/[^/]+/Library/Containers/5ZSL2CJU2T.com.dingtalk.mac/Data/Library/Caches/5ZSL2CJU2T.com.dingtalk.mac/thumbnails/.+png"
#define kRegxQQV2                               @"/Users/[^/]+/Library/Containers/com.tencent.qq/Data/Library/Application Support/QQ/nt_qq_[^/]+/nt_data/Pic/.+png"
#define kRegxQQ                                 @"/Users/[^/]+/Library/Containers/com.tencent.qq/Data/Library/Application Support/QQ/Users/[0-9]+/QQ/Temp.db/.+png"
#define kRegxFeiShu                             @"/Users/[^/]+/Library/Application Support/LarkShell/OptimizeImage/.+jpeg"
#define kRegxFeiShuInternal                     @"/Users/[^/]+/Library/Application Support/LarkInternational/OptimizeImage/.+jpeg"
#define kRegxFeiShuAppstore                     @"/Users/[^/]+/Library/Containers/com.bytedance.macos.feishu/Data/Library/Application Support/LarkShell/OptimizeImage/.+jpeg"
#define kRegxWechat                             @"/Users/[^/]+/Library/Containers/com.tencent.xinWeChat/Data/Library/Application Support/com.tencent.xinWeChat/.+/Message/MessageTemp/.+pic(_hd)?.jpg"
#define kRegxWechatFile                         @"/Users/[^/]+/Library/Containers/com.tencent.xinWeChat/Data/Library/Application Support/com.tencent.xinWeChat/.+/Message/MessageTemp/.+OpenData/.+"
#define kRegxWechatMsgFileCache                 @"/Users/[^/]+/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/[^/]+/msg/file/.+"
#define KRegxWechatSendCache                    @"/Users/[^/]+/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/[^/]+/cache/.+_send_temp"
#define kRegxWechat4File                        @"/Users/[^/]+/Library/Containers/com.tencent.xWeChat/Data/Documents/xwechat_files/[^/]+/msg/file/.+"
#define KRegWechat4FileCache                    @"/Users/[^/]+/Library/Containers/com.tencent.xWeChat/Data/Documents/xwechat_files/[^/]+/cache/.+_send_temp"
#define kRegxWechat4PNG                         @"/Users/[^/]+/Library/Containers/com.tencent.(xWeChat|xinWeChat)/Data/Documents/xwechat_files/[^/]+/temp/InputTemp/.+png"
#define kRegxWechat4PNGCache                    @"/Users/[^/]+/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/[^/]+/temp/[^/]+/[^/]+/Img/.+"
#define kRegxWechatFileTemp                     @"/Users/[^/]+/Library/Containers/com.tencent.xinWeChat/Data/Library/Application Support/com.tencent.xinWeChat/.+/Message/MessageTemp/.+"
#define kRegxWework                             @"/Users/[^/]+/Library/Containers/com.tencent.WeWorkMac/Data/Library/Application Support/WXWork/Temp/ScreenCapture/.+png"
#define kRegxWeworkFileUpload                   @"/Users/[^/]+/Library/Containers/com.tencent.WeWorkMac/Data/Documents/Profiles/.+/UploadFiles/Zips/.+zip"
#define KRegxWeworkZipCache                     @"/Users/[^/]+/Library/Containers/com.tencent.WeWorkMac/Data/Documents/Profiles/.+/Caches/Files/.+"
#define KRegxSunloginConfig                     @"/Users/[^/]+/Sunlogin/.+"
#define KRegxAnydeskConfig                      @"/Users/[^/]+/[.]anydesk/.+"
#define KRegxiCloundCache                       @"/Users/[^/]+/Library/Mobile Documents/com~apple~CloudDocs/.+"
//#define KRegxOneDriveCache                      @"/Users/[^/]+/Library/Group Containers/[^/]+/OneDrive.noindex/Staging/.+staging"
#define KRegxOneDriveCache                      @"/Users/[^/]+/Library/CloudStorage/OneDrive.+"
#define KRegxGoogleDriveCache                   @"/Users/[^/]+/Library/CloudStorage/GoogleDrive.+"
#define KRegxDropboxCache                       @"/Users/[^/]+/Dropbox/.+"
#define KRegxUserLibrary                        @"/Users/[^/]+/Library/.+"
#define KRegxCoremail                           @"/Users/[^/]+/Library/Application Support/.Cm/CMClient/temp/temp_[^/]+/compose/newatt_.+"
#define KRegxWpscloudGlobalCache                @"/Users/[^/]+/Library/Containers/com.kingsoft.wpsoffice.mac.global/Data/Library/Application Support/Kingsoft/WPS Cloud Files/userdata/[^/]+/filecache/[^.].+"

#define KRegxWpscloudOldCache                   @"/Users/[^/]+/Library/Containers/com.kingsoft.wpsoffice.mac(.global)?/Data/Library/Application Support/Kingsoft/WPS Cloud Files/userdata/[^/]+/filecache/[^.].+"

#define KRegxWpscloudCache                      @"/Users/[^/]+/Library/Containers/com.kingsoft.wpsoffice.mac(.global)?/Data/Library/Application Support/Kingsoft/WPS Cloud Files/userdata/[^/]+/filecache/[.][^/]+/pre_cloudfile/.+"

#define KRegxWpscloudUploadCache                @"/Users/[^/]+/Library/Containers/com.kingsoft.wpsoffice.mac(.global)?/Data/Library/Application Support/Kingsoft/WPS Cloud Files/userdata/[^/]+/filecache/[.][^/]+/cachedata/.+"

#define KRegxWpsAutoCache                @"/Users/[^/]+/Library/Containers/com.kingsoft.wpsoffice.mac(.global)?/Data/Library/Application Support/Kingsoft/WPS Cloud Files/userdata/[^/]+/filecache/[.][^/]+/cachedata/[^/]+/[{][^}]+[}]-[0-9]+"

#define KRegxWpsBackupCache                     @"/Users/[^/]+/Library/Containers/com.kingsoft.wpsoffice.mac(.global)?/Data/Library/Application Support/Kingsoft/office[^/]+/OfficeSpace/batchuploadcache/.+"

#endif /* Consts_h */

//ddr

#define kYunshuConfigDDRPath                    @"/opt/.yunshu/config/ddr_config"

// EDR子功能开关宏定义
#define EDR_FEATURE_PROCESS_START               0x00000001  // 进程启动检测
#define EDR_FEATURE_PROCESS_TREE                0x00000002  // 进程树(依赖进程启动)
#define EDR_FEATURE_FILE_CREATE                 0x00000004  // 文件创建检测
#define EDR_FEATURE_FILE_RENAME                 0x00000008  // 文件重命名检测
#define EDR_FEATURE_NETWORK_MONITOR             0x00000010  // 网络监测

// 复合功能开关
#define EDR_FEATURE_FILE_ALL                    (EDR_FEATURE_FILE_CREATE | EDR_FEATURE_FILE_RENAME)
#define EDR_FEATURE_PROCESS_ALL                 (EDR_FEATURE_PROCESS_START | EDR_FEATURE_PROCESS_TREE)
#define EDR_FEATURE_ALL                         (EDR_FEATURE_PROCESS_ALL | EDR_FEATURE_FILE_ALL | EDR_FEATURE_NETWORK_MONITOR)

// 特殊功能组合
#define EDR_FEATURE_OFF                         (EDR_FEATURE_PROCESS_TREE)  // 仅进程树功能：监听进程起停事件维护进程树，但不进行威胁检测
