# i85-U01 R2 host facts (unelevated session) - 2026-10-14T18:16:12.9494427+08:00
## OS / host
whoami: nilar\15549
## token groups (csv, via System32 whoami.exe)
"Mandatory Label\Medium Mandatory Level","标签","S-1-16-8192","" "Everyone","已知组","S-1-1-0","必需的组, 启用于默认, 启用的组" "NT AUTHORITY\本地帐户和管理员组成员","已知组","S-1-5-114","只用于拒绝的组" "Nilar\docker-users","别名","S-1-5-21-2839165489-1832998833-1574237796-1005","必需的组, 启用于默认, 启用的组" "BUILTIN\Administrators","别名","S-1-5-32-544","只用于拒绝的组" "BUILTIN\Users","别名","S-1-5-32-545","必需的组, 启用于默认, 启用的组" "NT AUTHORITY\INTERACTIVE","已知组","S-1-5-4","必需的组, 启用于默认, 启用的组" "CONSOLE LOGON","已知组","S-1-2-1","必需的组, 启用于默认, 启用的组" "NT AUTHORITY\Authenticated Users","已知组","S-1-5-11","必需的组, 启用于默认, 启用的组" "NT AUTHORITY\This Organization","已知组","S-1-5-15","必需的组, 启用于默认, 启用的组" "MicrosoftAccount\1554997790@qq.com","用户","S-1-11-96-3623454863-58364-18864-2661722203-1597581903-1862480077-4060098054-1386230434-3940352901-1210781871","必需的组, 启用于默认, 启用的组" "NT AUTHORITY\本地帐户","已知组","S-1-5-113","必需的组, 启用于默认, 启用的组" "LOCAL","已知组","S-1-2-0","必需的组, 启用于默认, 启用的组" "NT AUTHORITY\云帐户身份验证","已知组","S-1-5-64-36","必需的组, 启用于默认, 启用的组"
## token privileges
 特权信息 ----------------------  特权名                        描述                 状态   ============================= ==================== ====== SeShutdownPrivilege           关闭系统             已禁用 SeChangeNotifyPrivilege       绕过遍历检查         已启用 SeUndockPrivilege             从扩展坞上取下计算机 已禁用 SeIncreaseWorkingSetPrivilege 增加进程工作集       已禁用 SeTimeZonePrivilege           更改时区             已禁用
## build
ProductName=Windows 10 Pro
DisplayVersion=26H2
CurrentBuild=26300
UBR=9457
OSArchitecture=AMD64
PSVersion=5.1.26100.9444
## admin probes (non-elevated expectations)
net session rc=2 out=发生系统错误 5。 System.Management.Automation.RemoteException 拒绝访问。 System.Management.Automation.RemoteException
## key env presence (value NEVER printed)
DEEPSEEK_API_KEY present=True length=35
NODE_OPTIONS=
HTTPS_PROXY= HTTP_PROXY=
