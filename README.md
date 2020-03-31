# cors-relay CORS系统中继程序

基于 Ntrip 协议实现的可用于 CORS 网络差分中继的 Ntrip Caster 服务程序。C 语言编写，支持 Linux 和 Windows，单线程，高并发（基于 libev）。

## 原理
cors-relay 实现了 Ntrip Caster 协议和 Ntrip Client 协议（均为1.0版本），当有客户端连接时，会创建一个到源 CORS 服务器的 Client 连接，将客户端的 GGA 数据转发到源 CORS 服务，并将源 CORS 返回的差分数据转发给客户端。细节如下：

+ 客户端接入时验证将与数据库中的用户名密码进行比对验证，失败将拒绝连接。
+ 支持客户端的 sourcetable 源列表请求。
+ 客户端连接后，将会从数据库中选择一个未正在使用的源 CORS 信息（用户名密码、服务器），同步创建一个 Ntrip Client 连接到源 CORS，后续将转发客户端的 GGA 数据和源 CORS 的差分数据，实现中继功能。
+ 客户端和源 CORS 连接会状态同步，即客户端断开，源 CORS 连接也会断开（如果是最后一个客户端的话）；源 CORS 连接断开，也会断开客户端的连接。
+ 相同的用户名密码客户端重复连接时，将挤出之前的客户端。
+ 如果新客户端的位置与已有客户端相差不大（当前是30km，可代码中修改）且使用相同的挂载点，则会直接复用已有的源 CORS 连接（1+1基准站流动站作业支持基站距离移动站50KM以内，都可以实现RTK固定解算）。

以上是 cors-relay 的原理，实际应用中 cors-relay 可以解决的需求场景包括：
1. 源 CORS 的服务重分发以及高效利用。使用多个源 CORS 帐号建立帐号池，然后使用 cors-relay 创建多用户，在保证源 CORS 帐号安全的情况下，重分发 CORS 服务。这么做，可以将包月包年的源 CORS 服务以灵活的服务期限进行分发（包天，包周，甚至几个小时）。同时，因为用户一般不会同时进行连接，那么可以进行超量分发，类似于飞机票的“超卖”。
2. 同地区的差分广播。利用 cors-relay 客户端差分数据复用的特性，可以利用 1 个 CORS 帐号，实现地区的无限制差分数据服务，覆盖范围可以达到1000平方公里（30km x 30km）。
3. 源 CORS 的安全分享。在不失去已有 CORS 帐号的安全控制前提下，提供新的用户名密码分发已有 CORS 服务给第三方。

cors-relay 提供一个管理接口，可以用于用户创建、更新，源 CORS 增加、更新，实时连接查询等。cors-relay 也会输出连接日志，并周期打印客户端详细信息。

## 编译

支持 Windows 和 Linux 系统上编译，依赖工具 cmake、git，依赖库 libev 和 sqlite3。在 Debian/Ubuntu 上可以使用 `apt-get install libev-dev libsqlite3-dev` 来安装依赖库。

编译
```shell
git clone https://github.com/tisyang/cors-relay.git
cd cors-relay
git submodule update --init

mkdir build
cd build
cmake ..
make
```
`build` 目录下的 `cors-relay` 为编译的可执行文件。

## 使用

cors-relay 默认的帐号及源 CORS 数据均保存在数据库中（sqlite3），默认的文件名为 `cors-relay.db`。
通常可以使用管理接口来进行管理，而不是使用数据操作数据库。

### 管理接口

管理接口以 TCP Server 端口形式提供，默认端口号为 8000（可以在代码中修改)，管理命令为文本格式，提供的管理命令均会使用密码进行验证，确保命令来源可信。管理密码通过环境变量 `CONSOLE_PASSWD` 设置，默认为 `passwd`.

管理接口提供以下命令：

####  USER-LIST 列出所有用户
格式为 `USER-LIST passwd`，命令返回数据库中所有有效的用户名密码，执行正常返回格式为:

```text
OK USER-LIST\r\n
user:pass  2020-12-31 23:59:59\r\n
...\r\n
\r\n
```
其中 `\r\n` 为回车换行，每个用户名密码以冒号分隔，然后是该帐号的过期时刻。

失败返回格式为 `ERROR xxxx\r\n`描述了错误信息。

#### USER-ADD 新增用户
格式为 `USER-ADD passwd user:pass EDATE [ETIME]`，其中 `EDATE` 为用户过期日期，`ETIME` 为过期时间，`ETIME` 为可选，默认为 `23:59:59`。命令向数据库中新增用户名密码以及有效期信息。

命令执行正常返回 `OK USER-ADD\r\n\r\n`，失败返回 `ERROR xxxx\r\n` 描述错误信息。

#### CLIENT-LIST 列出在线用户
格式为 `CLIENT-LIST passwd`, 命令会返回所有在线的用户名密码，执行正常返回格式为：

```text
OK CLIENT-LIST\r\n
user:pass  192.x.x.x 2020-03-31 10:00:00\r\n
...\r\n
\r\n
```
除了消息头和尾部`\r\n`，其他每行表示一个在线用户，分别表示用户名密码、IP地址和登录时间。

失败返回格式为 `ERROR xxxx\r\n`描述了错误信息。

#### USER-UPDATE 更新用户名密码
格式为 `USER-UPDATE passwd user newpass`，命令用于修改用户密码。

执行正常返回 `OK USER-UPDATE\r\n\r\n`，失败返回 `ERROR xxxx\r\n` 描述错误信息。

#### SOURCE-ADD 新增源 CORS 数据
格式为 `SOURCE-ADD passwd SERVER user:pass EDATE [ETIME]`，其中 `SERVER` 为 CORS 服务器 IP，`user:pass` 为 CORS 服务器用户名密码，`EDATE` 为过期日期，`ETIME` 为可选的过期时间，默认为 `23:59:59`。命令向数据库中新增一条源 CORS 数据。这里没有提供服务器端口信息，因为 cors-relay 约定自身监听的端口与源 CORS 端口一致。

执行正常返回 `OK SOURCE-ADD\r\n\r\n`，失败返回 `ERROR xxxx\r\n` 描述错误信息。

#### SOURCE-LIST 列出所有源 CORS 数据
格式为 `SOURCE-LIST passwd`，命令会输出所有的源 CORS 数据，执行正常返回格式：

```text
OK SOURCE-LIST\r\n
172.x.x.x user:pass 2020-12-31 23:59:59\r\n
...\r\n
\r\n
```
除了消息头和尾部`\r\n`，其他每行表示一条源 CORS 数据，分别表示IP地址、用户名密码、过期时间。

失败返回格式为 `ERROR xxxx\r\n`描述了错误信息。

### 备注

cors-relay 代码中默认监听 8000（管理端口），8001-8003（Caster端口）。8001-8003 为 Caster 服务端口，这些是针对 qx 设定的，可以根据实际需求修改代码。

8001-8003 服务的 sourcetable 源列表在代码中是复制 qx 的 3 个挂载点 `RTCM23_GPS/RTCM30_GG/RTCM32_GGB` 编写的，可以根据实际需求修改代码。

某些情况下，可能需要隐藏 cors-relay 的出口 IP，以避免被源 CORS 服务封禁。可以采取的方式有：
1. 网络代理。将 cors-relay 运行主机的出口网络配置代理至另外一台主机。
2. 跳板程序。参考 [tcpredirection](https://github.com/tisyang/tcpredirection)，将 cors-relay 的源 CORS IP 指向跳板程序所在主机。

## 其他
cors-relay 是经过实际验证的程序，但还有一些需要改进的地方：

1. 数据库。cors-relay 开始使用的是文本存储数据，后来迁移使用了 sqlite3，没有使用其他数据库是为了减少依赖。但从实际考量，使用其他独立数据库是一个比较明确的需求，只是目前没有太多时间进行改进。
2. 源列表。目前程序中是代码写死的源列表，虽然可以靠修改程序代码来适应需求，但这毕竟缺乏弹性。其实有一个更好的实现思路，详见下一条。

3. 基于 TCP 重实现。中继客户端和源 CORS 的连接使用 TCP 实现，在连接中同步解析数据，验证并替换客户端中的密码，以旁路中间人的方式操纵两个连接的数据。这样就无需 cors-relay 来提供源列表了。

## License 许可

BSD-3 开源许可证

## 联系我

lazy.tinker#outlook.com


