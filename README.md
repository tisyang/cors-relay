# cors-relay CORS系统重分发程序

TODO

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

## License 开源许可

BSD-3 开源许可证

## 使用说明

TODO

