# SSH图形客户端

基于PyQt5和Paramiko开发的SSH隧道管理工具

## 功能特性
- 可视化SSH连接管理
- 本地端口隧道转发
- 连接配置加密存储
- 实时日志记录

## 安装要求
```bash
pip install -r requirements.txt
```

## 使用说明
1. 运行启动脚本
```bash
run.bat
```
2. 主界面操作：
   - 输入SSH连接信息
   - 添加/删除端口隧道
   - 查看实时日志

## 隧道配置示例
```ini
[SSH_TUNNEL]
local_port = 3306
remote_host = 127.0.0.1
remote_port = 3306
```

## 许可证
[GNU GPLv3 License](LICENSE) - 查看完整协议内容请访问[官方网站](https://www.gnu.org/licenses/gpl-3.0.html)