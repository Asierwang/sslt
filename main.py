import sys
import os
import configparser
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import select
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QLabel, QLineEdit, QPushButton, QTabWidget, QFormLayout, 
                             QListWidget, QMessageBox, QStatusBar)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QMutex
import socket
import threading
import logging
import datetime
import time

# 过滤Paramiko的TripleDES弃用警告
import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning, module='paramiko')

import paramiko
from paramiko import SSHClient, AutoAddPolicy

# 确保日志目录存在
log_dir = 'log'
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# 配置日志
log_filename = os.path.join(log_dir, datetime.datetime.now().strftime('%Y-%m-%d.log'))
logger = logging.getLogger('ssh_client')
logger.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

file_handler = logging.FileHandler(log_filename)
file_handler.setFormatter(formatter)

stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(stream_handler)

class TunnelManager:
    """管理隧道连接和线程"""
    def __init__(self):
        self.tunnels = {}
        self.lock = QMutex()
        self.running = True
    
    def add_tunnel(self, local_port, remote_host, remote_port, ssh_transport):
        self.lock.lock()
        try:
            if local_port in self.tunnels:
                return False
                
            # 创建本地监听socket
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(('127.0.0.1', local_port))
            listener.settimeout(1)  # 设置超时以便检查运行状态
            listener.listen(5)
            
            # 启动隧道线程
            thread = threading.Thread(
                target=self._tunnel_thread,
                args=(listener, remote_host, remote_port, ssh_transport),
                daemon=True
            )
            thread.start()
            
            self.tunnels[local_port] = {
                'listener': listener,
                'thread': thread,
                'remote_host': remote_host,
                'remote_port': remote_port,
                'active': True
            }
            return True
        except Exception as e:
            logger.error(f"创建隧道失败: {str(e)}")
            return False
        finally:
            self.lock.unlock()
    
    def _tunnel_thread(self, listener, remote_host, remote_port, ssh_transport):
        """隧道工作线程"""
        local_port = listener.getsockname()[1]
        logger.info(f"隧道监听在 127.0.0.1:{local_port}")
        try:
            while self.running:
                try:
                    # 使用select检查套接字状态
                    r, _, _ = select.select([listener], [], [], 1.0)
                    if not r:
                        continue
                        
                    client_sock, client_addr = listener.accept()
                    logger.info(f"来自 {client_addr} 的隧道连接")
                    
                    try:
                        # 通过SSH建立通道
                        chan = ssh_transport.open_channel(
                            'direct-tcpip',
                            (remote_host, remote_port),
                            client_addr
                        )
                    except Exception as e:
                        logger.error(f"隧道错误: {str(e)}")
                        client_sock.close()
                        continue
                    
                    # 双向转发数据
                    threading.Thread(
                        target=self._forward_data,
                        args=(client_sock, chan),
                        daemon=True
                    ).start()
                except socket.timeout:
                    # 超时是正常的，继续检查运行状态
                    continue
                except OSError as e:
                    if not self.running:
                        # 当管理器停止时，套接字被关闭是正常的
                        logger.info(f"隧道线程正常退出: {str(e)}")
                        break
                    else:
                        logger.error(f"隧道错误: {str(e)}")
                except Exception as e:
                    logger.error(f"隧道线程异常: {str(e)}")
        except Exception as e:
            logger.error(f"隧道线程终止: {str(e)}")
        finally:
            try:
                listener.close()
            except:
                pass
            logger.info(f"隧道线程已退出: 127.0.0.1:{local_port}")
    
    def _forward_data(self, sock, chan):
        """在socket和SSH通道之间转发数据"""
        try:
            while self.running:
                r, _, _ = select.select([sock, chan], [], [], 1.0)
                if not r:
                    continue
                    
                if sock in r:
                    try:
                        data = sock.recv(1024)
                        if not data:
                            break
                        chan.send(data)
                    except ConnectionResetError:
                        break
                if chan in r:
                    try:
                        data = chan.recv(1024)
                        if not data:
                            break
                        sock.send(data)
                    except paramiko.SSHException:
                        break
        except Exception as e:
            logger.debug(f"转发错误: {str(e)}")
        finally:
            try:
                sock.close()
            except:
                pass
            try:
                chan.close()
            except:
                pass
    
    def remove_tunnel(self, local_port):
        self.lock.lock()
        try:
            if local_port in self.tunnels:
                tunnel = self.tunnels.pop(local_port)
                try:
                    tunnel['listener'].close()
                except:
                    pass
                return True
        finally:
            self.lock.unlock()
        return False
    
    def close_all(self):
        self.running = False
        self.lock.lock()
        try:
            for port, tunnel in list(self.tunnels.items()):
                try:
                    tunnel['listener'].close()
                except:
                    pass
            self.tunnels.clear()
        finally:
            self.lock.unlock()

class SSHConnectionThread(QThread):
    connected = pyqtSignal()
    disconnected = pyqtSignal()
    error = pyqtSignal(str)
    tunnel_established = pyqtSignal(int, str, int)  # local_port, remote_host, remote_port
    
    def __init__(self, host, port, username, password, tunnels):
        super().__init__()
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.tunnels = tunnels  # 格式: [(local_port, remote_host, remote_port), ...]
        self.ssh_client = None
        self.transport = None
        self.tunnel_manager = TunnelManager()
        self.running = True
        self.active = False

    def run(self):
        logger.info(f'正在连接 {self.host}:{self.port} 用户 {self.username}')
        try:
            self.ssh_client = SSHClient()
            self.ssh_client.set_missing_host_key_policy(AutoAddPolicy())
            self.ssh_client.connect(
                self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=10,
                look_for_keys=False,
                allow_agent=False
            )
            self.transport = self.ssh_client.get_transport()
            self.active = True
            self.connected.emit()
            logger.info('连接成功')
            
            # 建立隧道
            for local_port, remote_host, remote_port in self.tunnels:
                try:
                    if self.tunnel_manager.add_tunnel(local_port, remote_host, remote_port, self.transport):
                        self.tunnel_established.emit(local_port, remote_host, remote_port)
                        logger.info(f'隧道建立: localhost:{local_port} -> {remote_host}:{remote_port}')
                except Exception as e:
                    error_msg = f'创建隧道失败 {local_port}->{remote_host}:{remote_port}: {str(e)}'
                    logger.error(error_msg)
                    self.error.emit(error_msg)
            
            # 保持连接
            while self.running and self.transport.is_active():
                self.msleep(1000)
                
        except Exception as e:
            error_msg = f'连接错误: {str(e)}'
            logger.error(error_msg)
            self.error.emit(error_msg)
        finally:
            self.active = False
            # 先关闭隧道
            self.tunnel_manager.close_all()
            # 再关闭SSH连接
            if self.ssh_client:
                try:
                    self.ssh_client.close()
                except:
                    pass
            self.disconnected.emit()
            logger.info('连接已关闭')

    def stop(self):
        self.running = False
        self.tunnel_manager.close_all()
        if self.ssh_client:
            try:
                self.ssh_client.close()
            except:
                pass
        self.wait(3000)  # 等待线程结束

class SSHClientApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('SSH图形客户端')
        self.setGeometry(100, 100, 800, 600)
        self.ssh_thread = None
        self.config_file = 'connections.ini'
        self.current_connection = None  # 跟踪当前加载的连接
        self.encryption_key = self.get_or_create_encryption_key()
        self.init_ui()
        self.load_saved_connections()

    def get_or_create_encryption_key(self):
        """获取或生成加密密钥，确保密钥一致性"""
        key_file = 'encryption.key'
        key_size = 32  # AES-256
        
        # 如果密钥文件存在，读取它
        if os.path.exists(key_file):
            try:
                with open(key_file, 'rb') as f:
                    key = f.read()
                    # 验证密钥长度
                    if len(key) == key_size:
                        return key
                    else:
                        logger.warning("密钥长度不正确，生成新密钥")
            except Exception as e:
                logger.error(f"读取密钥文件失败: {str(e)}")
        
        # 生成新密钥
        key = get_random_bytes(key_size)
        try:
            with open(key_file, 'wb') as f:
                f.write(key)
            logger.info("已生成新的加密密钥")
        except Exception as e:
            logger.error(f"保存密钥文件失败: {str(e)}")
            QMessageBox.critical(self, '错误', f'无法创建加密密钥: {str(e)}')
        
        return key

    def init_ui(self):
        # 创建中心部件和布局
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # 创建标签页
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # 连接标签页
        self.connection_tab = QWidget()
        self.tabs.addTab(self.connection_tab, 'SSH连接')
        self.init_connection_tab()

        # 隧道标签页
        self.tunnel_tab = QWidget()
        self.tabs.addTab(self.tunnel_tab, '端口隧道')
        self.init_tunnel_tab()

        # 状态栏
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage('就绪')

    def init_connection_tab(self):
        layout = QVBoxLayout(self.connection_tab)

        # 连接信息表单
        form_layout = QFormLayout()

        self.host_input = QLineEdit()
        self.port_input = QLineEdit('22')
        self.username_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)

        form_layout.addRow('主机:', self.host_input)
        form_layout.addRow('端口:', self.port_input)
        form_layout.addRow('用户名:', self.username_input)
        form_layout.addRow('密码:', self.password_input)

        # 按钮布局
        btn_layout = QHBoxLayout()
        self.connect_btn = QPushButton('连接')
        self.connect_btn.clicked.connect(self.connect_ssh)
        self.save_btn = QPushButton('保存连接')
        self.save_btn.clicked.connect(self.save_connection)
        self.load_btn = QPushButton('加载连接')
        self.load_btn.clicked.connect(self.load_connection)
        self.delete_btn = QPushButton('删除连接')
        self.delete_btn.clicked.connect(self.delete_connection)

        btn_layout.addWidget(self.connect_btn)
        btn_layout.addWidget(self.save_btn)
        btn_layout.addWidget(self.load_btn)
        btn_layout.addWidget(self.delete_btn)

        # 已保存连接列表
        self.connections_list = QListWidget()
        self.connections_list.doubleClicked.connect(lambda: self.load_connection(None))

        # 添加到主布局
        layout.addLayout(form_layout)
        layout.addLayout(btn_layout)
        layout.addWidget(QLabel('已保存连接:'))
        layout.addWidget(self.connections_list)

    def init_tunnel_tab(self):
        layout = QVBoxLayout(self.tunnel_tab)

        form_layout = QFormLayout()
        self.local_port_input = QLineEdit()
        self.remote_host_input = QLineEdit('127.0.0.1')
        self.remote_port_input = QLineEdit()

        form_layout.addRow('本地端口:', self.local_port_input)
        form_layout.addRow('远程主机:', self.remote_host_input)
        form_layout.addRow('远程端口:', self.remote_port_input)

        btn_layout = QHBoxLayout()
        self.add_tunnel_btn = QPushButton('添加隧道')
        self.add_tunnel_btn.clicked.connect(self.add_tunnel)
        self.remove_tunnel_btn = QPushButton('移除隧道')
        self.remove_tunnel_btn.clicked.connect(self.remove_tunnel)

        btn_layout.addWidget(self.add_tunnel_btn)
        btn_layout.addWidget(self.remove_tunnel_btn)

        self.tunnels_list = QListWidget()

        layout.addLayout(form_layout)
        layout.addLayout(btn_layout)
        layout.addWidget(QLabel('隧道列表:'))
        layout.addWidget(self.tunnels_list)

        self.tunnels = []

    def add_tunnel(self):
        local_port = self.local_port_input.text().strip()
        remote_host = self.remote_host_input.text().strip()
        remote_port = self.remote_port_input.text().strip()

        if not all([local_port, remote_host, remote_port]):
            QMessageBox.warning(self, '警告', '请填写所有隧道信息')
            return

        try:
            local_port = int(local_port)
            remote_port = int(remote_port)
            if not (1 <= local_port <= 65535) or not (1 <= remote_port <= 65535):
                raise ValueError
        except ValueError:
            QMessageBox.warning(self, '警告', '端口号必须是1-65535之间的整数')
            return

        # 检查本地端口是否已被占用
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(('127.0.0.1', local_port))
            sock.close()
        except socket.error:
            QMessageBox.warning(self, '警告', f'本地端口 {local_port} 已被占用')
            return
        except Exception as e:
            QMessageBox.warning(self, '警告', f'端口检查错误: {str(e)}')
            return

        tunnel_entry = (local_port, remote_host, remote_port)
        if tunnel_entry in self.tunnels:
            QMessageBox.warning(self, '警告', '该隧道已存在')
            return

        self.tunnels.append(tunnel_entry)
        self.tunnels_list.addItem(f'{local_port} -> {remote_host}:{remote_port}')

        # 清空输入
        self.local_port_input.clear()
        self.remote_port_input.clear()
        
        # 保存隧道到当前连接配置
        self.save_tunnel_to_config()

    def save_tunnel_to_config(self):
        """将当前隧道保存到配置文件中"""
        if not self.current_connection:
            # 如果没有加载连接，提示用户保存连接
            reply = QMessageBox.question(
                self,
                '保存隧道',
                '隧道信息需要保存到连接配置中。是否现在保存当前连接配置？',
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                self.save_connection()
            return
            
        # 保存到配置文件
        config = configparser.ConfigParser()
        if os.path.exists(self.config_file):
            config.read(self.config_file)

        if not config.has_section(self.current_connection):
            return

        # 保存隧道信息
        tunnels_str = ','.join([f'{l}:{r}:{p}' for l, r, p in self.tunnels])
        config.set(self.current_connection, 'tunnels', tunnels_str)

        try:
            with open(self.config_file, 'w') as f:
                config.write(f)
            self.status_bar.showMessage(f'隧道信息已保存到连接: {self.current_connection}')
        except Exception as e:
            QMessageBox.critical(self, '错误', f'保存隧道信息失败: {str(e)}')

    def remove_tunnel(self):
        current_item = self.tunnels_list.currentItem()
        if current_item:
            index = self.tunnels_list.row(current_item)
            self.tunnels_list.takeItem(index)
            del self.tunnels[index]
            # 保存隧道到当前连接配置
            self.save_tunnel_to_config()

    def connect_ssh(self):
        if self.ssh_thread and self.ssh_thread.isRunning():
            self.disconnect_ssh()
            return

        host = self.host_input.text().strip()
        port = self.port_input.text().strip()
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()

        if not all([host, port, username, password]):
            QMessageBox.warning(self, '警告', '请填写所有连接信息')
            return

        try:
            port = int(port)
            if not (1 <= port <= 65535):
                raise ValueError
        except ValueError:
            QMessageBox.warning(self, '警告', '端口号必须是1-65535之间的整数')
            return

        self.status_bar.showMessage('正在连接...')
        self.ssh_thread = SSHConnectionThread(host, port, username, password, self.tunnels)
        self.ssh_thread.connected.connect(self.on_connected)
        self.ssh_thread.disconnected.connect(self.on_disconnected)
        self.ssh_thread.error.connect(self.on_error)
        self.ssh_thread.tunnel_established.connect(self.on_tunnel_established)
        self.ssh_thread.start()
        self.connect_btn.setText('断开连接')
        self.set_ui_enabled(False)

    def disconnect_ssh(self):
        if self.ssh_thread and self.ssh_thread.isRunning():
            self.ssh_thread.stop()
            self.status_bar.showMessage('正在断开连接...')
            self.connect_btn.setEnabled(False)

    def on_connected(self):
        self.status_bar.showMessage('SSH连接成功')
        self.set_ui_enabled(True)

    def on_disconnected(self):
        self.connect_btn.setText('连接')
        self.connect_btn.setEnabled(True)
        self.status_bar.showMessage('连接已断开')
        self.set_ui_enabled(True)

    def on_error(self, error_msg):
        self.status_bar.showMessage(f'错误: {error_msg}')
        QMessageBox.critical(self, '错误', f'连接失败: {error_msg}')
        self.connect_btn.setText('连接')
        self.set_ui_enabled(True)
        if self.ssh_thread:
            self.ssh_thread.stop()

    def on_tunnel_established(self, local_port, remote_host, remote_port):
        """隧道建立时的槽函数 - 接收3个参数"""
        self.status_bar.showMessage(f'隧道: 本地 {local_port} -> {remote_host}:{remote_port}')
        QMessageBox.information(self, '隧道建立', 
                               f'隧道建立成功!\n本地端口: {local_port}\n远程目标: {remote_host}:{remote_port}')

    def set_ui_enabled(self, enabled):
        self.host_input.setEnabled(enabled)
        self.port_input.setEnabled(enabled)
        self.username_input.setEnabled(enabled)
        self.password_input.setEnabled(enabled)
        self.save_btn.setEnabled(enabled)
        self.load_btn.setEnabled(enabled)
        self.add_tunnel_btn.setEnabled(enabled)
        self.remove_tunnel_btn.setEnabled(enabled)
        self.tunnels_list.setEnabled(enabled)
        self.connections_list.setEnabled(enabled)
        self.delete_btn.setEnabled(enabled)

    def encrypt_password(self, password):
        """安全加密密码"""
        try:
            iv = get_random_bytes(AES.block_size)
            cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
            ct_bytes = cipher.encrypt(pad(password.encode(), AES.block_size))
            return base64.b64encode(iv + ct_bytes).decode()
        except Exception as e:
            logger.error(f"加密失败: {str(e)}")
            return ""

    def decrypt_password(self, encrypted_password):
        """安全解密密码"""
        if not encrypted_password:
            return ""
            
        try:
            data = base64.b64decode(encrypted_password)
            iv = data[:AES.block_size]
            ct = data[AES.block_size:]
            cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            return pt.decode()
        except Exception as e:
            logger.error(f"解密失败: {str(e)}")
            return ""

    def save_connection(self):
        host = self.host_input.text().strip()
        port = self.port_input.text().strip()
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()

        if not all([host, port, username, password]):
            QMessageBox.warning(self, '警告', '请填写所有连接信息')
            return

        connection_name = f'{username}@{host}:{port}'
        self.current_connection = connection_name  # 设置当前连接

        # 加密密码
        encrypted_password = self.encrypt_password(password)
        if not encrypted_password:
            QMessageBox.critical(self, '错误', '密码加密失败，请重试')
            return

        # 保存到配置文件
        config = configparser.ConfigParser()
        if os.path.exists(self.config_file):
            config.read(self.config_file)

        # 确保连接名称唯一
        if config.has_section(connection_name):
            reply = QMessageBox.question(
                self, 
                '确认', 
                f'连接 "{connection_name}" 已存在。是否覆盖？',
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.No:
                return
        else:
            config.add_section(connection_name)

        config.set(connection_name, 'host', host)
        config.set(connection_name, 'port', port)
        config.set(connection_name, 'username', username)
        config.set(connection_name, 'password', encrypted_password)

        # 保存隧道信息
        tunnels_str = ','.join([f'{l}:{r}:{p}' for l, r, p in self.tunnels])
        config.set(connection_name, 'tunnels', tunnels_str)

        try:
            with open(self.config_file, 'w') as f:
                config.write(f)
        except Exception as e:
            QMessageBox.critical(self, '错误', f'保存配置失败: {str(e)}')
            return

        # 更新连接列表
        if connection_name not in [self.connections_list.item(i).text() 
                                  for i in range(self.connections_list.count())]:
            self.connections_list.addItem(connection_name)
            
        QMessageBox.information(self, '成功', '连接已保存')

    def load_saved_connections(self):
        if not os.path.exists(self.config_file):
            return

        config = configparser.ConfigParser()
        try:
            config.read(self.config_file)
        except Exception as e:
            QMessageBox.warning(self, '警告', f'读取配置文件失败: {str(e)}')
            return

        self.connections_list.clear()
        for section in config.sections():
            self.connections_list.addItem(section)

    def delete_connection(self):
        """删除选中的连接"""
        current_item = self.connections_list.currentItem()
        if not current_item:
            return
            
        connection_name = current_item.text()
        
        reply = QMessageBox.question(
            self, 
            '确认删除', 
            f'确定要删除连接 "{connection_name}" 吗？',
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.No:
            return
            
        # 从配置文件中删除
        config = configparser.ConfigParser()
        if os.path.exists(self.config_file):
            config.read(self.config_file)
            
        if config.has_section(connection_name):
            config.remove_section(connection_name)
            
            try:
                with open(self.config_file, 'w') as f:
                    config.write(f)
            except Exception as e:
                QMessageBox.critical(self, '错误', f'删除连接失败: {str(e)}')
                return
                
        # 从列表中删除
        row = self.connections_list.row(current_item)
        self.connections_list.takeItem(row)
        
        # 如果删除的是当前连接，清除当前连接
        if self.current_connection == connection_name:
            self.current_connection = None
            
        QMessageBox.information(self, '成功', f'连接 "{connection_name}" 已删除')

    def load_connection(self, _):
        current_item = self.connections_list.currentItem()
        if not current_item:
            return

        connection_name = current_item.text()
        self.current_connection = connection_name  # 设置当前连接
        
        config = configparser.ConfigParser()
        try:
            config.read(self.config_file)
        except Exception as e:
            QMessageBox.warning(self, '警告', f'读取配置文件失败: {str(e)}')
            return

        if not config.has_section(connection_name):
            QMessageBox.warning(self, '警告', f'连接 "{connection_name}" 不存在')
            return

        # 加载基本连接信息
        self.host_input.setText(config.get(connection_name, 'host'))
        self.port_input.setText(config.get(connection_name, 'port'))
        self.username_input.setText(config.get(connection_name, 'username'))

        # 解密密码
        encrypted_password = config.get(connection_name, 'password')
        password = self.decrypt_password(encrypted_password)
        self.password_input.setText(password)

        # 加载隧道信息
        self.tunnels.clear()
        self.tunnels_list.clear()
        tunnels_str = config.get(connection_name, 'tunnels', fallback='')
        if tunnels_str:
            tunnels = tunnels_str.split(',')
            for tunnel in tunnels:
                if tunnel.strip():
                    parts = tunnel.split(':')
                    if len(parts) == 3:
                        try:
                            local_port = int(parts[0])
                            remote_host = parts[1]
                            remote_port = int(parts[2])
                            self.tunnels.append((local_port, remote_host, remote_port))
                            self.tunnels_list.addItem(f'{local_port} -> {remote_host}:{remote_port}')
                        except ValueError:
                            continue
                            
        QMessageBox.information(self, '成功', f'连接 "{connection_name}" 已加载')

    def closeEvent(self, event):
        if self.ssh_thread and self.ssh_thread.isRunning():
            self.ssh_thread.stop()
            # 等待线程结束
            if not self.ssh_thread.wait(3000):
                logger.warning("SSH线程未能在3秒内结束")
        event.accept()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = SSHClientApp()
    window.show()
    sys.exit(app.exec_())