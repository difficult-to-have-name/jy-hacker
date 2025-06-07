import ctypes
import re
import tkinter as tk
from tkinter import ttk

OPTIONS = ("关机", "重启", "广播窗口化", "消息", "命令提示符", "Powershell", "执行文件")


def _get_windows_scaling() -> float:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
    scale_factor = ctypes.windll.shcore.GetScaleFactorForDevice(0) / 100
    return max(1.0, scale_factor)  # 确保最小为1.0


class PromptEntry(tk.Frame):
    def __init__(self, master, prompt="输入", validate_type=None, **options):
        super().__init__(master, options)

        self.prompt = ttk.Label(self, text=f"{prompt}: ")
        self.prompt.grid(row=0, column=0, padx=10, pady=10)

        self.entry = ttk.Entry(self)
        self.entry.grid(row=0, column=1, padx=10, pady=10)

        if validate_type == "ip":
            self.__setup_ip_validation()
        elif validate_type == "port":
            self.__setup_port_validation()

    def __setup_ip_validation(self):
        validate_cmd = (self.register(self.__validate_ip), '%P')
        self.entry.config(
            validate="key",
            validatecommand=validate_cmd
        )

    def __setup_port_validation(self):
        validate_cmd = (self.register(self.__validate_port), '%P')
        self.entry.config(
            validate="key",
            validatecommand=validate_cmd
        )

    @staticmethod
    def __validate_ip(new_text):
        if not new_text:
            return True

        if new_text.lower() in ("localhost", "::1"):
            return True

        if new_text[-1] in ('.', ':'):
            return True

        ipv4_pattern = r'^(\d{1,3}\.){0,3}\d{0,3}$'
        if re.match(ipv4_pattern, new_text):
            parts = [p for p in new_text.split('.') if p]
            for part in parts:
                if not part.isdigit() or int(part) > 255:
                    return False
            return True

        ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){0,7}[0-9a-fA-F]{0,4}$'
        if re.match(ipv6_pattern, new_text):
            return True

        return False

    @staticmethod
    def __validate_port(new_text):
        if not new_text:
            return True

        if new_text.isdigit():
            port = int(new_text)
            return 0 <= port <= 65535
        return False

    @property
    def get(self):
        return self.entry.get()


class SelectionFrame(tk.LabelFrame):
    global OPTIONS
    __OPTIONS = OPTIONS
    EVENT_NAME = "<<SelectionChanged>>"

    def __init__(self, master, **options):
        super().__init__(master, options)

        self.__init_widgets()
        self.combo.bind("<<ComboboxSelected>>", self.__selection_change)

    def __init_widgets(self):
        self.combo = ttk.Combobox(self)
        self.combo["values"] = self.__OPTIONS
        self.combo["state"] = "readonly"
        self.combo.current(0)
        self.combo.pack(padx=10, pady=10)

    def __selection_change(self, event):
        self.event_generate(self.EVENT_NAME)

    @property
    def get(self):
        return self.combo.get()


class AddressEntries(tk.LabelFrame):
    def __init__(self, master, **options):
        super().__init__(master, options)
        self["text"] = "目标"

        self.ip = PromptEntry(self, prompt="IP", validate_type="ip")
        self.ip.grid(row=0, column=0, padx=5, pady=5)
        self.port = PromptEntry(self, prompt="端口", validate_type="port")
        self.port.grid(row=1, column=0, padx=5, pady=5)

    @property
    def get(self):
        return self.ip.get, self.port.get


class ShutdownInterface(tk.Frame):
    def __init__(self, master, **options):
        super().__init__(master, options)

        self.__init_widgets()

    def __init_widgets(self):
        self.address_entries = AddressEntries(self)
        self.address_entries.pack()


class RestartInterface(tk.Frame):
    def __init__(self, master, **options):
        super().__init__(master, options)


class WindowedInterface(tk.Frame):
    def __init__(self, master, **options):
        super().__init__(master, options)


class MsgInterface(tk.Frame):
    def __init__(self, master, **options):
        super().__init__(master, options)


class CmdInterface(tk.Frame):
    def __init__(self, master, **options):
        super().__init__(master, options)


class PowershellInterface(tk.Frame):
    def __init__(self, master, **options):
        super().__init__(master, options)


class ExecInterface(tk.Frame):
    def __init__(self, master, **options):
        super().__init__(master, options)


class RootWindow(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.scale_factor = _get_windows_scaling()
        self.tk.call("tk", "scaling", self.scale_factor * 1.43)
        self.__init_widgets()
        self.__bind_events()

    def __init_widgets(self) -> None:
        self.selection_frame = SelectionFrame(self, text="功能")
        self.selection_frame.pack(padx=10, pady=10)

        # 初始化所有界面但先隐藏
        self.interfaces = {
            "shutdown": ShutdownInterface(self),
            "restart": RestartInterface(self),
            "windowed": WindowedInterface(self),
            "msg": MsgInterface(self),
            "cmd": CmdInterface(self),
            "powershell": PowershellInterface(self),
            "execute": ExecInterface(self)
        }

        for interface in self.interfaces.values():
            interface.pack_forget()

        self.confirm_btn = ttk.Button(self, text="发送")
        self.confirm_btn.pack(padx=10, pady=10)

    def __bind_events(self):
        self.bind(self.selection_frame.EVENT_NAME, self.__show_interface)

    def __hide_interfaces(self):
        """隐藏所有界面"""
        for interface in self.interfaces.values():
            interface.pack_forget()

    def __show_interface(self, event):
        option = self.selection_frame.get
        self.__hide_interfaces()

        if option == OPTIONS[0]:  # 关机
            self.interfaces["shutdown"].pack()
        elif option == OPTIONS[1]:  # 重启
            self.interfaces["restart"].pack()
        elif option == OPTIONS[2]:  # 窗口化
            self.interfaces["windowed"].pack()
        elif option == OPTIONS[3]:  # 消息
            self.interfaces["msg"].pack()
        elif option == OPTIONS[4]:  # 命令提示符
            self.interfaces["cmd"].pack()
        elif option == OPTIONS[5]:  # Powershell
            self.interfaces["powershell"].pack()
        elif option == OPTIONS[6]:  # 执行文件
            self.interfaces["execute"].pack()


if __name__ == '__main__':
    app = RootWindow()
    app.withdraw()
    app.deiconify()
    app.mainloop()
