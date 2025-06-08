import ctypes
import re
import tkinter as tk
from functools import partial
from tkinter import messagebox as mb
from tkinter import ttk
from typing import Optional

import core

OPTIONS = ("关机", "重启", "广播窗口化", "消息", "命令提示符", "Powershell", "执行文件")


def _get_windows_scaling() -> float:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
    scale_factor = ctypes.windll.shcore.GetScaleFactorForDevice(0) / 100
    return max(1.0, scale_factor)  # 确保最小为1.0


class PromptEntry(tk.Frame):
    def __init__(self, master, prompt="输入", validate_type=None, **options):
        super().__init__(master, options)

        self.prompt = ttk.Label(self, text=f"{prompt}: ")
        self.prompt.grid(row=0, column=0)

        self.entry = ttk.Entry(self)
        self.entry.grid(row=0, column=1)

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
        self.combo.set("选择...")
        self.combo.pack(padx=5, pady=5)

    def __selection_change(self, event):
        self.event_generate(self.EVENT_NAME)

    @property
    def get(self):
        return self.combo.get()


class AddressEntries(tk.LabelFrame):
    def __init__(self, master, fill_ip: Optional[str] = None, fill_port: Optional[str] = "4705", **options):
        super().__init__(master, options)
        self["text"] = "目标"

        self.ip = PromptEntry(self, prompt="IP", validate_type="ip")
        self.ip.grid(row=0, column=0, padx=3, pady=3, sticky="w")
        self.port = PromptEntry(self, prompt="端口", validate_type="port")
        self.port.grid(row=1, column=0, padx=3, pady=3, sticky="w")

        if fill_ip:
            self.ip.entry.delete(0, tk.END)
            self.ip.entry.insert(0, fill_ip)
        if fill_port:
            self.port.entry.delete(0, tk.END)
            self.port.entry.insert(0, fill_port)

    @property
    def get(self):
        return self.ip.get, int(self.port.get)


class ShutdownInterface(tk.Frame):
    def __init__(self, master, **options):
        super().__init__(master, options)

        self.__init_widgets()

    def __init_widgets(self):
        self.address_entries = AddressEntries(self, fill_ip="127.0.0.1")  # debug
        self.address_entries.pack(padx=5, pady=5)


RestartInterface = WindowedInterface = AddressInterface = ShutdownInterface


class MsgInterface(tk.Frame):
    def __init__(self, master, **options):
        super().__init__(master, options)

        self.__init_widgets()
        self.__detect_modify()

    def __init_widgets(self):
        self.address_lf = AddressInterface(self)
        self.address_lf.pack(padx=5, pady=5)

        self.content_lf = ttk.Labelframe(self, text="消息")
        self.content_lf.pack(padx=5, pady=5)

        self.content_input = tk.Text(self.content_lf, width=30, height=5, font=("Consolas", 12))
        self.content_input.pack(padx=3, pady=3)

        self.input_size = ttk.Label(self.content_lf, text="0")
        self.input_size.pack(padx=3, pady=4, side="left")

        self.delete_btn = ttk.Button(self.content_lf, text="清空", width=5,
                                     command=lambda: self.content_input.delete("0.0", tk.END))
        self.delete_btn.pack(padx=3, pady=4, side="right")

    def __detect_modify(self):
        length = len(self.content_input.get("0.0", tk.END))
        self.input_size.config(text=f"{length}")
        if length > 449:
            self.input_size.config(foreground="red")
        elif length > 300:
            self.input_size.config(foreground="orange")
        else:
            self.input_size.config(foreground="black")
        self.after(100, self.__detect_modify)

    @property
    def get(self):
        return self.content_input.get("0.0", tk.END)


CmdInterface = PowershellInterface = ExecInterface = MsgInterface


class RootWindow(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.scale_factor = _get_windows_scaling()
        self.tk.call("tk", "scaling", self.scale_factor * 1.43)
        self.__init_widgets()
        self.__bind_events()

    def __send(self):
        global OPTIONS

        option = self.selection_frame.get

        if option == OPTIONS[0]:  # 关机
            addr = self.interfaces["shutdown"].address_entries.get
            try:
                target = core.Target(addr)
                target.shutdown()
            except ValueError:
                mb.showerror("错误", "无效的 IP 地址")
            except Exception as e:
                mb.showerror("错误", f"{type(e).__name__}: {e}")
                self.notice_label.config(text=":(", foreground="red")
                self.after(500, partial(self.notice_label.config, text="", foreground="black"))
            else:
                self.notice_label.config(text=":)", foreground="green")
                self.after(500, partial(self.notice_label.config, text="", foreground="black"))

        elif option == OPTIONS[1]:  # 重启
            addr = self.interfaces["restart"].address_entries.get
            try:
                target = core.Target(addr)
                target.restart()
            except ValueError:
                mb.showerror("错误", "无效的 IP 地址")
            except Exception as e:
                mb.showerror("错误", f"{type(e).__name__}: {e}")
                self.notice_label.config(text=":(", foreground="red")
                self.after(500, partial(self.notice_label.config, text="", foreground="black"))
            else:
                self.notice_label.config(text=":)", foreground="green")
                self.after(500, partial(self.notice_label.config, text="", foreground="black"))

        elif option == OPTIONS[2]:  # 窗口化
            addr = self.interfaces["windowed"].address_entries.get
            try:
                target = core.Target(addr)
                target.windowed()
            except ValueError:
                mb.showerror("错误", "无效的 IP 地址")
            except Exception as e:
                mb.showerror("错误", f"{type(e).__name__}: {e}")
                self.notice_label.config(text=":(", foreground="red")
                self.after(500, partial(self.notice_label.config, text="", foreground="black"))
            else:
                self.notice_label.config(text=":)", foreground="green")
                self.after(500, partial(self.notice_label.config, text="", foreground="black"))

        elif option == OPTIONS[3]:  # 消息
            addr = self.interfaces["msg"].address_lf.address_entries.get
            content = self.interfaces["msg"].get
            try:
                target = core.Target(addr)
                target.msg(content)
            except OverflowError:
                mb.showerror("错误", "消息长度大于上限 449 无法发送, 请减少字符数量!")
                self.notice_label.config(text=":(", foreground="red")
                self.after(500, partial(self.notice_label.config, text="", foreground="black"))
            except Exception as e:
                mb.showerror("错误", f"{type(e).__name__}: {e}")
                self.notice_label.config(text=":(", foreground="red")
                self.after(500, partial(self.notice_label.config, text="", foreground="black"))
            else:
                self.notice_label.config(text=":)", foreground="green")
                self.after(500, partial(self.notice_label.config, text="", foreground="black"))

        elif option == OPTIONS[4]:  # 命令提示符
            addr = self.interfaces["cmd"].address_lf.address_entries.get
            content = self.interfaces["cmd"].get
            try:
                target = core.Target(addr)
                target.cmd(content)
            except OverflowError:
                mb.showerror("错误", "消息长度大于上限 449 无法发送, 请减少字符数量!")
                self.notice_label.config(text=":(", foreground="red")
                self.after(500, partial(self.notice_label.config, text="", foreground="black"))
            except Exception as e:
                mb.showerror("错误", f"{type(e).__name__}: {e}")
                self.notice_label.config(text=":(", foreground="red")
                self.after(500, partial(self.notice_label.config, text="", foreground="black"))
            else:
                self.notice_label.config(text=":)", foreground="green")
                self.after(500, partial(self.notice_label.config, text="", foreground="black"))

        elif option == OPTIONS[5]:  # Powershell
            self.confirm_btn.config(state=tk.DISABLED)
            self.notice_label.config(text="没做好, 不许点!", font=("Microsoft Yahei", 14), foreground="red")
            self.after(1500, partial(self.notice_label.config, text="", foreground="black"))
            self.after(1500, partial(self.confirm_btn.config, state=tk.NORMAL))

        elif option == OPTIONS[6]:  # execute
            self.confirm_btn.config(state=tk.DISABLED)
            self.notice_label.config(text="没做好, 不许点!", font=("Microsoft Yahei", 14), foreground="red")
            self.after(1500, partial(self.notice_label.config, text="", foreground="black"))
            self.after(1500, partial(self.confirm_btn.config, state=tk.NORMAL))

    def __init_widgets(self) -> None:
        self.selection_frame = SelectionFrame(self, text="功能")
        self.selection_frame.pack(padx=5, pady=5)

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

        self.interfaces["cmd"].content_lf.config(text="命令")
        self.interfaces["powershell"].content_lf.config(text="命令")
        self.interfaces["execute"].content_lf.config(text="命令")

        for interface in self.interfaces.values():
            interface.pack_forget()

        self.notice_label = ttk.Label(self, font=("微软雅黑", 15))
        self.notice_label.pack_forget()

        self.confirm_btn = ttk.Button(self, text="发送", command=self.__send)
        self.confirm_btn.pack_forget()

    def __bind_events(self):
        self.bind(self.selection_frame.EVENT_NAME, self.__show_interface)

    def __hide_interfaces(self):
        for interface in self.interfaces.values():
            interface.pack_forget()
        self.notice_label.pack_forget()
        self.confirm_btn.pack_forget()

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

        self.notice_label.pack()
        self.confirm_btn.pack(padx=10, pady=10)


if __name__ == '__main__':
    app = RootWindow()
    app.title("Eeeeee")
    app.withdraw()
    app.deiconify()
    app.mainloop()
