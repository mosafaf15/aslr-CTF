from pwn import *
from colorama import Fore, Back, Style
# from time import sleep


class find():
    def __init__(self) -> list:
        self.q = "00"
        self.return_type = "list"
        self.order = 50
        self.lines = 1
        self.sleep = 0.5
        self.op = "p"
        self.decode = True
        self.valid_types = ["list", "set", "tuple", "str", "dict"]

    def auto(self, exploit_function, file_name, **kwargs):
        if kwargs.get("query"):
            self.q = kwargs.get("query")
        if kwargs.get("return_type"):
            self.retrun_type = kwargs.get("return_type")
        if kwargs.get("order"):
            self.order = kwargs.get("order")
        if kwargs.get("lines"):
            self.lines = kwargs.get("lines")
        if kwargs.get("sleep"):
            self.sleep = kwargs.get("sleep")
        if kwargs.get("op"):
            self.op = kwargs.get("op")
        if kwargs.get("decode"):
            self.decode = kwargs.get("decode")
        elif self.return_type not in self.valid_types:
            return log.error(f"{Fore.WHITE} return_type only can be {Fore.GREEN} list, set, tuple, str, dict {Fore.WHITE} not {Fore.RED}{ self.return_type}")
        log.failure(f"starting ...")

    def custom(self, exploit_function, **kwargs):
        self.exploit_function = exploit_function
        if kwargs.get("query"):
            self.q = kwargs.get("query")
        if kwargs.get("return_type"):
            self.return_type = kwargs.get("return_type")
        exploit = self.exploit_function()
        res = []
        if not exploit or type(exploit).__name__ != 'list':
            return log.error(f"exploit function must return a list")
        elif self.return_type not in self.valid_types:
            return log.error(f"{Fore.WHITE} return_type only can be {Fore.GREEN} list, set, tuple, str, dict {Fore.WHITE} not {Fore.RED}{ self.return_type}")
        for element in exploit:
            if type(element).__name__ != "bytes":
                return log.error("all list elements must be bytes")
            else:
                if element.decode('utf-8').endswith(self.q):
                    res.append(
                        f"|{exploit.index(element)+1}| {element.decode()} ;")
        log.warn(f"find {len(res)} element with ({self.q}) query")
        if self.return_type == "str":
            return "".join(res).replace(";", "\n")
        elif self.return_type == "dict":
            dict_res = {}
            for i in res:
                splited_list = i.split()
                key = splited_list[0].replace("|", "")
                value = splited_list[1]
                dict_res.update({key: value})
            return dict_res
        else:
            return eval(f"{self.return_type}({res})")
