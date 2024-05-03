from pwn import log,process,ELF
from colorama import Fore, Back, Style
from tabulate import tabulate
# from time import sleep

class Find:
    def __init__(self,decode:bool=True,verbose:bool=False):
        self.decode = decode
        self.res:list[list] = []
        self.verbose = verbose
    def check(self):
        """check
            check for invalid options
        Returns:
            error or None
        """
        pass
    
    def exists(self,target):
        # TODO : modify this method
        if not self.res:
            return log.error(f"you should be call start() first")
        for index,value in self.res:
            if value == target:
                return True
        return False


class FindInObjects(Find):
    def __init__(self,exploit,decode:bool=True,verbose:bool=False):
        self.exploit = exploit
        super().__init__(decode,verbose)
    
    def start(self):
        self.check()
        self.res = []
        header = ["index","value"]
        outputs = self.exploit()
        
        for index,value in enumerate(outputs):
            if type(value).__name__ == "bytes" and self.decode:
                value = value.decode('utf-8')
            else:
                return log.error("if decode is true list elements must be bytes")
            if value.endswith('00'):
                self.res.append([index+1,value])
        
        
        if self.verbose:
            table = tabulate(self.res,headers=header,tablefmt="grid")
            log.warning(f"find [{len(self.res)}] objects of [{len(outputs)}]")
            print(table)
            
        return self.res

        
    

class FindByPlan(Find):
    """FindByPlan
        find canary with plan (exploit function)
    """
    def __init__(self,plan,order:int=50,sleep:float=.5,**kwargs):
        """FindByPlan

        Args:
            plan (function): function to go to f-string vuln
            order (int, optional): process count. Defaults to 50.
            sleep (float, optional): sleep beetwen each process. Defaults to .5.
            decode (bool, optional): decode output to utf-8. Defaults to True.
        """
        self.order = order
        self.sleep = sleep
        self.plan = plan
        # self.q = "00"
        # self.lines = 1
