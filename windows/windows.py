from havoc import Demon, RegisterCommand, RegisterModule

BOF_PATH = "./bin/windows.x64.o"

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


def windows_list(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) != 0:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "this command does not take any argument")
        return False

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", BOF_PATH, packer.getbuffer(), False)

    return task_id

RegisterCommand(windows_list, "", "list_windows", "list windows", 0, "", "")