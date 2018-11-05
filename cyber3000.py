import grp
import pwd
import re
import subprocess
from pathlib import Path

'''
Possibly use this solution to make this work in windows:
https://stackoverflow.com/a/16529231/5434860
'''


def get_users():
    """
    :return: All the users with UIDs in range [1000, 65534)
    """
    return set(entry for entry in pwd.getpwall()
               if entry.pw_uid in range(1000, 65534))


def get_groups(username):
    """
    Reference: https://stackoverflow.com/a/9324811/5434860
    :param username: The name of the user
    :return: A collection of groups
    """
    groups = [g for g in grp.getgrall() if username in g.gr_mem]
    gid = pwd.getpwnam(username).pw_gid
    groups.append(grp.getgrgid(gid))
    return groups


def is_admin(username):
    return any(g.gr_name == "sudo" for g in get_groups(username))


def user_test():
    admins_string = input("Please input all admins separated by a space:")
    authorized_users_string = input("Please input all authorized users separated by a space:")

    admins = [s for s in admins_string.split(" ") if s]
    authorized_users = [s for s in authorized_users_string.split(" ") if s]

    expected_all_users = admins + authorized_users

    all_users = [entry.pw_name for entry in get_users()]
    print("inputted users: " + str(expected_all_users))
    print("system users: " + str(all_users))
    print()
    perfect = True
    for username in all_users:
        should_be_admin = username in admins
        should_be_standard = username in authorized_users
        if not should_be_admin and not should_be_standard:
            print("User: {} shouldn't exist but it does!".format(username))
            perfect = False
            continue
        if should_be_admin and should_be_standard:
            print("You entered {} twice!".format(username))
            perfect = False
            continue
        if is_admin(username):
            if not should_be_admin:
                print("{} should not be an admin!".format(username))
                perfect = False
        else:  # not admin
            if not should_be_standard:
                print("{} is supposed to be an admin!".format(username))
                perfect = False

    for username in expected_all_users:
        if username not in all_users:
            print("There's no user " + username)
            perfect = False

    if perfect:
        print("Everything is perfect!")


def log_guest_account():
    path = Path("/etc/lightdm/lightdm.conf")
    if not path.exists():
        directory = Path("/etc/lightdm/lightdm.conf.d")
        if directory.exists() and directory.is_dir():
            for p in directory.iterdir():
                if p.name.endswith(".conf"):
                    path = p
                    break
        if not path.exists():
            print("{} doesn't exist so we are unable to read contents of lightdm.conf"
                  .format(path.absolute()))
            return
    with path.open() as f:
        s = f.read()
        no_guest = "allow-guest=false" in s
        yes_guest = "allow-guest=true" in s
        maybe_guest = "allow-guest" in s
        print(path)
        if yes_guest:
            print("Guest account is explicitly allowed! Why would you do that?")
        elif no_guest:
            print("Guest account is explicitly disabled! Yay!")
        elif maybe_guest:
            print("Guest account configuration is explicitly stated, but the formatting is off.")
        else:
            print("Guest account is enabled! Bad!")

        if "autologin-user" in s:
            print("Auto login explicitly stated! Probably bad.")

    print()


def log_ssh():
    path = Path("/etc/ssh/sshd_config")
    if not path.exists():
        print("{} doesn't exist! ssh must not be installed! "
              "(sudo apt-get install openssh-server)".format(path))
        return
    with path.open() as f:
        s = f.read()
        print(path)
        if "#PermitRootLogin" in s:
            print("The PermitRootLogin configuration is commented out!")
        elif "PermitRootLogin yes" in s:
            print("The PermitRootLogin configuration is allowed! The is usually bad!")
        elif "PermitRootLogin no" in s:
            print("The PermitRootLogin configuration is now allowed! Hurray!")
        elif "PermitRootLogin prohibit-password" in s or "PermitRootLogin without-password" in s:
            print("The PermitRootLogin configuration is allowed by logging in using keys.")
        else:
            print("The PermitRootLogin configuration is nowhere to be found!")

    print()


def log_firewall():
    process = subprocess.Popen("ufw status", shell=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    process.wait()
    if process.returncode == 0:  # success
        print("firewall status: " + str(process.stdout.read()))
    elif process.returncode == 1:
        print("You must be root to read the ufw status")
    elif process.returncode == 127:
        print("ufw not installed!")
    else:
        print("Unknown error code: {}".format(process.returncode))
    print()


def log_password_history():
    path = Path("/etc/login.defs")
    with path.open() as f:
        lines = f.readlines()
        max_days = None
        min_days = None
        warn_age = None
        for line in lines:
            line = line[:-1]
            if line.startswith("PASS_"):
                split = re.split("\W+", line)
                if line.startswith("PASS_MAX_DAYS"):
                    max_days = int(split[-1])
                elif line.startswith("PASS_MIN_DAYS"):
                    min_days = int(split[-1])
                elif line.startswith("PASS_WARN_AGE"):
                    warn_age = int(split[-1])

        print(path)
        print("Password history settings: max days: {}\tmin days:{}\twarn age:{}"
              .format(max_days, min_days, warn_age))
        if max_days is None:
            print("Password max days is not defined")
        if min_days is None:
            print("Password min days is not defined")
        if warn_age is None:
            print("Password warn age is not defined")

        if max_days != 90:
            print("Password max days should be 90. It's {}".format(max_days))
        else:
            print("Max days is correct.")

        if min_days != 10:
            print("Password min days should be 10. It's {}".format(min_days))
        else:
            print("Min days is correct.")

        if warn_age != 7:
            print("Password warn age should be 7. It's {}".format(warn_age))
        else:
            print("Password warn age is correct.")

        print()


def log_lockout():  # TODO
    path = Path("/etc/pam.d/common-auth")


def main():
    log_guest_account()
    log_ssh()
    log_firewall()
    log_password_history()
    user_test()


if __name__ == '__main__':
    main()
