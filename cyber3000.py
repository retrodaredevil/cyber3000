import grp
import pwd
import re
import subprocess
from pathlib import Path

try:
    import apt
except ImportError:
    apt = None

'''
Possibly use this solution to make this work in windows:
https://stackoverflow.com/a/16529231/5434860
'''

ACCOUNT_POLICY_LINE = "auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800"
ALWAYS_REPORT_PACKAGES = ["openssh-server", "clamav", "auditd"]
"""Packages that the user may want to install or uninstall"""
REPORT_INSTALLED_PACKAGES = ["kismet", "ophcrack", "apache", "nmap", "zenmap"]
"""Packages that the user may want to uninstall"""
REPORT_INSTALLED_PACKAGES_CONTAINS = ["freeciv", "wireshark"]
"""Names contained in packages that the user may want to uninstall"""


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
    else:
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
                print(
                    "Guest account configuration is explicitly stated, but the formatting is off.")
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
    else:
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
    process = subprocess.Popen("ufw status", shell=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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


def log_lockout_policy():
    path = Path("/etc/pam.d/common-auth")
    with path.open() as f:
        lockout_line = None
        for line in f.readlines():
            if line.startswith("auth required pam_tally2.so"):
                lockout_line = line
                break
        print(path)
        if lockout_line is not None:
            print("Account policy line found: '{}'".format(lockout_line))
            print("It should have the same values as: '{}'".format(ACCOUNT_POLICY_LINE))
        else:
            print("Account policy line not found. Add '{}'".format(ACCOUNT_POLICY_LINE))

        print()


def log_password_policy():
    path = Path("/etc/pam.d/common-password")
    with path.open() as f:
        basic_line = None
        cracklib_line = None
        for line in f.readlines():
            if "pam_unix.so" in line:
                basic_line = line
            if "pam_cracklib.so" in line:
                cracklib_line = line

        print(path)
        if basic_line is not None:
            print("On line with pam_unix.so...")
            if "remember" in basic_line:
                print("\tYay! We're enforcing a password history!")
            else:
                print("\tWe need to enforce a password history using remember=5")
            if "minlen" in basic_line:
                print("\tYay! We're enforcing a min length!")
            else:
                print("\tYou need to enforce a min length with minlen=8")
        else:
            print("For what ever reason, the line with pam_unix.so isn't here!")

        if cracklib_line is not None:
            print("On line with pam_cracklib.so...")
            if "ucredit" in cracklib_line:
                print("\tYay! You're enforcing uppercase!")
            else:
                print("\tYou need to enforce uppercase with ucredit=")
            if "lcredit" in cracklib_line:
                print("\tYay! You're enforcing lowercase!")
            else:
                print("\tYou need to enforce lowercase with lcredit=")
            if "dcredit" in cracklib_line:
                print("\tYay! You're enforcing a number!")
            else:
                print("\tYou need to enforce a number with dcredit=")
            if "ocredit" in cracklib_line:
                print("\tYay! You're enforcing a symbol!")
            else:
                print("\tYou need to enforce a symbol with ocredit=")
        else:
            print("Line with pam_cracklib.so not found! "
                  "Remember (sudo apt install libpam-cracklib)")

        print()


def log_home_directory_permissions():
    correct = 0
    incorrect = 0
    for user in get_users():
        home = Path(user.pw_dir)
        permission = home.stat().st_mode
        if permission & 0o750 != 0o750:
            incorrect += 1
            print("{}'s home directory has incorrect permission level.".format(user.pw_name))
        else:
            correct += 1

    print("{} have the correct home directory permission and {} have an incorrect permission. "
          "(Use chmod 0750 <HOME_DIRECTORY>)".format(correct, incorrect))
    print()


def log_installed_packages():
    if apt is None:
        print("Unable to report package status (sudo apt install python-apt)")
    else:
        cache = apt.Cache()
        for package in cache:
            package_name = str(package)
            if (package_name in ALWAYS_REPORT_PACKAGES
                    or (package.is_installed and (package_name in REPORT_INSTALLED_PACKAGES
                                                  or any(part in package_name for part in
                                                         REPORT_INSTALLED_PACKAGES_CONTAINS)))):
                print("{} Package {} {}installed"
                      .format("+ " if package.is_installed else "- ", package_name, "IS " if package.is_installed else "NOT "))

    print()


def main():
    log_guest_account()
    log_ssh()
    log_firewall()
    log_password_history()
    log_lockout_policy()
    log_password_policy()
    log_home_directory_permissions()
    log_installed_packages()
    print()
    user_test()


if __name__ == '__main__':
    main()
