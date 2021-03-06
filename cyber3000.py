import os
import platform
import re
import subprocess
import sys
from pathlib import Path
from argparse import ArgumentParser

try:
    import pwd
    import spwd
    import grp

    win32net = None
    win32netcon = None
except ImportError:
    pwd = None
    spwd = None
    grp = None
    try:
        import win32net
        import win32netcon
    except ImportError:
        win32net = None
        win32netcon = None

try:
    import apt
except ImportError:
    apt = None

ACCOUNT_POLICY_LINE = "auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800"
ALWAYS_REPORT_PACKAGES = ["openssh-server", "clamav", "auditd", "pure-ftpd", "apache2", "vsftpd", "unattended-upgrades"]
"""Packages that the user may want to install or uninstall"""
ALWAYS_REPORT_PACKAGES_SET = set(ALWAYS_REPORT_PACKAGES)
_HACKING_PACKAGES = ["airbase-ng", "acccheck", "ace-voip", "amap", "apache-users", "arachni",
                     "android-sdk", "apktool", "arduino", "armitage", "asleap", "automater",
                     "backdoor-factory", "bbqsql", "bed", "beef", "bing-ip2hosts", "binwalk",
                     "blindelephant", "bluelog", "bluemaho", "bluepot", "blueranger", "bluesnarfer",
                     "bulk-extractor", "bully", "burpsuite", "braa", "capstone", "casefile",
                     "cdpsnarf",
                     "cewl", "chntpw", "cisco-auditing-tool", "cisco-global-exploiter", "cisco-ocs",
                     "cisco-torch", "cisco-router-config", "cmospwd", "cookie-cadger", "commix",
                     "cowpatty", "crackle", "creddump", "crunch", "cryptcat", "cymothoa",
                     "copy-router-config", "cuckoo", "cutycapt", "davtest", "dbd", "dbpwaudit",
                     "dc3dd", "ddrescue", "deblaze", "dex2jar", "dff", "dhcpig", "dictstat", "dirb",
                     "dirbuster", "distorm3", "dmitry", "dnmap", "dns2tcp", "dnschef", "dnsenum",
                     "dnsmap", "dnsrecon", "dnstracer", "dnswalk", "doona", "dos2unix", "dotdotpwn",
                     "dradis", "dumpzilla", "eapmd5pass", "edb-debugger", "enum4linux", "enumiax",
                     "exploitdb", "extundelete", "fern-wifi-cracker", "fierce", "fiked", "fimap",
                     "findmyhash", "firewalk", "fragroute", "foremost", "funkload", "galleta",
                     "ghost-fisher", "giskismet", "grabber", "go-lismero", "goofile", "gpp-decrypt",
                     "gsad", "gsd", "gqrx", "guymager", "gr-scan", "hamster-sidejack",
                     "hash-identifier", "hexinject", "hexorbase", "http-tunnel", "httptunnel",
                     "hping3", "hydra", "iaxflood", "inguma", "intrace", "inundator", "inviteflood",
                     "ipv6-toolkit", "iphone-backup-analyzer", "intersect", "ismtp", "isr-evilgrade",
                     "jad", "javasnoop", "jboss-autopwn", "jd-gui", "john", "johnny", "joomscan",
                     "jsql", "kalibrate-rtl", "keepnote", "killerbee", "kismet", "keimpx",
                     "linux-exploit-suggester", "ldb", "lynis", "maltego-teeth", "magictree",
                     "masscan", "maskgen", "maskprocessor", "mdk3", "metagoofil", "metasploit",
                     "mfcuk", "mfoc", "mfterm", "miranda", "mitmproxy", "multiforcer",
                     "multimon-ng", "ncrack", "netcat", "nishang", "nipper-ng", "nmap", "ntop",
                     "oclgausscrack", "ohwurm", "ollydpg", "openvas-administrator", "openvas-cli",
                     "openvas-manager", "openvas-scanner", "oscanner", "p0f", "padbuster", "paros",
                     "parsero", "patator", "pdf-parser", "pdfid", "pdgmail", "peepdf",
                     "phrasendrescher", "pipal", "pixiewps", "plecost", "polenum", "policygen",
                     "powerfuzzer", "powersploit", "protos-sip", "proxystrike", "pwnat", "rcrack",
                     "rcrack-mt", "reaver", "rebind", "recon-ng", "redfang", "regripper",
                     "responder", "ridenum", "rsmangler", "rtlsdr-scanner", "rtpbreak", "rtpflood",
                     "rtpinsertsound", "rtpmixsound", "sakis3g", "sbd", "sctpscan", "setoolkit",
                     "sfuzz", "shellnoob", "sidguesser", "siparmyknife", "sipp", "sipvicious",
                     "skipfish", "slowhttptest", "smali", "smtp-user-enum", "sniffjoke", "snmpcheck",
                     "spooftootph", "sslcaudit", "sslsplit", "sslstrip", "sslyze", "sqldict",
                     "sqlmap", "sqlninja", "sqlsus", "statprocessor", "t50", "termineter",
                     "thc-hydra", "thc-ipv6", "thc-pptp-bruter", "thc-ssl-dos", "tnscmd10g",
                     "truecrack", "theharverster", "tlssled", "twofi", "u3-pwn", "uatester",
                     "urlcrazy", "uniscan", "unix-privesc-check", "vega", "w3af", "webscarab",
                     "webshag", "webshells", "webslayer", "websploit", "weevely", "wfuzz",
                     "wifi-honey", "wifitap", "wifite", "wireshark", "winexe", "wpscan",
                     "wordlists", "valgrind", "volatility", "voiphopper", "wol-e", "xspy", "xplico",
                     "xsser", "yara", "yersinia", "zaproxy"]
"""Many hacking tools. 
Source: https://github.com/moomanst/CBHelper/blob/master/Linux/Ubuntu/CyberPatriotBasics.sh"""
REPORT_INSTALLED_PACKAGES = ["kismet", "ophcrack", "apache", "nmap", "zenmap", "samba", "postgresql", "postgresql-contrib", "nginx", "proftpd"] + _HACKING_PACKAGES
"""Packages that the user may want to uninstall"""
REPORT_INSTALLED_PACKAGES_SET = set(REPORT_INSTALLED_PACKAGES)
REPORT_INSTALLED_PACKAGES_CONTAINS = ["freeciv", "wireshark", "cyphesis"]
"""Names contained in packages that the user may want to uninstall"""
REPORT_FILE_EXTENSIONS = ["mp3", "mov", "ogg", "mp4", "m4a", "avi", "flac", "flv", "mpeg", "mpg",
                          "gif", "png", "jpg", "jpeg"]
REPORT_FILE_EXTENSIONS_SET = set(REPORT_FILE_EXTENSIONS)
PASSWORD_MAX_DAYS = 90
PASSWORD_MIN_DAYS = 10
PASSWORD_WARN_DAYS = 7


def run_simple_command(command):
    """
    :param command: The command to run
    :return: stdout if successful, otherwise will return None
    """
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    process.wait()
    return process.stdout if process.returncode == 0 else None


def get_hostname():
    return platform.uname()[1]


def is_windows():
    return os.name == "nt"


def get_users_unix():
    """
    NOTE: This does not include the user "nobody"

    Only works on *nix

    :return: All the users with UIDs in range [1000, 65534)
    """
    return set(entry for entry in pwd.getpwall()
               if entry.pw_uid in range(1000, 65534))


def get_users_windows(level=3):
    """
    Only works on windows

    :param level: The information level of the data. (0, 1, 2, 3, 10, 11, 20, 23 or 24)
    :return: All the users. This includes Administrator, Guest and DefaultAccount
    """
    return win32net.NetUserEnum(platform.uname()[1], level)[0]


def get_user_info_windows(username, level=3):
    """

    :param username: The username
    :param level: The information level of the data. (0, 1, 2, 3, 10, 11, 20, 23 or 24)
    :return: Info about the user
    """
    return win32net.NetUserGetInfo(get_hostname(), username, level)


def get_users_names():
    """
    NOTE: If on windows, This includes Administrator, Guest and DefaultAccount

    Works on Windows and *nix

    :return: A collection of strings representing all the users on the system
    """
    if not pwd or not grp:
        if not win32net:
            raise RuntimeError("Not pwd or grp module and also no win32net found")
        return set(user["name"] for user in get_users_windows(level=0))
    return set(entry.pw_name for entry in pwd.getpwall()
               if entry.pw_uid in range(1000, 65534))


def get_groups_unix(username):
    """
    Reference: https://stackoverflow.com/a/9324811/5434860

    Only works on unix

    :param username: The name of the user
    :return: A collection of groups
    """
    groups = [g for g in grp.getgrall() if username in g.gr_mem]
    gid = pwd.getpwnam(username).pw_gid
    groups.append(grp.getgrgid(gid))
    return groups


def get_groups_names(username):
    """
    Works on windows and *nix
    :param username: A string representing a username
    :return: A set or list (collection) of group names that the user has
    """
    if not pwd or not grp:
        return win32net.NetUserGetLocalGroups(platform.uname()[1], username)
    groups = set(g.gr_name for g in grp.getgrall() if username in g.gr_mem)
    gid = pwd.getpwnam(username).pw_gid
    groups.add(grp.getgrgid(gid).gr_name)
    return groups


def is_admin(username):
    """
    Works on Windows and *nix
    :param username: A string representing a username
    :return: True or False depending on if the user is an admin
    """
    if not pwd or not grp:
        return "Administrators" in get_groups_names(username)
    return "sudo" in get_groups_names(username)


def print_path_expected(path):
    print("{} does not exist! Maybe you're using windows?".format(path))


def print_run_with_fix():
    print("Run with --fix to fix")


def user_test():
    admins_string = input("Please input all admins separated by a space:")
    authorized_users_string = input("Please input all authorized users separated by a space:")

    admins = [s for s in admins_string.split(" ") if s]
    authorized_users = [s for s in authorized_users_string.split(" ") if s]

    if is_windows():
        admins.append("Administrator")
        authorized_users.append("Guest")
        authorized_users.append("DefaultAccount")
        authorized_users.append("WDAGUtilityAccount")
        print("Windows detected. Automatically accounting for "
              "Administrator, Guest, DefaultAccount and WDAGUtilityAccount")

    expected_all_users = admins + authorized_users

    all_users = get_users_names()
    print("inputted users: " + str(expected_all_users))
    print("system users: " + str(all_users))
    perfect = True
    for username in all_users:
        should_be_admin = username in admins
        should_be_standard = username in authorized_users
        if not should_be_admin and not should_be_standard:
            print("{} shouldn't exist but they do!".format(username))
            perfect = False
            continue
        if should_be_admin and should_be_standard:
            print("You entered {} twice! Make sure you separate admins and standard users when you input."
                  .format(username))
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
            print("{} does not exist!".format(username))
            perfect = False

    if perfect:
        print("Everything is perfect with the users' groups!")


def log_no_password_required():
    print("Checking for users that don't require passwords...")
    if is_windows():
        for user in get_users_windows(level=3):
            if user["flags"] & win32netcon.UF_PASSWD_NOTREQD != 0:
                print("User: {} doesn't require a password to login! (May not be accurate)"
                      .format(user["name"]))
            if user["password_expired"] != 0:
                print("User: {} has an expired password! (This should be accurate)"
                      .format(user["name"]))
    else:
        try:
            perfect = True
            for user in spwd.getspall():
                password = user.sp_pwd
                while password.startswith("!"):
                    password = password[1:]
                if not password:
                    print("User: {} does not require a password! Bad!".format(user.sp_nam))
                    perfect = False

            if perfect:
                print("All users require passwords! Hurray!")
        except PermissionError:
            print("Unable to view account passwords. Run this script as sudo")

    print()


def log_admin_account_enabled(fix=False):
    if is_windows():
        admin_disabled = get_user_info_windows("Administrator", level=3)["flags"] \
                         & win32netcon.UF_ACCOUNTDISABLE != 0
        if admin_disabled:
            print("Administrator account is disabled! Yay!")
        else:
            print("Administrator account is enabled! Bad!")
    else:
        try:
            password = spwd.getspnam("root").sp_pwd
            if fix and not password.startswith("!"):
                print("Going to try to lock root account...")
                process = subprocess.Popen("passwd -l root", shell=True,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                process.wait()
                if process.returncode == 0:
                    print("Locked root account!")
                else:
                    print("Couldn't lock root account!")
                print()
                return
            if not password:
                print("No password for root set! Very bad!! "
                      "(sudo passwd root) (sudo passwd -l root)")
                print_run_with_fix()
            elif password.startswith("!!"):
                print("The password for the root account has been locked! Yay!")
            elif password.startswith("!"):
                print("The root account has been locked! Yay!")
            else:
                print("The root account is enabled! Bad! (sudo passwd -l root)")
                print_run_with_fix()
        except (PermissionError, KeyError):
            print("Unable to view if root account is enabled. Run this script as sudo.")
    print()


def log_guest_account(fix=False):
    """Logs if the guest account is disabled. Works on windows and *nix"""
    if is_windows():
        print("Windows detected. Checking if guest is disabled...")
        guest_disabled = get_user_info_windows("Guest")["flags"] & win32netcon.UF_ACCOUNTDISABLE != 0
        if not guest_disabled:
            if fix:
                print("Guest is enabled. Disabling...")
                process = subprocess.Popen("net user guest /active:no")
                process.wait()
                if process.returncode == 0:
                    print("Disabled Guest account!")
                else:
                    print("Couldn't disable guest account! (Run as Administrator)")
            else:
                print("Guest is ENABLED!!! BAD!! (net user guest /active:no)")
                print_run_with_fix()
        else:
            print("Guest is disabled! Yay!")
    else:
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
                    print("Guest account configuration is explicitly stated, but formatted bad.")
                else:
                    print("Guest account is enabled! Bad!")
                    if fix:
                        print("Trying to disable guest account...")
                        try:
                            with path.open("a") as append:
                                append.write("\n")
                                append.write("allow-guest=false\n")
                            print("Success!")
                        except PermissionError:
                            print("Fail!")
                    else:
                        print_run_with_fix()

                if "autologin-user" in s:
                    print("Auto login explicitly stated! Probably okay.")
    print()


def log_ubuntu_repos():
    updates_path = Path("/etc/apt/sources.list")
    print("Don't edit these files directly. Go to Software and Updates.")
    print(updates_path)
    if updates_path.exists():
        security = False
        recommended = False
        unsupported = False
        with updates_path.open() as f:
            for line in f.readlines():
                if line.startswith("#"):
                    continue

                if "-security" in line:
                    security = True
                elif "-updates" in line:
                    recommended = True
                elif "-backports" in line:
                    unsupported = True

        if security:
            print("\tSecurity updates are enabled! Yay!")
        else:
            print("\tSecurity updates are disabled! Bad!")

        if recommended:
            print("\tRecommended updates are enabled! Yay!")
        else:
            print("\tRecommended updates are disabled! Bad!")

        if unsupported:
            print("\tUnsupported updates are enabled! Usually bad!")
        else:
            print("\tUnsupported updates are disabled! Yay!")
    else:
        print("\tCouldn't find file! Is this ubuntu?")

    check_path = Path("/etc/apt/apt.conf.d/10periodic")
    print(check_path)
    if not check_path.exists():
        print("Couldn't find. Using this instead:")
        check_path = Path("/etc/apt/apt.conf.d/20auto-upgrades")
        print(check_path)
    if check_path.exists():
        settings_dict = {
            "Update-Package-Lists": None,
            "Download-Upgradeable-Packages": None,
            "AutocleanInterval": None,
            "Unattended-Upgrade": None
        }
        with check_path.open() as f:
            for line in f.read().split(";"):
                # credit to https://askubuntu.com/a/1060281
                # for future reference: https://askubuntu.com/a/868729
                # documentation: https://help.ubuntu.com/lts/serverguide/automatic-updates.html
                for key in settings_dict.keys():
                    if key in line:
                        split = line.split("\"")
                        if len(split) >= 2:
                            number_string = split[1]
                            try:
                                number = int(number_string)
                            except ValueError:
                                number = None
                            settings_dict[key] = number

        update_check_period = settings_dict["Update-Package-Lists"]
        if not update_check_period:
            print("\tAutomatic checking for updates is disabled! Bad!")
        elif update_check_period == 1:
            print("\tAutomatically checking for updates daily! Yay!")
        else:
            print("\tAutomatically checking for updates every {} days! Change to daily!".format(update_check_period))

        upgradeable_download_period = settings_dict["Download-Upgradeable-Packages"]
        if not upgradeable_download_period:
            print("\tNot set to automatically download upgradeable packages")
        else:
            print("\tSet to download upgradeable packages every {} day(s)".format(upgradeable_download_period))

        install_period = settings_dict["Unattended-Upgrade"]
        if not install_period:
            print("\tNot set to automatically install packages. (May need unattended-upgrades)")
        else:
            print("\tSet to install packages every {} day(s) (May need unattended-upgrades)".format(install_period))

        autoclean_period = settings_dict["AutocleanInterval"]
        if not autoclean_period:
            print("\tNot set to autoclean")
        else:
            print("\tSet to autoclean every {} day(s)".format(autoclean_period))

    else:
        print("\tCouldn't find 10periodic or 20auto-upgrades! Is this ubuntu?")

    print()


def log_ssh():
    """
    Logs ssh configurations

    For reference:
    http://tldp.org/LDP/solrhe/Securing-Optimizing-Linux-RH-Edition-v1.3/chap15sec122.html
    """
    path = Path("/etc/ssh/sshd_config")
    if not path.exists():
        print("{} doesn't exist! ssh must not be installed!".format(path))
    else:
        with path.open() as f:
            print(path)
            print("Also remember to set firewall rules!")
            found_root_login_line = False
            for line in f.readlines():
                line = line[0:-1]
                if "PermitRootLogin" in line:
                    found_root_login_line = True
                    if "#" in line:
                        print("found COMMENT referencing PermitRootLogin. line: '{}'".format(line))
                    elif "yes" in line:
                        print("found line permitting root login! Bad! line: '{}'".format(line))
                    elif "no" in line:
                        print("found line disallowing root login! Good! line: '{}'".format(line))
                    elif "prohibit-password" in line or "without-password" in line:
                        print("found line permitting root login via keys. Probably should be "
                              "changed to 'no' instead of 'prohibit-password'. line: '{}'"
                              .format(line))
                    else:
                        print("found a line with PermitRootLogin in it with unknown value? "
                              "Possibly corrupt file? line: {}".format(line))
                elif "IgnoreRhosts" in line:
                    if "#" not in line:
                        if "no" in line.replace("IgnoreRhosts", ""):
                            print("Rhosts are not being ignored! Bad! Change to no!")
                elif "StrictModes" in line:
                    if "#" not in line:
                        if "no" in line:
                            print("StrictModes is disabled! Bad!")
                elif "X11Forwarding" in line:
                    if "#" not in line:
                        if "yes" in line:
                            print("X11Forwarding is enabled! This should probably be disabled!")
                elif "RhostsAuthentication" in line:
                    if "#" not in line:
                        if "yes" in line:
                            print("RhostsAuthentication is enabled! Bad!")
                elif "RhostsRSAAuthenitcation" in line:
                    if "#" not in line:
                        if "yes" in line:
                            print("RhostsRSAAuthentication is enabled! Bad!")
                elif "RSAAuthentication" in line:
                    if "#" not in line:
                        if "no" in line:
                            print("RSAAuthentication is disabled! Enable for better security! line: {}".format(line))
                        elif "yes" in line:
                            print("RSAAuthentication is enabled! Yay!")
                elif "PasswordAuthentication" in line:
                    if "#" not in line:
                        if "no" in line:
                            print("PasswordAuthentication is disabled! VERY BAD!")
                elif "PermitEmptyPasswords" in line:
                    if "#" not in line:
                        if "yes" in line:
                            print("Empty passwords are permitted! This is insecure but is "
                                  "necessary if backing up files using scp.")
                elif "AllowUsers" in line:
                    print("AllowUsers line: '{}'".format(line))

            if not found_root_login_line:
                print("There is no line with 'PermitRootLogin' in it!")

    print()


def log_pure_ftp():
    def get_contents(path):
        if not path.exists():
            return None
        with path.open() as f:
            return f.read()

    install_path = Path("/etc/pure-ftpd")
    if not install_path.exists():
        print("pure-ftpd must not be installed because '{}' doesn't exist".format(install_path))
        print()
        return
    config_path = Path(install_path, "conf")
    if not config_path.exists():
        print("pure-ftpd is installed but has no conf folder. (Using an older configuration style?) '{}' "
              "does not exist.".format(config_path))
        print()
        return

    print(config_path)
    print("Also look at other options here: {}"
          .format("https://github.com/jedisct1/pure-ftpd/blob/master/pure-ftpd.conf.in"))
    print("Remember to set firewall rules!")

    tls_path = Path(config_path, "TLS")
    print("\t{}".format(tls_path))
    tls_contents = get_contents(tls_path)
    if not tls_contents:
        print("\t\tCouldn't find file! Needs to contain '2'")
    elif "2" in tls_contents:
        print("\t\tYay! Using TLS encryption only!")
    else:
        print("\t\tBad! Not using TLS encryption only! Needs to be set to '2'! Found '{}' instead".format(tls_contents))

    chroot_path = Path(config_path, "ChrootEveryone")
    print("\t{}".format(chroot_path))
    chroot_contents = get_contents(chroot_path)
    if not chroot_contents:
        print("\t\tCouldn't find file! Needs to contain 'yes'")
    elif "yes" in chroot_contents:
        print("\t\tChrootEveryone is enabled! Yay!")
    else:
        print("\t\tChrootEveryone is disabled! Bad! Found '{}'".format(chroot_contents))

    no_anonymous_path = Path(config_path, "NoAnonymous")
    print("\t{}".format(no_anonymous_path))
    no_anonymous_contents = get_contents(no_anonymous_path)
    if not no_anonymous_contents:
        print("\t\tCouldn't find file! Needs to contain 'yes'")
    elif "yes" in no_anonymous_contents:
        print("\t\tAnonymous logins are disabled! Yay!")
    else:
        print("\t\tAnonymous logins are allowed! Bad! NoAnonymous needs to be set to 'yes'")

    prohibit_dot_files_path = Path(config_path, "ProhibitDotFilesWrite")
    print("\t{}".format(prohibit_dot_files_path))
    prohibit_dot_files_contents = get_contents(prohibit_dot_files_path)
    if not prohibit_dot_files_contents:
        print("\t\tCouldn't find file! Needs to contain 'yes'")
    elif "yes" in prohibit_dot_files_contents:
        print("\t\tWriting to dot files is prohibited! Yay!")
    else:
        print("\t\tWriting to dot files is allowed! Bad! ProhibitDotFilesWrite needs to be set to 'yes'")

    daemonize_path = Path(config_path, "Daemonize")
    print("\t{}".format(daemonize_path))
    daemonize_contents = get_contents(daemonize_path)
    if not daemonize_contents:
        print("\t\tCouldn't find file! Needs to contain 'yes'")
    elif "yes" in daemonize_contents:
        print("\t\tRunning as a daemon! Yay!")
    else:
        print("\t\tNot running as a daemon! Bad! Daemonize needs to be set to 'yes'")

    no_chmod_path = Path(config_path, "NoChmod")
    print("\t{}".format(no_chmod_path))
    no_chmod_contents = get_contents(no_chmod_path)
    if not no_chmod_contents:
        print("\t\tCouldn't fine file! Needs to contain 'yes'")
    elif "yes" in no_chmod_contents:
        print("\t\tChmod is disabled! Yay!")
    else:
        print("\t\tChmod is enabled! Bad! Needs to be set to 'yes'")

    customer_proof_path = Path(config_path, "CustomerProof")
    print("\t{}".format(customer_proof_path))
    customer_proof_contents = get_contents(customer_proof_path)
    if not customer_proof_contents:
        print("\t\tCouldn't find file! Needs to contain 'yes'")
    elif "yes" in customer_proof_contents:
        print("\t\tCustomer Proof is enabled! Yay!")
    else:
        print("\t\tCustomer Proof is disabled! Bad! CustomerProof needs to be set to 'yes'")

    print()


def log_vsftpd():
    path = Path("/etc/vsftpd.conf")
    if not path.exists():
        print("vsftpd must not be installed because {} doesn't exist.".format(path))
        print()
        return
    print(path)
    print("NOTE: This does not check for many things and is a WIP")
    print("See also: {}".format("https://www.digitalocean.com/community/tutorials/how-to-set-up-vsftpd-for-a-user-s"
                                "-directory-on-ubuntu-16-04"))
    with path.open() as f:
        for line in f.readlines():
            if not line.startswith("#"):
                split = line.replace(" ", "").replace("\n", "").split("=")
                if len(split) == 2:
                    key = split[0]
                    value_string = split[1]
                    if key == "anonymous_enable":
                        if value_string == "YES":
                            print("Anonymous is enabled! Bad!")
                        elif value_string == "NO":
                            print("Anonymous is disabled! Yay!")
                        else:
                            print("Anonymous's value is: {}. (That's not a valid value)".format(value_string))
    print()


def log_samba():
    path = Path("/etc/samba/smb.conf")
    if not path.exists():
        print("samba must not be installed because {} doesn't exist".format(path))
        print()
        return

    print(path)
    print("\tIt looks like you have samba installed! Good luck on configuring it!")
    print("\tTry this link: https://www.dummies.com/programming/networking/network-administration-samba-smb-conf-file/")
    print("\tAlso make sure to back up the file before configuring it!")


def log_firewall(fix=False):
    """Logs if the firewall is on or not and turns it on if off and if fix is True.

    Works on windows and linux"""

    def turn_on_windows_firewall(shown_name, set_name):
        """Reference: https://helpdeskgeek.com/networking/windows-firewall-command-prompt-netsh/"""
        print("Trying to turn on {} firewall...".format(shown_name))
        firewall_process = subprocess.Popen("netsh advfirewall set {} state on".format(set_name),
                                            shell=True, stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE)
        firewall_process.wait()
        if firewall_process.returncode == 0:
            print("Success!")
        else:
            print("Fail!")

    if is_windows():
        process = subprocess.Popen("netsh advfirewall show allprofiles", shell=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.wait()
        if process.returncode == 0:
            profile = None  # 0:domain, 1:private, 2:public
            status = [None, None, None]
            for line in process.stdout.readlines():
                line = line.decode("utf-8").lower()
                if line.startswith("domain profile"):
                    profile = 0
                elif line.startswith("private profile"):
                    profile = 1
                elif line.startswith("public profile"):
                    profile = 2
                elif line.startswith("state"):
                    is_on = "off" not in line
                    on_off_string = "on" if is_on else "off"
                    if profile is None:
                        print("No profile. But the state of something is: {}".format(on_off_string))
                    else:
                        status[profile] = is_on
            if status[0] is None:
                print("Unable to tell if domain profile is on or off")
            if status[1] is None:
                print("Unable to tell if private profile is on or off")
            if status[2] is None:
                print("Unable to tell if public profile is on or off")

            if all(status):
                print("Each firewall profile is on! Yay!")
            else:
                print("Some firewall profile(s) are off! Is on: domain:{}, private:{}, public:{}"
                      .format(*status))
                if fix:
                    if not status[0]:
                        turn_on_windows_firewall("domain", "domainprofile")
                    if not status[1]:
                        turn_on_windows_firewall("private", "privateprofile")
                    if not status[2]:
                        turn_on_windows_firewall("public", "publicprofile")
                else:
                    print_run_with_fix()

        else:
            print("Couldn't view windows firewall status.")
    else:
        process = subprocess.Popen("ufw status", shell=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.wait()
        if process.returncode == 0:  # success
            output = str(process.stdout.read())
            if "inactive" not in output:
                print("Firewall is on! Yay!")
            else:
                print("Firewall is off!")
                if fix:
                    print("Turning on firewall...")
                    process = subprocess.Popen("ufw enable", shell=True,
                                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    process.wait()
                    if process.returncode == 0:
                        print("Turned on the firewall! Yay!")
                    else:
                        print("Couldn't turn on the firewall!")
                else:
                    print_run_with_fix()
        elif process.returncode == 1:
            print("You must be root to read the ufw status")
        elif process.returncode == 127:
            print("ufw not installed!")
        else:
            print("(from ufw) Unknown error code: {}".format(process.returncode))
    print()


def log_password_history_config(fix=False):
    path = Path("/etc/login.defs")
    if not path.exists():
        print_path_expected(path)
    else:
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
            print("NOTE: These PASS_MAX* settings only apply to new users")
            # print("Password history settings: max days: {}\tmin days:{}\twarn age:{}"
            #       .format(max_days, min_days, warn_age))
            if max_days is None:
                print("Password max days is not defined")
            if min_days is None:
                print("Password min days is not defined")
            if warn_age is None:
                print("Password warn age is not defined")

            if max_days != PASSWORD_MAX_DAYS:
                print("Password max days should be {}. It's {}".format(PASSWORD_MAX_DAYS, max_days))
            else:
                print("Max days is correct.")

            if min_days != 10:
                print("Password min days should be {}. It's {}".format(PASSWORD_MIN_DAYS, min_days))
            else:
                print("Min days is correct.")

            if warn_age != 7:
                print("Password warn age should be {}. It's {}"
                      .format(PASSWORD_WARN_DAYS, warn_age))
            else:
                print("Password warn age is correct.")
    print()


def log_password_history_users(fix=False):
    if is_windows():
        print("passwd command does't exist on windows: unable to check password history for users.")
    else:
        print("Checking users incorrect max/min/warn password ages (Not usually scored) (Not important)")
        fails = 0
        incorrect_count = 0
        for username in get_users_names():
            status = run_simple_command("passwd --status {}".format(username))
            if not status:
                fails += 1
            else:
                split = status.read().decode("utf-8").split(" ")
                if split[1] != "P":
                    print("User: {} has a password status of '{}'. This should be 'P' but isn't."
                          .format(username, split[1]))
                min_days = int(split[3])
                max_days = int(split[4])
                warn_days = int(split[5])
                if max_days != PASSWORD_MAX_DAYS:
                    print("{} has maximum password age of {}. Should be {}."
                          .format(username, max_days, PASSWORD_MAX_DAYS))
                    incorrect_count += 1
                    if fix:
                        print("\tTrying to fix...", end="")
                        if run_simple_command("passwd --maxdays {} {}".format(PASSWORD_MAX_DAYS,
                                                                              username)):
                            print("\tSuccess!")
                        else:
                            print("\tFail!")
                if min_days != PASSWORD_MIN_DAYS:
                    print("{} has minimum password age of {}. Should be {}."
                          .format(username, min_days, PASSWORD_MIN_DAYS))
                    incorrect_count += 1
                    if fix:
                        print("\tTrying to fix...", end="")
                        if run_simple_command("passwd --mindays {} {}".format(PASSWORD_MIN_DAYS,
                                                                              username)):
                            print("\tSuccess!")
                        else:
                            print("\tFail!")
                if warn_days != PASSWORD_WARN_DAYS:
                    print("{} has warn age of {}. Should be {}."
                          .format(username, warn_days, PASSWORD_WARN_DAYS))
                    incorrect_count += 1
                    if fix:
                        print("\tTrying to fix...", end="")
                        if run_simple_command("passwd --warndays {} {}".format(PASSWORD_WARN_DAYS, username)):
                            print("\tSuccess!")
                        else:
                            print("\tFail!")
        if fails != 0:
            print("Failed to view status for {} user(s).".format(fails))
        if not fix and incorrect_count > 0:
            print_run_with_fix()

    print()


def log_lockout_policy(fix=False):
    path = Path("/etc/pam.d/common-auth")
    if not path.exists():
        print_path_expected(path)
    else:
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
                if fix:
                    print("Trying to add line...")
                    try:
                        with path.open("a") as append:  # append
                            append.write("\n")
                            append.write(ACCOUNT_POLICY_LINE)
                            append.write("\n")
                            print("Success!")
                    except PermissionError:
                        print("Failed!")
                else:
                    print_run_with_fix()
    print()


def log_password_policy():
    path = Path("/etc/pam.d/common-password")
    if not path.exists():
        print_path_expected(path)
    else:
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
                    print("\tYou need to enforce uppercase with ucredit=-1")
                if "lcredit" in cracklib_line:
                    print("\tYay! You're enforcing lowercase!")
                else:
                    print("\tYou need to enforce lowercase with lcredit=-1")
                if "dcredit" in cracklib_line:
                    print("\tYay! You're enforcing a number!")
                else:
                    print("\tYou need to enforce a number with dcredit=-1")
                if "ocredit" in cracklib_line:
                    print("\tYay! You're enforcing a symbol!")
                else:
                    print("\tYou need to enforce a symbol with ocredit=-1")
            else:
                print("Line with pam_cracklib.so not found! Remember (sudo apt install libpam-cracklib) "
                      "Also, say yes if it asks to override a file in /etc/pam.d")
    print()


def log_home_directory_permissions(fix=False):
    if not pwd or not grp:
        print("pwd or grp modules not found. Cannot test home directory permissions")
    else:
        correct = 0
        incorrect = 0
        for user in get_users_unix():
            home = Path(user.pw_dir)
            permission = home.stat().st_mode
            if permission & 0o750 != 0o750:
                incorrect += 1
                print("{}'s home directory has incorrect permission level.".format(user.pw_name))
                if fix:
                    print("Trying to fix...")
                    new_permission = permission | 0o750
                    try:
                        home.chmod(new_permission)
                        print("Fixed the permission level!")
                    except PermissionError:
                        print("Unable to fix. Run with sudo.")
                else:
                    print_run_with_fix()
            else:
                correct += 1

        if incorrect == 0 and correct > 0:
            print("All users have the correct home directory permission. (from chmod 0750 <dir>)")
        else:
            print("{} have the correct home directory permission and "
                  "{} have an incorrect permission. (Use chmod 0750 <dir>)"
                  .format(correct, incorrect))
    print()


def log_installed_packages():
    if apt is None:
        print("Unable to report package status (sudo apt install python-apt)")
    else:
        cache = apt.Cache()
        for package in cache:
            package_name = package.name
            if (package_name in ALWAYS_REPORT_PACKAGES_SET
                    or (package.is_installed and (package_name in REPORT_INSTALLED_PACKAGES_SET
                                                  or any(part in package_name for part in
                                                         REPORT_INSTALLED_PACKAGES_CONTAINS)))):
                print("{}Package {} {}installed"
                      .format("+  " if package.is_installed else " - ",
                              package_name,
                              "IS " if package.is_installed else "NOT "))

    print()


def log_media_files(directory, max_depth=None, ignore_hidden=True, find_pngs=False):
    if isinstance(directory, str):
        directory = Path(directory)
    directory = directory.resolve()  # get rid of any ".."s (simplify the path)
    if ignore_hidden and directory.name.startswith("."):
        return
    if max_depth is not None:
        if max_depth <= 0:
            return
        max_depth -= 1

    number_found = 0
    try:
        for file in directory.iterdir():
            if file.is_dir():
                log_media_files(file, max_depth=max_depth, ignore_hidden=ignore_hidden, find_pngs=find_pngs)
            else:
                extension = file.name.split(".")[-1].lower()
                if extension in REPORT_FILE_EXTENSIONS_SET and (extension != "png" or find_pngs):
                    number_found += 1
    except (PermissionError, FileNotFoundError, OSError):
        pass
    if number_found != 0:
        print("Found {} file(s) in {}"
              .format((" " * (4 - len(str(number_found)))) + str(number_found), directory))


def main():
    parser = ArgumentParser()
    parser.add_argument("--fix", action="store_true",
                        help="Try to fix as many things that are wrong with the system.")
    parser.add_argument("--pngs", action="store_true",
                        help="Should we scan for pngs as well? Used with --only scan")

    parser.add_argument("--only", type=str,
                        help="Only do one thing [scan|user|firewall|home|ssh|pass]")
    parser.add_argument("--path", type=str,
                        help="The path to scan media files. Use with --only scan")

    args = parser.parse_args()

    if args.only:
        if args.only == "scan":
            directory = args.path or "/home"
            print("Starting scan for media files")
            log_media_files(directory, max_depth=15, find_pngs=args.pngs)
            print("Scan finished")
        elif args.only == "user":
            user_test()
        elif args.only == "firewall":
            log_firewall(fix=args.fix)
        elif args.only == "home":
            log_home_directory_permissions(fix=args.fix)
        elif args.only == "ssh":
            if is_windows():
                print("Cannot detect ssh on windows")
                sys.exit(1)
            log_ssh()
        elif args.only == "pass":
            log_no_password_required()
            if not is_windows():
                log_password_history_config(fix=args.fix)
                log_password_history_users(fix=args.fix)
                log_lockout_policy(fix=args.fix)
                log_password_policy()
        else:
            print("Unknown --only option: {}".format(args.only))
            sys.exit(1)
    else:
        log_guest_account(fix=args.fix)
        log_admin_account_enabled(fix=args.fix)
        log_no_password_required()
        log_firewall(fix=args.fix)
        if not is_windows():  # for linux only
            log_ssh()
            log_pure_ftp()
            log_vsftpd()
            log_samba()
            log_password_history_config(fix=args.fix)
            log_password_history_users(fix=args.fix)
            log_lockout_policy(fix=args.fix)
            log_password_policy()
            log_home_directory_permissions(fix=args.fix)
            log_ubuntu_repos()
            log_installed_packages()
        print()
        user_test()


def try_main():
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == '__main__':
    try_main()
