# OpenPhish
Open URLs and files in a separate analysis machine

OpenPhish assists URL and file analysis by relaying content to an untrusted analysis machine. 
It has two components:

 1. **FileMonitor:** Auto-open files dropped in a shared directory within the analysis machine.
 2. **URLMonitor:** Auto-open web URLs within the analysis machine, when URLs are placed in a file residing in a shared folder.

The companion `openlinks` script (and compiled py2exe executable for windows) can be used to replace the default browser, so that all links opened by the current default browser are relayed to the untrusted machine. 

Trusted directories can be a Guest-to-Host shared folders, or they could be remote network file systems such as SMB or NFS. 

This process will expedite analysis of suspicious content and when `openlinks.exe` is set to replace the default browser, it prevents accidental visitation of untrusted URls from the analyst's computer. 

### Example configuration files:

**openphish_config.example_linux.json:**

```
{
    "attachments_path": "/home/analyst/malware/",
    "linux_cmd": [
        "xdg-open"
    ],
    "sharedurls": "/home/analyst/malware/.sharedurls",
    "url_cmd": [
        "firefox-esr",
        "--new-tab"
    ],
    "windows_cmd": [
        "C:\\windows\\system32\\cmd.exe",
        "/c",
        "start"
    ]
}
```

**openphish_config.example_windows.json:**

```
{
    "attachments_path": "E:\\malware\\",
    "linux_cmd": [
        "xdg-open"
    ],
    "sharedurls": "E:\\.sharedurls",
    "url_cmd": [
        "C:\\Program Files\\internet explorer\\iexplore.exe"
    ],
    "windows_cmd": [
        "explorer.exe"
    ]
}
```

### Usage

On the untrusted machine:
	Run `python3 openphish.py` it will always use the `openphish_config.json` file as it's configuration, if it does not exist, it will create a default configuration. It needs write access to the current directory in order to keep track of files that have already been opened in the past. 

Configuration items:
	attachments_path: This is the shared folder where untrusted files will be placed. all files placed in this directory will be auto-opened.
	sharedurls: This is the file that is monitored for new URLs that will be auto-opened in the untrusted machine. 
	linux_cmd,windows_cmd: These are the commands used to auto-open arbitrary files within the untrusted machine
	url_cmd: This is the command that will be used to open URls, it should point to a desired browser's file path. 

On the trusted machine, install a browser you will never use and set it as your default browser (this is largely because I haven't found a way to consistently set the default browser value on windows yet). Next, replace the executable of you default browser with `openlinks/openlinks.exe` (e.g.: replace `chrome.exe`). 

Use the virtual machine hypervisor or a remote file system to establish a shared directory between the analyst(tursted) machine and the untrusted analysis/detonation machine. 



