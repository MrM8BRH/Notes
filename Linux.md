#### Power
```
# View the available CPU speed governors for the first CPU core
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors 
# Output example: performance powersave

# Check the current CPU governor in use for the first CPU core
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
# Output example: powersave

# Change the CPU governor to 'performance' mode for all CPU cores
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
# This command sets the scaling governor to 'performance' for all CPU cores
```
#### BIOS & Firmware Version
```
# Display BIOS information from the system's DMI (Desktop Management Interface) data
sudo dmidecode -t bios
```
#### Cgroup Version
```
# Checking cgroup Version via `/proc/filesystems`
grep cgroup /proc/filesystems

# Output Interpretation
# Systems Supporting cgroupv2
nodev   cgroup
nodev   cgroup2

# Systems with cgroupv1 Only
nodev   cgroup
```
#### Linux File Permissions
```bash
-rw-r--r-- 12 linuxize users 12.0K Apr  28 10:10 file_name
|[-][-][-]-   [------] [---]
| |  |  | |      |       |
| |  |  | |      |       +-----------> 7. Group
| |  |  | |      +-------------------> 6. Owner
| |  |  | +--------------------------> 5. Alternate Access Method
| |  |  +----------------------------> 4. Others Permissions
| |  +-------------------------------> 3. Group Permissions
| +----------------------------------> 2. Owner Permissions
+------------------------------------> 1. File Type
```

| Number | Permission Type        | Symbol |
| ------ | ---------------------- | ------ |
| 0      | No Permission          | `---`  |
| 1      | Execute                | `--x`  |
| 2      | Write                  | `-w-`  |
| 3      | Write + Execute        | `-wx`  |
| 4      | Read                   | `r--`  |
| 5      | Read + Execute         | `r-x`  |
| 6      | Read + Write           | `rw-`  |
| 7      | Read + Write + Execute | `rwx`  |
#### Passwd File Format
```bash
mark:x:1001:1001:mark,,,:/home/mark:/bin/bash
[--] - [--] [--] [-----] [--------] [--------]
|    |   |    |     |         |        |
|    |   |    |     |         |        +-> 7. Login shell
|    |   |    |     |         +----------> 6. Home directory
|    |   |    |     +--------------------> 5. GECOS
|    |   |    +--------------------------> 4. GID
|    |   +-------------------------------> 3. UID
|    +-----------------------------------> 2. Password
+----------------------------------------> 1. Username
```
#### Shadow File Format
```bash
mark:$6$.n.:17736:0:99999:7:::
[--] [----] [---] - [---] ----
|      |      |   |   |   |||+-----------> 9. Unused
|      |      |   |   |   ||+------------> 8. Expiration date
|      |      |   |   |   |+-------------> 7. Inactivity period
|      |      |   |   |   +--------------> 6. Warning period
|      |      |   |   +------------------> 5. Maximum password age
|      |      |   +----------------------> 4. Minimum password age
|      |      +--------------------------> 3. Last password change
|      +---------------------------------> 2. Encrypted Password
+----------------------------------------> 1. Username
```
#### Rsync & SCP
```bash
# Rsync - Copy a local file to another directory
rsync -azv --numeric-ids /opt/filename.zip /tmp/
# Rsync - Sync a local directory to a remote machine
rsync -azv --numeric-ids /opt/media/ remote_user@remote_host_or_ip:/opt/media/

# SCP - Copy a local file to a remote system
scp file.txt remote_username@remote_host_or_ip:/remote/directory
# SCP - Copy a local directory recursively to a remote system
scp -r /local/directory remote_username@remote_host_or_ip:/remote/directory
```
#### Firewalld
```bash
firewall-cmd --permanent --add-port=8000/tcp
firewall-cmd --permanent --add-port=9997/tcp
firewall-cmd --permanent --add-port=8089/tcp
firewall-cmd --permanent --add-port=8080/tcp
firewall-cmd --permanent --add-port=22/tcp
firewall-cmd --permanent --add-port=53/udp
firewall-cmd --permanent --add-port=514/tcp
firewall-cmd --permanent --remove-port=8000/tcp
firewall-cmd --reload
systemctl stop firewalld
systemctl disable firewalld
```
#### SSH logging
```bash
nano /etc/ssh/sshd_config

# Logging
SyslogFacility AUTH
LogLevel INFO

##################
# SysLogFacility #
#- DAEMON        #
#- USER          #
#- AUTH          #
#- LOCAL0        #
#- LOCAL1        #
#- LOCAL2        #
#- LOCAL3        #
#- LOCAL4        #
#- LOCAL5        #
#- LOCAL6        #
#- LOCAL7        #
##################
```
#### Syslog
```bash
nano /etc/syslog.conf
auth.info /var/log/sshd.log
```

| Filename | Purpose                                                          |
| -------- | ---------------------------------------------------------------- |
| auth.log | System authentication and security events                        |
| boot.log | A record of boot-related events                                  |
| dmesg    | Kernel-ring buffer events related to device drivers              |
| dpkg.log | Software package-management events                               |
| kern.log | Linux kernel events                                              |
| syslog   | A collection of all logs                                         |
| wtmp     | Tracks user sessions (accessed through the who and last commands |

| 0   | Emergency     | System is unusable                |
| --- | ------------- | --------------------------------- |
| 1   | Alert         | Action must be taken immediately  |
| 2   | Critical      | Critical conditions               |
| 3   | Error         | Error conditions                  |
| 4   | Warning       | Warning conditions                |
| 5   | Notice        | Normal but significant conditions |
| 6   | Informational | Informational messages            |
| 7   | Debug         | Debug-level messages              |
#### MISC
```bash
# Display the contents of the /etc/os-release file to show OS information
cat /etc/os-release

# Display system information including the kernel version and architecture
uname -a

# Set the system's hostname to 'host.domain.com'
hostnamectl set-hostname host.domain.com

# Show the current status of the hostname and related settings
hostnamectl status

# Display the DNS domain name of the system
dnsdomainname

# Set the system's timezone to Asia/Jerusalem
timedatectl set-timezone Asia/Jerusalem
```
#### Memory Commands
```bash
# Display memory usage in megabytes
free -m

# Display memory usage in a human-readable format (e.g., KB, MB, GB)
free -h

# Display detailed information about the system's memory (RAM) using DMI data
dmidecode --type memory
```
#### CPU & Processes Commands
```bash
# Display a dynamic real-time view of system processes and resource usage
top

# Display an enhanced version of top with a more user-friendly interface
htop

# Display system and process information, including resource usage over time
atop

# Search for processes by name and return their process IDs
pgrep

# Kill processes by name using their process IDs
pkill

# Display detailed information about all running processes
ps -elf

# Identify processes that are accessing a specific file (e.g., ~/testfile.txt)
fuser ~/testfile.txt

# Display the number of processing units available to the current process
nproc

# Display the total number of processing units available, including all cores and threads
nproc --all

# Calculate the number of virtual CPUs (vCPUs) based on the formula provided
# (Threads x Cores) x Physical CPU Number = Number of vCPUs

# Display detailed information about the CPU architecture and configuration
lscpu 
# Look for the following fields:
#     - CPU(s): Total number of logical CPUs (vCPUs).
#     - Core(s) per socket: Number of physical cores per CPU socket.
#     - Socket(s): Number of physical CPU sockets.
#     - Model name: CPU model and speed (e.g., `2.20 GHz`).

# Count the number of logical processors (vCPUs) available on the system
cat /proc/cpuinfo | grep processor | wc -l

# Display detailed information about the system's processors using DMI data
dmidecode --type processor
```
#### Storage Commands
```bash
# Display the total disk usage of the current directory and its subdirectories in a human-readable format
du -csh

# List all block devices, including partitions and their mount points
lsblk

# Display disk space usage for the specified directories (/opt/splunk and /) in a human-readable format
df -h /opt/splunk /

# List all disk partitions and their details
fdisk -l

# Open the fdisk utility to manage partitions on the specified disk (/dev/sda)
fdisk /dev/sda

# Display information about volume groups in the Logical Volume Manager (LVM)
vgdisplay

# Display real-time I/O usage by processes
iotop #

# Check the type of disk (rotational or non-rotational) and its performance
lsblk -d -o name,rota
### - rota=1: Rotational disk (HDD).
### - rota=0: Non-rotational disk (SSD).
```
#### Network Commands
```bash
# Open the network interface configuration file for the specified interface in the vi editor
vi /etc/sysconfig/network-scripts/ifcfg-<int>

# Display the kernel routing table in a numeric format
route -n

# Display the IP addresses assigned to the host
hostname -I #

# Capture and display TCP packets on interface eth3 for the specified host and ports (80 and 443)
tcpdump -i eth3 -n tcp and host 192.168.1.50 and (port 80 or port 443)

# Check if a specific port is open on a given IP address using netcat
nc -zv <IP Address> <Port>

# Connect to a specific IP address and port using telnet
telnet <IP Address> <Port>

# Open the NetworkManager TUI (Text User Interface) for managing network connections
nmtui

# Check the speed of the network interface card (NIC) for the specified interface
sudo ethtool enp2s0 | grep Speed:

# `ip addr`: Manage IP Addresses
- `ip addr show`  
  # Display all IP addresses.
- `ip addr show dev eth0`  
  # Show IP addresses on interface `eth0`.
- `ip addr add 1.1.1.1/24 dev eth0`  
  # Add IP address `1.1.1.1/24` to `eth0`.
- `ip addr del 1.1.1.1/24 dev eth0`  
  # Remove IP address `1.1.1.1/24` from `eth0`.
- `ip addr flush dev eth0`  
  # Remove all IP addresses from `eth0`.

# `ip route`: Manage Network Routes
- `ip route`  
  # Display all routing table entries.
- `ip route show default`  
  # Show the default gateway route.
- `ip route flush dev eth0`  
  # Remove all routes associated with `eth0`.
- `ip route get 1.1.1.1`  
  # Show the route taken for `1.1.1.1`.
- `ip route show 1.1.1.0/24`  
  # Display routes for the `1.1.1.0/24` subnet.
- `ip route add 1.1.1.0/24 dev eth0`  
  # Add a route for `1.1.1.0/24` via `eth0`.
- `ip route add default via 192.168.0.1 dev eth0`  
  # Set default gateway to `192.168.0.1` via `eth0`.
- `ip route add/del 1.1.1.0/24 via 192.168.0.1`  
  # Add/remove a route via a next-hop IP.
- `ip route replace 1.1.1.0/24 via 192.168.1.1 dev eth0`  
  # Replace an existing route entry.
- `ip route add 1.1.1.0/24 via 192.168.1.1 dev eth0 metric 100`  
  # Specify a metric for the route.

# `ip link`: Manage Network Interfaces
- `ip link show`  
  # List all network interfaces.
- `ip link show eth0`  
  # Show details for interface `eth0`.
- `ip link set eth0 up/down`  
  # Activate/deactivate `eth0`.
- `ip link set eth0 mtu 9000`  
  # Set MTU to `9000` for `eth0`.
- `ip link set eth0 promisc on`  
  # Enable promiscuous mode for `eth0`.
- `ip -s link show eth0`  
  # Show traffic statistics for `eth0`.
- `ip link set eth0 addr 11:22:33:44:55:66`  
  # Change MAC address of `eth0`.

# `ip neigh`: Manage ARP Neighbors
- `ip neigh show`  
  # Display all ARP table entries.
- `ip neigh show dev eth0`  
  # Show ARP entries for `eth0` only.
- `ip neigh del 192.168.0.2 dev eth0`  
  # Remove ARP entry for `192.168.0.2`.
- `ip neigh add 192.168.0.2 lladdr <mac-addr> dev eth0 nud permanent`  
  # Add a static ARP entry.
- `ip neigh change 192.168.0.2 lladdr <mac-addr> dev eth0`  
  # Update an existing ARP entry.
- `ip neigh flush 192.168.0.0/24`  
  # Clear ARP entries for the `192.168.0.0/24` subnet.

## IPv6 Support
- Use the `-6` option to apply commands to IPv6 addresses (e.g., `ip -6 addr show`).

## `ip tunnel`: Manage Tunnels
- `ip tunnel show`  
  List all configured tunnel interfaces.
- `ip tunnel add gre1 mode gre remote 10.0.0.2 local 10.0.0.1 ttl 255`  
  Create a GRE tunnel named `gre1`.
```

#### Disable SELinux
```bash
sestatus
nano /etc/selinux/config
SELINUX=disabled
```
#### Disable Transparent Huge Pages (THP)
```bash
nano /etc/systemd/system/disable-thp.service
[Unit]
Description=Disable Transparent Huge Pages (THP)

[Service]
Type=simple
ExecStart=/bin/sh -c "echo 'never' > /sys/kernel/mm/transparent_hugepage/enabled && echo 'never' > /sys/kernel/mm/transparent_hugepage/defrag"

[Install]
WantedBy=multi-user.target
```

```
systemctl daemon-reload
systemctl start disable-thp
systemctl enable disable-thp
```
#### NTP Commands
```bash
# Display the current system time, timezone, and NTP synchronization status
timedatectl

# Display the sources that chrony is using for time synchronization
chronyc sources

# Open the chrony configuration file in the nano text editor for editing
nano /etc/chrony.conf

# Open the NTP configuration file in the nano text editor for editing
nano /etc/ntp.conf
```
#### Permission Commands
```bash
# Open the sudoers file for editing with the visudo command
visudo

# Change the permissions of a file or directory (usage example: chmod 755 filename)
chmod

# Change the ownership of a file or directory (usage example: chown user:group filename)
chown

# Modify the Access Control List (ACL) to give a specific user read permission on a folder or file
setfacl -m u:<User>:r /path/to/folder/or/files

# Modify the Access Control List (ACL) to give a specific group read permission on a folder or file
setfacl -m g:<Group>:r /path/to/folder/or/files
```
#### Storage Options
Option 1: Resize Without Adding a New Disk
This method assumes you have increased the virtual disk size at the hypervisor/cloud level and need the OS to recognize it.

**Method A: Using `growpart` (Recommended for LVM)**
```bash
# 1. Update the partition table to expand partition 3
growpart /dev/sda 3

# 2. Resize the Physical Volume (PV) so LVM sees the new space
pvresize /dev/sda3

# 3. Extend the LV and the filesystem simultaneously
lvextend -r -l +100%FREE /dev/mapper/centos-opt

# Inform the operating system of partition table changes (useful after modifying partitions)
partprobe
```
**Method B: The Manual `fdisk` Way (High Risk)**

**Note:** Deleting a partition is risky. Always ensure you start the new partition at the **exact same sector** as the old one.
```bash
# 1. Expand the partition
fdisk /dev/sda
# d -> 1 (Delete partition 1)
# n -> p -> 1 (Create new primary partition 1)
# Accept defaults (ensure Start Sector matches the old one!)
# N (Do NOT signature/wipe existing filesystem)
# w (Write changes)

# 2. Force the kernel to reload the partition table
partprobe

# 3. Resize the filesystem (Assuming XFS)
# Note: Use the mount point or the device path
xfs_growfs /dev/sda1
```
Option 2: Resize by Adding a New Disk
Use this when you have attached a **completely new** disk (e.g., `/dev/sdb`) rather than expanding the existing `/dev/sda`.
```bash
# 1. Initialize the NEW disk (Ensure you aren't overwriting sda!)
pvcreate /dev/sdb

# 2. Find your Volume Group name
vgdisplay -c | cut -d: -f1

# 3. Add the new PV to your existing Volume Group
vgextend <VG_Name> /dev/sdb

# 4. Expand the Logical Volume and resize the filesystem
lvextend -r -l +100%FREE /dev/mapper/<VG_Name>-opt

# 5. Inform the operating system of partition table changes
partprobe
```
#### Crontab
**Overview:** Crontab is a time-based job scheduling program in Unix-like operating systems, allowing users to automate recurring tasks. The term "crontab" combines "cron" (the daemon that executes scheduled tasks) and "tab" (short for table, as the scheduling information is organized in a tabular format).

**Usage:** Crontab is ideal for scheduling scripts, commands, or programs to run at specified intervals (e.g., daily, weekly, monthly, or specific minutes within an hour). It is particularly useful for automating repetitive tasks and maintenance activities.

**Crontab File Format:** The crontab file follows this structure:
```bash
# <Minute> <Hour> <Day of Month> <Month> <Day of Week> Command
```

**Field Breakdown:**
- **Minute:** 0-59 (when the task runs)
- **Hour:** 0-23 (when the task runs)
- **Day of Month:** 1-31 (when the task runs)
- **Month:** 1-12 or names (e.g., Jan, Feb)
- **Day of Week:** 0-7 or names (0/7 = Sunday)
- **Command:** The command or script to execute
Use `*` to mean "every possible value."

**Special Time Strings**

| String      | Meaning                          |
| ----------- | -------------------------------- |
| `@reboot`   | Once at system startup           |
| `@hourly`   | Once every hour                  |
| `@daily`    | At midnight each day             |
| `@midnight` | At midnight each day             |
| `@weekly`   | At midnight every Sunday         |
| `@monthly`  | At midnight on 1st of each month |
| `@yearly`   | At midnight on Jan 1st each year |

**Examples**

| Cron Expression | Description                      |
| --------------- | -------------------------------- |
| `0 * * * *`     | Every hour                       |
| `*/5 * * * *`   | Every 5 minutes                  |
| `0 */6 * * *`   | Every 6 hours (fixed formatting) |
| `0 9-17 * * *`  | Every hour from 9 AM to 5 PM     |
| `0 8,18 * * *`  | 8 AM and 6 PM daily              |
| `30 0 * * 3`    | 00:30 AM every Wednesday         |

**Scheduling a Task:** To schedule a task, add a line to your crontab file using the specified format. Fields are separated by spaces or tabs, and asterisks (*) can be used to represent any value.

**Editing Crontab:** Use the command `crontab -e` to edit the crontab file for the current user.

#### Special File Permissions in Linux: SUID, GUID, and Sticky Bit  
Linux supports three special file permissions that provide additional functionality beyond standard read/write/execute permissions:    
##### 1. **SUID (Set User ID)**    
- **Purpose**: Allows a file to be executed with the **owner's privileges**, regardless of who runs it.    
- **Symbol**: `s` in the **owner's execute position**.    
- **Octal Value**: `4` (e.g., `4755`).    
- **Example**:    
```bash  
-rwsr-xr-x 1 root root /usr/bin/passwd  
# ^--- SUID bit set (owner's execute = 's')  
```  
  - **Set SUID**:    
```bash  
chmod u+s file    # Symbolic  
chmod 4755 file   # Octal  
```  
##### 2. **GUID (Set Group ID)**    
- **Purpose**:    
  - For **files**: Run with the **group's privileges**.    
  - For **directories**: New files inherit the directory's **group ownership**.    
- **Symbol**: `s` in the **group's execute position**.    
- **Octal Value**: `2` (e.g., `2775`).    
- **Example**:    
```bash  
drwxrwsr-x 2 root developers /shared  
#       ^--- GUID bit set (group's execute = 's')  
```  
  - **Set GUID**:    
```bash  
chmod g+s file    # Symbolic  
chmod 2775 file   # Octal  
```  
##### 3. **Sticky Bit**    
- **Purpose**: Restricts file deletion in directories. Only the **file owner**, **directory owner**, or **root** can delete files.    
- **Symbol**: `t` in the **others' execute position**.    
- **Octal Value**: `1` (e.g., `1777`).    
- **Example**:    
```bash  
drwxrwxrwt 2 root root /tmp  
#          ^--- Sticky bit set (others' execute = 't')  
```  
  - **Set Sticky Bit**:    
```bash  
chmod +t dir     # Symbolic  
chmod 1777 dir   # Octal  
```  
##### Key Notes:  
- **Uppercase `S`/`T`**: Indicates the special bit is set, but the underlying **execute permission** is missing.    
  Example: `-rwSr--r--` (SUID set, no owner execute).    
- **Security**: Use SUID/GUID sparingly; improper use can create security risks.    
- **View Permissions**: Use `ls -l` to check for `s`/`t` in the permission string.  

### Linux Command Chaining
#### Types of Command Chaining
##### 1. Sequential Chaining (`;`)
- **Description**: Run commands sequentially, regardless of success/failure of the previous command.  
- **Example**:  
```bash
mkdir testdir; cd testdir; touch file.txt
```
##### 2. Conditional Execution - Success (`&&`)
- **Description**: Run the next command **only if** the previous command succeeds.
- **Example**:
```bash
gcc app.c && echo "Build success"
```
##### 3. Conditional Execution - Failure (`||`)
- **Description**: Run the next command **only if** the previous command fails.
- **Example**:
```bash
invalid_command || echo "Command failed"
```
##### 4. Combined Success/Failure Handling (`&&` + `||`)
- **Description**: Run one command on success **or** another on failure.
- **Example**:
```bash
gcc app.c && echo "Build success" || echo "Build failed"
```
##### 5. Pipeline (`|`)
- **Description**: Pass the output of one command as input to the next. 
- **Example**:
```bash
ps aux | grep nginx | awk '{print $2}'
```
##### 6. Redirection (`>` and `>>`)
- **Description**:
    - `>`: Overwrite a file with command output.
    - `>>`: Append command output to a file.
- **Examples**:
```bash
dmesg | grep error > system_errors.log    # Overwrite
dmesg | grep error >> system_errors.log   # Append
```

### Linux Device Driver Commands
#### Module Inspection & Information
- **`lsmod`**  
  List all loaded kernel modules and drivers.
- **`modinfo <module>`**  
  Display information about a kernel module (located in `/lib/modules` or custom-built).
#### Hardware Device Drivers
- **`lspci -k`**  
  Show the kernel driver in use for each connected PCI device (e.g., NIC, GPU).
- **`lsusb -t`**  
  Display the driver used for each USB device (e.g., USB stick, dongle).
#### Network Interface Drivers
- **`ethtool -i eth0`**  
  Show the driver name for a specific network interface (replace `eth0` with the interface name).
#### Module Management
- **`modprobe <module>`**  
  Load a kernel module (from `/lib/modules`) and its dependencies. Use `-r` to remove a module.  
  Example: `modprobe -r <module>`.
- **`insmod /path/to/module.ko`**  
  Load a custom-built kernel module. Does **not** automatically load dependencies.
- **`rmmod <module>`**  
  Unload a kernel module. Does **not** automatically remove dependencies.
#### Kernel Module Parameters & Debugging
- **`sysctl -a | grep <module>`**  
  View kernel module parameter values exported via `sysctl`.
- **`dmesg | grep <module>`**  
  Display kernel ring buffer messages related to a specific module/driver.
#### Dynamic Kernel Module Support (DKMS)
- **`dkms status`**  
  Show the status of dynamically built out-of-tree kernel modules.
