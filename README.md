# Linux_privilege_escalation_labs
This repository contains a technical breakdown and analysis of key privilege escalation vectors in Linux environments. These labs were conducted on the TryHackMe Linux PrivEsc room, focusing on identifying misconfigurations and exploiting them to gain administrative (root) access.

# About Me
Information Systems graduate, currently transitioning to Cyber Security. Previously served as a Technician at Oil and Gas Industry (Pertamina Patra Niaga vendor), where I developed a highly disciplined approach to managing critical infrastructure compliance and 24/7 reliability. Currently formalizing expertise through an intensive cybersecurity bootcamp at Dibimbing, I am eager to apply this technical foundation and structured approach to a security operations role.

# Tools

- Kali Linux
- Virtual Machine
- TryHackMe 

# Task 1 - Deploy the Vulnerable Debian VM
<p align="center">
  <img width="500" height="455" alt="image" src="https://github.com/user-attachments/assets/1fbd8964-3dc5-4e26-8b1b-740111ecee3f" />
  <br>
</p>
To interact with the vulnerable Debian VM, I utilized OpenVPN to route my traffic through a secure gateway. This ensures that the laboratory environment is isolated and accessible only to authorized users.
<br>
<br>

```bash
#Executed the OpenVPN client
openvpn --config youraccname.ovpn
```
<p align="center">
  <img width="500" height="112" alt="image" src="https://github.com/user-attachments/assets/057a30d6-82c0-4c07-9f84-27ae723081fc" />
  <br>
</p>
Once the configuration file (youraccname.ovpn) was acquired, I initialized the connection using the Linux terminal. This process involves elevating privileges to manage network interfaces and routing tables. Upon execution, OpenVPN establishes a virtual tunnel. Once the message "Initialization Sequence Completed" appears, the system's external IP is masked, and a new internal IP (usually in the 10.x.x.x range) is assigned to the tun0 interface, allowing direct communication with the vulnerable Debian VM.

```bash
#version detection scan
nmap -sV 10.201.78.111
```
<p align="center">
  <img width="500" height="263" alt="image" src="https://github.com/user-attachments/assets/6a4328ae-99a9-4f68-9ad5-655114f1fbba" />
  <br>
</p>
I utilized the Nmap (Network Mapper) tool to perform a version detection scan. This was done to verify if the SSH service was indeed active and listening on the expected port. The scan successfully confirmed that Port 22/TCP is Open, running the OpenSSH service. This validation aligns with the lab requirements, confirming that the initial access vector (SSH) is available for the next phase of the penetration test.
<br>
<br>

```bash
#start the ssh
ssh user@10.201.78.111 -oHostKeyAlgorithms=+ssh-rsa
```
<p align="center">
  <img width="500" height="247" alt="image" src="https://github.com/user-attachments/assets/4fce7fbe-fdd6-4bce-ba37-66f3967fd0f8" />
  <br>
</p>
During the connection attempt, a common compatibility issue was encountered regarding the SSH key exchange algorithm. The modern OpenSSH client on Kali Linux may refuse to negotiate with older servers that still utilize the ssh-rsa or ssh-dss algorithms. To bypass this security restriction for the purpose of the lab, I utilized the -oHostKeyAlgorithms option to explicitly allow the use of the legacy ssh-rsa algorithm.

```bash
#executed id
id
```
<p align="center">
  <img width="500" height="81" alt="image" src="https://github.com/user-attachments/assets/45d1b28d-3043-4c10-8baf-90eb421f3f2a" />
  <br>
</p>
I executed the id command to retrieve the User ID (UID), Group ID (GID), and the Groups associated with the current session. The output was as follows: uid=1000(user) gid=1000(user)groups=1000(user),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev).

# Task 3 - Weak File Permissions (Readable /etc/shadow)
```bash
#look the directory
ls -lh /etc/shadow
```
<p align="center">
  <img width="500" height="40" alt="image" src="https://github.com/user-attachments/assets/9384439c-3c4d-45da-8d49-5ad1605a9652" />
  <br>
</p>
The output revealed a severe security flaw: -rw-r--rw- 1 root shadow 837 Aug 25 2019 /etc/shadow. The permission string -rw-r--rw- indicates that any user on the system can read from and write to this file. Since the file is readable, an attacker can extract the root password hash and attempt to crack it offline using tools like John the Ripper or Hashcat. Since the file is writable, an attacker can directly replace the root user password hash with a known hash, effectively changing the root password without knowing the original one.

```bash
#look the directory /etc/shadow
cat /etc/shadow
```
<p align="center">
  <img width="500" height="273" alt="image" src="https://github.com/user-attachments/assets/86881932-292e-4f28-9922-bee13bb8d28f" />
  <br>
</p>
I utilized the cat command to display the entire contents of the /etc/shadow file. The command successfully outputted the system's password file. Each line represents a user, with fields separated by colons ":". While the passwords are not stored in plaintext, the ability to read these hashes allows an attacker to perform an Offline Brute Force or Dictionary Attack. By copying these hashes to a local machine, an attacker can use high-performance hardware to crack the passwords without triggering any system alerts or account lockouts.
<br>
<br>
<p align="center">
  <img width="500" height="217" alt="image" src="https://github.com/user-attachments/assets/9aa42519-7a59-40e4-92ec-67ffa1f4d77b" />
  <br>
</p>
I copied the extracted root and user password hashes from the target and saved them into a local file named password.txt on my Kali Linux machine for offline analysis. I opened a new terminal session and initiated the hash-identifier tool. The tool successfully analyzed the hash structure and identified it as SHA-256. 

```bash
#run the haschcat
hashcat -m 1800 password.txt /usr/share/wordlists/rockyou.txt
```
<p align="center">
  <img width="500" height="75" alt="image" src="https://github.com/user-attachments/assets/b9ddaa44-4063-425b-b083-d46c53542e27" />
  <br>
</p>
The attack was successful. Hashcat matched the captured hash with a string in the wordlist, revealing the plaintext password (password321). he successful cracking of the root password grants the attacker full administrative control over the system. This demonstrates that even hashed passwords are not secure if they are "weak" (present in common wordlists) and if the system files protecting them (/etc/shadow) are misconfigured to be readable by low-privileged users.

```bash
#root Access
su root

#password
password321
```
<p align="center">
  <img width="500" height="101" alt="image" src="https://github.com/user-attachments/assets/1d0e7ede-d1b0-4be7-a5ee-41c5b301c8c5" />
  <br>
</p>
The command was successful, and the shell prompt changed from $ to #, indicating root-level access.
<br>
<br>
After completing the exploitation and cracking phase, the following sensitive data was successfully exfiltrated and decrypted:

- Captured Hash: $6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0
- Encryption Standard: SHA-512
- Decrypted Password: Password123

# Task 6 - Sudo (Shell Escape Sequences)
```bash
#List the programs which sudo allows your user to run
sudo -l
```
<p align="center">
  <img width="500" height="246" alt="image" src="https://github.com/user-attachments/assets/a0141d4e-4b21-4567-aa8d-6d43cee3299b" />
  <br>
</p>
The sudo -l command output lists the specific binaries that the current user can run as root. In this lab environment, I identified several binaries (such as vim, find, or nano) that do not require a root password to execute.

```bash
#execute a system shell
sudo awk 'BEGIN {system("/bin/sh")}'
```
<p align="center">
  <img width="500" height="80" alt="image" src="https://github.com/user-attachments/assets/7e75b744-d444-4dd0-b74b-add92a87f66f" />
  <br>
</p>
Since the system allowed the execution of awk with sudo privileges without requiring a password, I utilized the BEGIN block to execute a system shell before any files were processed.

# Task 11 - SUID / SGID Executables (Known Exploits)
```bash
#system-wide search to identify all executables with special permissions
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```
<p align="center">
  <img width="500" height="295" alt="image" src="https://github.com/user-attachments/assets/e59b76e3-5bf3-4c09-8d56-f9905e3bda96" />
  <br>
</p>
In this phase, I focused on identifying and exploiting known vulnerabilities within binaries that have the SUID (Set User ID) or SGID (Set Group ID) bits enabled. These special permissions allow a file to be executed with the privileges of the file's owner or group, respectively. To begin the investigation, I performed a system wide search to identify all executables with these special permissions.
<br>
<br>
By cross-referencing the version number (4.84-3) with public exploit databases, I identified a specific vulnerability documented in Exploit-DB (EDB-ID: 39535). The vulnerability exists in the way Exim handles the perl_startup variable when the SUID bit is set. An attacker can leverage this by creating a malicious environment where Exim is forced to execute arbitrary code with root privileges.

```bash
#Exploitation Script
ls -lh tools/suid/exim
```
<p align="center">
  <img width="500" height="66" alt="image" src="https://github.com/user-attachments/assets/c1bc24b0-c6ed-4ca6-8c36-7f6a8af2b59f" />
  <br>
</p>
I used the ls -lh command to inspect the specific path where the vulnerable Exim binary or its associated tools were stored. This step is critical to confirm the SUID bit presence and the owner of the file. With the target verified, I prepared to execute the exploit script derived from Exploit DB. The script is designed to manipulate the environment variables that Exim uses, specifically targeting the way it initializes its perl interpreter.

```bash
#run the script
./tools/suid/exim/cve-2016-1531.sh
```
<p align="center">
 <img width="500" height="93" alt="image" src="https://github.com/user-attachments/assets/b8773e5d-1dcd-4652-b866-3be7f7063729" />
  <br>
</p>
I initiated the exploit by calling the shell script specifically designed for CVE-2016-1531. The script successfully manipulated the environment variables and forced the vulnerable Exim binary to spawn a shell. Because the binary was running with SUID root permissions, the spawned shell inherited full administrative privileges.

# Task 18 - Passwords & Keys (SSH Keys)
In this phase, the objective was to search for sensitive information left behind in the filesystem, such as backup files or hidden directories that might contain credentials. Accessing another user's SSH private key is a classic "Lateral Movement" or "Privilege Escalation" technique.

```bash
#show all files including the hidden one
ls -la /
```
<p align="center">
 <img width="500" height="165" alt="image" src="https://github.com/user-attachments/assets/b875ab47-ee48-4f97-9908-dd1428c0d47b" />
  <br>
</p>
I began by performing a thorough inspection of the root directory (/). Unlike a standard ls, I used flags that reveal hidden files and detailed permission metadata. 

```bash
#read the contents of the file
cat /.ssh/root_key
```
<p align="center">
  <img width="500" height="470" alt="image" src="https://github.com/user-attachments/assets/2172a613-5dc1-4445-9e5c-48f7454c59a5" />
  <br>
</p>
I replicated the captured key into a new file named root_key on the local machine to facilitate the attack.

```bash
#initiated the SSH connection
ssh -i root_key -oPubkeyAcceptedKeyTypes=+ssh-rsa -oHostKeyAlgorithms=+ssh-rsa root@10.201.78.111
```
<p align="center">
 <img width="500" height="168" alt="image" src="https://github.com/user-attachments/assets/1954dbba-bc8d-4f38-a89e-5e3171d8e6b8" />
  <br>
</p>
After securing the key with chmod 600, I initiated the SSH connection. Because the target system utilized legacy RSA algorithms, I added specific configuration flags to force the SSH client to accept the older key types. The authentication was successful. The server accepted the private key, and I was granted an interactive shell with the highest possible privileges.
