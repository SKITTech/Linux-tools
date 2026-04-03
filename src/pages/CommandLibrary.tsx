import { useState, useMemo, useCallback } from "react";
import { Terminal, Search, Copy, Check, Zap, Tag, ArrowRight, Loader2, Sparkles, Clock, Star, AlertTriangle } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Sidebar } from "@/components/Sidebar";
import { Sidebar } from "@/components/Sidebar";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";

// ─── Types ───
interface CommandExample {
  command: string;
  description: string;
}

interface CommandInfo {
  name: string;
  description: string;
  syntax: string;
  category: string;
  difficulty: "Beginner" | "Intermediate" | "Advanced";
  options: { flag: string; description: string }[];
  examples: CommandExample[];
  related: string[];
}

// ─── Data ───
const commandDatabase: Record<string, CommandInfo> = {
  ls: {
    name: "ls", description: "List directory contents", syntax: "ls [OPTION]... [FILE]...", category: "File Management", difficulty: "Beginner",
    options: [
      { flag: "-l", description: "Long listing format with permissions, owner, size, date" },
      { flag: "-a", description: "Show all files including hidden (dotfiles)" },
      { flag: "-h", description: "Human-readable file sizes (1K, 234M, 2G)" },
      { flag: "-R", description: "List subdirectories recursively" },
      { flag: "-t", description: "Sort by modification time, newest first" },
      { flag: "-S", description: "Sort by file size, largest first" },
      { flag: "-r", description: "Reverse order while sorting" },
      { flag: "-i", description: "Print inode number of each file" },
    ],
    examples: [
      { command: "ls -la", description: "List all files including hidden in long format" },
      { command: "ls -lhS", description: "List files sorted by size with human-readable sizes" },
      { command: "ls -lt /var/log", description: "List /var/log sorted by modification time" },
      { command: "ls -la --color=auto", description: "Colorized listing of all files" },
      { command: "ls -d */", description: "List only directories in current path" },
      { command: "ls -1", description: "List one file per line" },
      { command: "ls -lR /etc", description: "Recursively list all files under /etc" },
      { command: "ls -lah /tmp | head -20", description: "List first 20 entries in /tmp" },
    ],
    related: ["dir", "tree", "find", "stat"],
  },
  grep: {
    name: "grep", description: "Search for patterns in files using regular expressions", syntax: "grep [OPTIONS] PATTERN [FILE...]", category: "Text Processing", difficulty: "Intermediate",
    options: [
      { flag: "-i", description: "Case-insensitive matching" },
      { flag: "-r", description: "Recursive search through directories" },
      { flag: "-n", description: "Show line numbers with output" },
      { flag: "-v", description: "Invert match — show lines NOT matching" },
      { flag: "-c", description: "Print only count of matching lines" },
      { flag: "-l", description: "Print only filenames containing matches" },
      { flag: "-E", description: "Use extended regular expressions (ERE)" },
      { flag: "-w", description: "Match whole words only" },
      { flag: "-A N", description: "Print N lines after each match" },
      { flag: "-B N", description: "Print N lines before each match" },
    ],
    examples: [
      { command: "grep 'error' /var/log/syslog", description: "Find 'error' in syslog" },
      { command: "grep -ri 'TODO' ./src/", description: "Recursively find TODO (case-insensitive)" },
      { command: "grep -rn 'function' *.js", description: "Find 'function' with line numbers in JS files" },
      { command: "grep -v '^#' /etc/ssh/sshd_config", description: "Show config lines (skip comments)" },
      { command: "grep -c 'Failed' /var/log/auth.log", description: "Count failed login attempts" },
      { command: "grep -E '\\b[0-9]{1,3}(\\.[0-9]{1,3}){3}\\b' access.log", description: "Extract IP addresses from log" },
      { command: "ps aux | grep nginx", description: "Find nginx processes" },
      { command: "grep -l 'password' /etc/*", description: "List files in /etc containing 'password'" },
      { command: "dmesg | grep -i 'error\\|warning'", description: "Find errors and warnings in kernel log" },
      { command: "grep -A5 'server {' /etc/nginx/nginx.conf", description: "Show server blocks with 5 lines of context" },
    ],
    related: ["awk", "sed", "find", "ag", "rg"],
  },
  find: {
    name: "find", description: "Search for files and directories in a hierarchy", syntax: "find [PATH] [OPTIONS] [EXPRESSION]", category: "File Management", difficulty: "Intermediate",
    options: [
      { flag: "-name", description: "Search by filename pattern (case-sensitive)" },
      { flag: "-iname", description: "Search by filename pattern (case-insensitive)" },
      { flag: "-type f", description: "Find regular files only" },
      { flag: "-type d", description: "Find directories only" },
      { flag: "-size", description: "Search by file size (+100M = larger than)" },
      { flag: "-mtime", description: "Find by modification time in days" },
      { flag: "-exec", description: "Execute command on each result" },
      { flag: "-delete", description: "Delete matching files" },
      { flag: "-perm", description: "Find by permission mode" },
      { flag: "-user", description: "Find files owned by user" },
    ],
    examples: [
      { command: "find /var -name '*.log'", description: "Find all .log files under /var" },
      { command: "find . -type f -size +100M", description: "Find files larger than 100MB" },
      { command: "find / -type f -mtime -1", description: "Files modified in the last 24 hours" },
      { command: "find . -name '*.tmp' -delete", description: "Delete all .tmp files" },
      { command: "find /home -user john -type f", description: "Find all files owned by john" },
      { command: "find . -perm 777", description: "Find files with 777 permissions" },
      { command: "find . -empty -type d", description: "Find empty directories" },
      { command: "find / -name '*.conf' -exec grep -l 'ssl' {} +", description: "Find config files mentioning SSL" },
      { command: "find . -newer reference.txt", description: "Files newer than reference.txt" },
      { command: "find /var/log -name '*.gz' -mtime +30 -delete", description: "Clean up old compressed logs" },
    ],
    related: ["locate", "ls", "grep", "fd"],
  },
  tar: {
    name: "tar", description: "Create, extract, and manage archive files", syntax: "tar [OPTIONS] [FILE]...", category: "Archiving", difficulty: "Intermediate",
    options: [
      { flag: "-c", description: "Create a new archive" },
      { flag: "-x", description: "Extract files from archive" },
      { flag: "-v", description: "Verbose — list files processed" },
      { flag: "-f", description: "Specify archive filename" },
      { flag: "-z", description: "Compress/decompress with gzip" },
      { flag: "-j", description: "Compress/decompress with bzip2" },
      { flag: "-J", description: "Compress/decompress with xz" },
      { flag: "-t", description: "List contents of archive" },
      { flag: "--exclude", description: "Exclude files matching pattern" },
    ],
    examples: [
      { command: "tar -cvzf backup.tar.gz /home/user/", description: "Create gzipped backup of home directory" },
      { command: "tar -xvzf archive.tar.gz", description: "Extract gzipped archive" },
      { command: "tar -xvzf archive.tar.gz -C /opt/", description: "Extract to specific directory" },
      { command: "tar -tvf archive.tar.gz", description: "List contents without extracting" },
      { command: "tar -cvjf backup.tar.bz2 /etc/", description: "Create bzip2 compressed archive" },
      { command: "tar -cvzf backup.tar.gz --exclude='*.log' /var/", description: "Archive excluding log files" },
      { command: "tar -cvzf $(date +%F)-backup.tar.gz /data/", description: "Date-stamped backup" },
      { command: "tar -xvf archive.tar --strip-components=1", description: "Extract removing top directory" },
    ],
    related: ["gzip", "bzip2", "zip", "unzip", "xz"],
  },
  chmod: {
    name: "chmod", description: "Change file access permissions", syntax: "chmod [OPTION]... MODE FILE...", category: "Permissions", difficulty: "Beginner",
    options: [
      { flag: "-R", description: "Recursively change permissions" },
      { flag: "-v", description: "Verbose — report changes" },
      { flag: "-c", description: "Report only when a change is made" },
      { flag: "--reference", description: "Copy permissions from reference file" },
    ],
    examples: [
      { command: "chmod 755 script.sh", description: "rwxr-xr-x — owner full, others read+execute" },
      { command: "chmod +x deploy.sh", description: "Add execute permission for everyone" },
      { command: "chmod 644 index.html", description: "rw-r--r-- — owner read/write, others read" },
      { command: "chmod -R 750 /var/www/private", description: "Recursively set directory permissions" },
      { command: "chmod u+s /usr/bin/prog", description: "Set SUID bit (run as owner)" },
      { command: "chmod g+s /shared/", description: "Set SGID bit on directory" },
      { command: "chmod o-rwx secret.txt", description: "Remove all permissions for others" },
      { command: "chmod --reference=good.txt bad.txt", description: "Copy permissions from another file" },
    ],
    related: ["chown", "chgrp", "stat", "umask"],
  },
  chown: {
    name: "chown", description: "Change file owner and group", syntax: "chown [OPTION]... [OWNER][:[GROUP]] FILE...", category: "Permissions", difficulty: "Beginner",
    options: [
      { flag: "-R", description: "Recursively change ownership" },
      { flag: "-v", description: "Verbose — report changes" },
      { flag: "--reference", description: "Copy ownership from reference file" },
      { flag: "-h", description: "Affect symbolic links instead of referenced file" },
    ],
    examples: [
      { command: "chown root:root /etc/myconfig", description: "Set owner and group to root" },
      { command: "chown -R www-data:www-data /var/www/", description: "Recursively set web server ownership" },
      { command: "chown :developers project/", description: "Change only the group" },
      { command: "chown john file.txt", description: "Change owner to john" },
      { command: "chown -R $USER:$USER ~/projects/", description: "Set current user as owner recursively" },
      { command: "chown --reference=/var/www/html /var/www/new-site", description: "Copy ownership from existing site" },
    ],
    related: ["chmod", "chgrp", "id", "groups"],
  },
  curl: {
    name: "curl", description: "Transfer data to/from servers using various protocols", syntax: "curl [OPTIONS] [URL]", category: "Networking", difficulty: "Intermediate",
    options: [
      { flag: "-o FILE", description: "Save output to file" },
      { flag: "-O", description: "Save with remote filename" },
      { flag: "-L", description: "Follow HTTP redirects" },
      { flag: "-I", description: "Fetch HTTP headers only" },
      { flag: "-X METHOD", description: "Specify HTTP method (GET, POST, PUT, DELETE)" },
      { flag: "-d DATA", description: "Send POST data" },
      { flag: "-H HEADER", description: "Add custom HTTP header" },
      { flag: "-s", description: "Silent mode — no progress bar" },
      { flag: "-k", description: "Allow insecure SSL connections" },
      { flag: "-u USER:PASS", description: "HTTP basic authentication" },
    ],
    examples: [
      { command: "curl -I https://example.com", description: "Check HTTP headers and status code" },
      { command: "curl -O https://example.com/file.zip", description: "Download file with original name" },
      { command: "curl -X POST -H 'Content-Type: application/json' -d '{\"key\":\"val\"}' https://api.example.com", description: "POST JSON data to API" },
      { command: "curl -sL https://get.docker.com | sh", description: "Download and run install script" },
      { command: "curl -u admin:pass https://api.example.com/admin", description: "Request with basic auth" },
      { command: "curl -w '%{http_code}' -s -o /dev/null https://example.com", description: "Get only HTTP status code" },
      { command: "curl -x http://proxy:8080 https://example.com", description: "Use HTTP proxy" },
      { command: "curl --resolve example.com:443:1.2.3.4 https://example.com", description: "Test specific server IP for domain" },
    ],
    related: ["wget", "httpie", "ssh", "nc"],
  },
  ssh: {
    name: "ssh", description: "Secure Shell — remote login and command execution", syntax: "ssh [OPTIONS] [user@]hostname [command]", category: "Networking", difficulty: "Beginner",
    options: [
      { flag: "-p PORT", description: "Connect to specified port" },
      { flag: "-i KEY", description: "Use identity file (private key)" },
      { flag: "-v", description: "Verbose mode for debugging" },
      { flag: "-L", description: "Local port forwarding (tunnel)" },
      { flag: "-R", description: "Remote port forwarding" },
      { flag: "-D", description: "Dynamic SOCKS proxy" },
      { flag: "-N", description: "No remote command (for tunneling)" },
      { flag: "-t", description: "Force pseudo-terminal allocation" },
    ],
    examples: [
      { command: "ssh user@192.168.1.100", description: "Connect to remote server" },
      { command: "ssh -p 2222 user@host", description: "Connect on custom port" },
      { command: "ssh -i ~/.ssh/id_rsa user@host", description: "Connect with specific private key" },
      { command: "ssh user@host 'df -h'", description: "Run single command remotely" },
      { command: "ssh -L 8080:localhost:80 user@host", description: "Forward local 8080 to remote 80" },
      { command: "ssh -D 1080 user@host", description: "Create SOCKS5 proxy tunnel" },
      { command: "ssh-copy-id user@host", description: "Copy public key for passwordless login" },
      { command: "ssh -J jumphost user@target", description: "Connect via jump/bastion host" },
    ],
    related: ["scp", "sftp", "ssh-keygen", "rsync"],
  },
  systemctl: {
    name: "systemctl", description: "Control the systemd service manager", syntax: "systemctl [OPTIONS] COMMAND [UNIT]", category: "System", difficulty: "Intermediate",
    options: [
      { flag: "start", description: "Start a service" },
      { flag: "stop", description: "Stop a service" },
      { flag: "restart", description: "Restart a service" },
      { flag: "reload", description: "Reload service configuration" },
      { flag: "status", description: "Show service status" },
      { flag: "enable", description: "Enable service to start at boot" },
      { flag: "disable", description: "Disable service at boot" },
      { flag: "is-active", description: "Check if service is running" },
      { flag: "list-units", description: "List all loaded units" },
      { flag: "daemon-reload", description: "Reload systemd manager config" },
    ],
    examples: [
      { command: "systemctl status nginx", description: "Check nginx service status" },
      { command: "systemctl restart apache2", description: "Restart Apache web server" },
      { command: "systemctl enable --now docker", description: "Enable and start Docker immediately" },
      { command: "systemctl list-units --type=service --state=running", description: "List all running services" },
      { command: "systemctl is-active mysql", description: "Check if MySQL is running" },
      { command: "systemctl mask firewalld", description: "Completely disable a service" },
      { command: "systemctl cat nginx", description: "Show service unit file" },
      { command: "systemctl list-timers", description: "List all active timers" },
      { command: "journalctl -u nginx -f", description: "Follow live logs for nginx" },
    ],
    related: ["service", "journalctl", "timedatectl", "hostnamectl"],
  },
  docker: {
    name: "docker", description: "Container management platform", syntax: "docker [OPTIONS] COMMAND", category: "Containers", difficulty: "Intermediate",
    options: [
      { flag: "run", description: "Create and start a container" },
      { flag: "ps", description: "List running containers" },
      { flag: "images", description: "List available images" },
      { flag: "build", description: "Build image from Dockerfile" },
      { flag: "exec", description: "Execute command in running container" },
      { flag: "logs", description: "View container logs" },
      { flag: "stop", description: "Stop running container" },
      { flag: "rm", description: "Remove container" },
      { flag: "compose", description: "Multi-container orchestration" },
    ],
    examples: [
      { command: "docker run -d -p 80:80 nginx", description: "Run nginx container in background" },
      { command: "docker ps -a", description: "List all containers (including stopped)" },
      { command: "docker exec -it mycontainer bash", description: "Open bash shell in container" },
      { command: "docker logs -f --tail 100 myapp", description: "Follow last 100 log lines" },
      { command: "docker build -t myapp:latest .", description: "Build image from current directory" },
      { command: "docker compose up -d", description: "Start all services from docker-compose.yml" },
      { command: "docker system prune -af", description: "Clean up all unused resources" },
      { command: "docker stats", description: "Live resource usage for all containers" },
      { command: "docker network ls", description: "List Docker networks" },
      { command: "docker volume ls", description: "List Docker volumes" },
    ],
    related: ["podman", "kubectl", "docker-compose", "containerd"],
  },
  iptables: {
    name: "iptables", description: "IPv4 packet filtering and NAT administration", syntax: "iptables [-t table] COMMAND chain rule", category: "Networking", difficulty: "Advanced",
    options: [
      { flag: "-A", description: "Append rule to chain" },
      { flag: "-D", description: "Delete rule from chain" },
      { flag: "-I", description: "Insert rule at position" },
      { flag: "-L", description: "List rules" },
      { flag: "-F", description: "Flush (delete all rules)" },
      { flag: "-P", description: "Set default policy" },
      { flag: "-s", description: "Source IP address" },
      { flag: "-d", description: "Destination IP address" },
      { flag: "-p", description: "Protocol (tcp, udp, icmp)" },
      { flag: "--dport", description: "Destination port" },
      { flag: "-j", description: "Target action (ACCEPT, DROP, REJECT)" },
    ],
    examples: [
      { command: "iptables -L -v -n", description: "List all rules with details" },
      { command: "iptables -A INPUT -p tcp --dport 22 -j ACCEPT", description: "Allow SSH" },
      { command: "iptables -A INPUT -p tcp --dport 80 -j ACCEPT", description: "Allow HTTP" },
      { command: "iptables -A INPUT -s 192.168.1.100 -j DROP", description: "Block specific IP" },
      { command: "iptables -A INPUT -p tcp --dport 3306 -s 10.0.0.0/8 -j ACCEPT", description: "Allow MySQL from internal network" },
      { command: "iptables -A INPUT -p icmp --icmp-type echo-request -j DROP", description: "Block ping" },
      { command: "iptables -P INPUT DROP", description: "Set default INPUT policy to DROP" },
      { command: "iptables-save > /etc/iptables.rules", description: "Save current rules" },
      { command: "iptables-restore < /etc/iptables.rules", description: "Restore saved rules" },
    ],
    related: ["nftables", "ufw", "firewalld", "ip6tables"],
  },
  rsync: {
    name: "rsync", description: "Fast, versatile file copying and synchronization tool", syntax: "rsync [OPTIONS] SRC DEST", category: "File Management", difficulty: "Intermediate",
    options: [
      { flag: "-a", description: "Archive mode (preserves permissions, timestamps, etc.)" },
      { flag: "-v", description: "Verbose output" },
      { flag: "-z", description: "Compress during transfer" },
      { flag: "--delete", description: "Delete files in dest not in source" },
      { flag: "-e", description: "Specify remote shell (e.g., ssh)" },
      { flag: "--progress", description: "Show transfer progress" },
      { flag: "--exclude", description: "Exclude files matching pattern" },
      { flag: "-n", description: "Dry run — show what would happen" },
    ],
    examples: [
      { command: "rsync -avz /src/ /backup/", description: "Archive sync with compression" },
      { command: "rsync -avz -e ssh /data/ user@remote:/backup/", description: "Sync to remote server over SSH" },
      { command: "rsync -avz --delete /src/ /mirror/", description: "Mirror sync (delete extra files)" },
      { command: "rsync -avz --progress /data/ /backup/", description: "Sync with progress indicator" },
      { command: "rsync -avz --exclude='*.log' /src/ /dest/", description: "Sync excluding log files" },
      { command: "rsync -avzn /src/ /dest/", description: "Dry run — preview changes" },
      { command: "rsync -avz -e 'ssh -p 2222' /data/ user@host:/backup/", description: "Sync over non-standard SSH port" },
    ],
    related: ["scp", "cp", "tar", "rclone"],
  },
  cd: {
    name: "cd", description: "Change current working directory", syntax: "cd [DIRECTORY]", category: "Navigation", difficulty: "Beginner",
    options: [
      { flag: "-", description: "Change to previous directory" },
      { flag: "~", description: "Change to home directory" },
      { flag: "..", description: "Move up one level" },
    ],
    examples: [
      { command: "cd /var/log", description: "Navigate to /var/log" },
      { command: "cd ~", description: "Go to home directory" },
      { command: "cd -", description: "Switch to previous directory" },
      { command: "cd ../..", description: "Go up two directory levels" },
    ],
    related: ["pwd", "pushd", "popd", "ls"],
  },
  cat: {
    name: "cat", description: "Concatenate and display file contents", syntax: "cat [OPTION]... [FILE]...", category: "File Management", difficulty: "Beginner",
    options: [
      { flag: "-n", description: "Number all output lines" },
      { flag: "-b", description: "Number non-empty lines" },
      { flag: "-s", description: "Squeeze multiple blank lines" },
      { flag: "-E", description: "Show $ at end of each line" },
    ],
    examples: [
      { command: "cat /etc/os-release", description: "View OS release info" },
      { command: "cat -n script.sh", description: "Display with line numbers" },
      { command: "cat file1.txt file2.txt > merged.txt", description: "Merge files" },
      { command: "cat << 'EOF' > config.yml\nkey: value\nEOF", description: "Create file with heredoc" },
    ],
    related: ["less", "more", "head", "tail", "tac"],
  },
  ps: {
    name: "ps", description: "Report snapshot of current processes", syntax: "ps [OPTIONS]", category: "Process Management", difficulty: "Beginner",
    options: [
      { flag: "aux", description: "All processes, user-oriented format" },
      { flag: "-e", description: "Select all processes" },
      { flag: "-f", description: "Full format listing" },
      { flag: "--forest", description: "Show process tree" },
      { flag: "-p PID", description: "Select by process ID" },
    ],
    examples: [
      { command: "ps aux", description: "List all processes with details" },
      { command: "ps aux | grep nginx", description: "Find nginx processes" },
      { command: "ps -ef --forest", description: "Process tree view" },
      { command: "ps aux --sort=-%mem | head", description: "Top memory consumers" },
      { command: "ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head", description: "Top CPU consumers with custom fields" },
    ],
    related: ["top", "htop", "kill", "pgrep"],
  },
  kill: {
    name: "kill", description: "Send signals to processes", syntax: "kill [OPTIONS] PID...", category: "Process Management", difficulty: "Beginner",
    options: [
      { flag: "-9", description: "SIGKILL — Force terminate" },
      { flag: "-15", description: "SIGTERM — Graceful shutdown (default)" },
      { flag: "-HUP", description: "SIGHUP — Reload config" },
      { flag: "-l", description: "List all signals" },
    ],
    examples: [
      { command: "kill 1234", description: "Gracefully terminate process 1234" },
      { command: "kill -9 1234", description: "Force kill process 1234" },
      { command: "kill -HUP $(cat /var/run/nginx.pid)", description: "Reload nginx" },
      { command: "killall -9 python3", description: "Force kill all python3 processes" },
      { command: "pkill -f 'node server'", description: "Kill processes matching pattern" },
    ],
    related: ["ps", "top", "killall", "pkill", "pgrep"],
  },
  df: {
    name: "df", description: "Report file system disk space usage", syntax: "df [OPTION]... [FILE]...", category: "Disk Management", difficulty: "Beginner",
    options: [
      { flag: "-h", description: "Human-readable sizes" },
      { flag: "-T", description: "Show filesystem type" },
      { flag: "-i", description: "Show inode information" },
      { flag: "-a", description: "Include pseudo filesystems" },
    ],
    examples: [
      { command: "df -h", description: "Disk usage in human-readable format" },
      { command: "df -hT", description: "Disk usage with filesystem types" },
      { command: "df -h /", description: "Check root partition usage" },
      { command: "df -i", description: "Check inode usage" },
    ],
    related: ["du", "lsblk", "fdisk", "mount"],
  },
  du: {
    name: "du", description: "Estimate file and directory space usage", syntax: "du [OPTION]... [FILE]...", category: "Disk Management", difficulty: "Beginner",
    options: [
      { flag: "-h", description: "Human-readable sizes" },
      { flag: "-s", description: "Display only total" },
      { flag: "-d N", description: "Max depth of traversal" },
      { flag: "-a", description: "Show all files, not just directories" },
    ],
    examples: [
      { command: "du -sh /var/", description: "Total size of /var" },
      { command: "du -h --max-depth=1 /", description: "Size of top-level directories" },
      { command: "du -sh * | sort -rh | head -10", description: "Top 10 largest items" },
      { command: "du -ah /var/log | sort -rh | head -20", description: "Largest files in /var/log" },
    ],
    related: ["df", "ncdu", "ls", "find"],
  },
  awk: {
    name: "awk", description: "Pattern scanning and text processing language", syntax: "awk [OPTIONS] 'PROGRAM' [FILE...]", category: "Text Processing", difficulty: "Advanced",
    options: [
      { flag: "-F SEP", description: "Set field separator" },
      { flag: "-v VAR=VAL", description: "Set variable" },
      { flag: "-f FILE", description: "Read program from file" },
    ],
    examples: [
      { command: "awk '{print $1}' file.txt", description: "Print first column" },
      { command: "awk -F: '{print $1, $7}' /etc/passwd", description: "Show username and shell" },
      { command: "awk '/error/ {count++} END {print count}' log.txt", description: "Count error lines" },
      { command: "awk '{sum+=$1} END {print sum}' numbers.txt", description: "Sum first column" },
      { command: "df -h | awk '$5+0 > 80 {print $6, $5}'", description: "Partitions over 80% full" },
      { command: "awk 'NR==10,NR==20' file.txt", description: "Print lines 10–20" },
    ],
    related: ["sed", "grep", "cut", "tr"],
  },
  sed: {
    name: "sed", description: "Stream editor for text transformation", syntax: "sed [OPTIONS] 'SCRIPT' [FILE...]", category: "Text Processing", difficulty: "Intermediate",
    options: [
      { flag: "-i", description: "Edit files in place" },
      { flag: "-n", description: "Suppress automatic printing" },
      { flag: "-e", description: "Add script command" },
      { flag: "-E", description: "Use extended regex" },
    ],
    examples: [
      { command: "sed 's/old/new/g' file.txt", description: "Replace all 'old' with 'new'" },
      { command: "sed -i 's/old/new/g' file.txt", description: "Replace in-place" },
      { command: "sed -n '5,10p' file.txt", description: "Print only lines 5–10" },
      { command: "sed '/^#/d' config.conf", description: "Remove comment lines" },
      { command: "sed -i '3i\\new line' file.txt", description: "Insert line at position 3" },
      { command: "sed 's/[[:space:]]*$//' file.txt", description: "Remove trailing whitespace" },
    ],
    related: ["awk", "grep", "tr", "cut"],
  },
  netstat: {
    name: "netstat", description: "Network connections, routing, and interface statistics", syntax: "netstat [OPTIONS]", category: "Networking", difficulty: "Intermediate",
    options: [
      { flag: "-t", description: "Show TCP connections" },
      { flag: "-u", description: "Show UDP connections" },
      { flag: "-l", description: "Show listening sockets" },
      { flag: "-n", description: "Numeric addresses (no DNS resolution)" },
      { flag: "-p", description: "Show PID and program name" },
    ],
    examples: [
      { command: "netstat -tulnp", description: "All listening ports with PIDs" },
      { command: "netstat -an | grep ESTABLISHED", description: "Active connections" },
      { command: "netstat -r", description: "Show routing table" },
      { command: "ss -tulnp", description: "Modern alternative using ss" },
    ],
    related: ["ss", "ip", "lsof", "nmap"],
  },
  ip: {
    name: "ip", description: "Show and manipulate network devices, routing, and tunnels", syntax: "ip [OPTIONS] OBJECT { COMMAND }", category: "Networking", difficulty: "Intermediate",
    options: [
      { flag: "addr", description: "IP address management" },
      { flag: "link", description: "Network device management" },
      { flag: "route", description: "Routing table management" },
      { flag: "neigh", description: "ARP/neighbor cache" },
      { flag: "-c", description: "Color output" },
      { flag: "-br", description: "Brief output" },
    ],
    examples: [
      { command: "ip addr show", description: "Show all IP addresses" },
      { command: "ip -br addr", description: "Brief IP address listing" },
      { command: "ip route show", description: "Show routing table" },
      { command: "ip link set eth0 up", description: "Bring interface up" },
      { command: "ip addr add 192.168.1.10/24 dev eth0", description: "Add IP address" },
      { command: "ip neigh show", description: "Show ARP cache" },
    ],
    related: ["ifconfig", "netstat", "ss", "ethtool"],
  },
  top: {
    name: "top", description: "Real-time process monitoring", syntax: "top [OPTIONS]", category: "Process Management", difficulty: "Beginner",
    options: [
      { flag: "-d N", description: "Update delay in seconds" },
      { flag: "-u USER", description: "Show only user's processes" },
      { flag: "-p PID", description: "Monitor specific PID" },
      { flag: "-b", description: "Batch mode for scripting" },
      { flag: "-n N", description: "Number of iterations" },
    ],
    examples: [
      { command: "top", description: "Start interactive monitor" },
      { command: "top -u www-data", description: "Monitor www-data processes" },
      { command: "top -bn1 | head -20", description: "Snapshot of top processes" },
      { command: "htop", description: "Enhanced interactive process viewer" },
    ],
    related: ["htop", "ps", "kill", "free", "vmstat"],
  },
  journalctl: {
    name: "journalctl", description: "Query and display systemd journal logs", syntax: "journalctl [OPTIONS]", category: "System", difficulty: "Intermediate",
    options: [
      { flag: "-u UNIT", description: "Show logs for specific unit/service" },
      { flag: "-f", description: "Follow new log entries (like tail -f)" },
      { flag: "--since", description: "Show entries since timestamp" },
      { flag: "-p PRIORITY", description: "Filter by priority (emerg, alert, crit, err, warning)" },
      { flag: "-b", description: "Show logs from current boot" },
      { flag: "-n N", description: "Show last N entries" },
      { flag: "--no-pager", description: "Don't pipe through pager" },
    ],
    examples: [
      { command: "journalctl -u nginx -f", description: "Follow nginx logs live" },
      { command: "journalctl --since '1 hour ago'", description: "Logs from last hour" },
      { command: "journalctl -p err -b", description: "Error+ level logs this boot" },
      { command: "journalctl --disk-usage", description: "Check journal disk usage" },
      { command: "journalctl -u sshd --since today", description: "Today's SSH logs" },
      { command: "journalctl -k", description: "Kernel messages only" },
    ],
    related: ["systemctl", "dmesg", "syslog", "tail"],
  },
  crontab: {
    name: "crontab", description: "Schedule recurring tasks with cron", syntax: "crontab [OPTIONS]", category: "System", difficulty: "Intermediate",
    options: [
      { flag: "-e", description: "Edit crontab" },
      { flag: "-l", description: "List crontab entries" },
      { flag: "-r", description: "Remove crontab" },
      { flag: "-u USER", description: "Operate on user's crontab" },
    ],
    examples: [
      { command: "crontab -l", description: "List scheduled tasks" },
      { command: "crontab -e", description: "Edit cron jobs" },
      { command: "*/5 * * * * /path/to/script.sh", description: "Run every 5 minutes" },
      { command: "0 2 * * * /usr/bin/backup.sh", description: "Run daily at 2 AM" },
      { command: "0 0 * * 0 certbot renew", description: "Renew SSL weekly on Sunday" },
      { command: "0 */6 * * * /scripts/check.sh", description: "Run every 6 hours" },
    ],
    related: ["at", "systemctl", "anacron", "watch"],
  },
  scp: {
    name: "scp", description: "Secure copy files between hosts over SSH", syntax: "scp [OPTIONS] SRC DEST", category: "Networking", difficulty: "Beginner",
    options: [
      { flag: "-r", description: "Copy directories recursively" },
      { flag: "-P PORT", description: "Specify SSH port" },
      { flag: "-i KEY", description: "Use identity file" },
      { flag: "-C", description: "Enable compression" },
    ],
    examples: [
      { command: "scp file.txt user@host:/tmp/", description: "Copy file to remote server" },
      { command: "scp user@host:/var/log/syslog .", description: "Copy file from remote server" },
      { command: "scp -r /data/ user@host:/backup/", description: "Copy directory recursively" },
      { command: "scp -P 2222 file.txt user@host:/path/", description: "Copy using custom SSH port" },
    ],
    related: ["rsync", "sftp", "ssh", "tar"],
  },
  wget: {
    name: "wget", description: "Non-interactive network file downloader", syntax: "wget [OPTIONS] URL", category: "Networking", difficulty: "Beginner",
    options: [
      { flag: "-O FILE", description: "Save to specific filename" },
      { flag: "-q", description: "Quiet mode" },
      { flag: "-c", description: "Continue partial download" },
      { flag: "-r", description: "Recursive download" },
      { flag: "--mirror", description: "Mirror a website" },
      { flag: "-b", description: "Background download" },
    ],
    examples: [
      { command: "wget https://example.com/file.tar.gz", description: "Download a file" },
      { command: "wget -O install.sh https://get.example.com", description: "Download with custom filename" },
      { command: "wget -c https://example.com/large-file.iso", description: "Resume interrupted download" },
      { command: "wget -q -O - https://api.ipify.org", description: "Get public IP silently" },
    ],
    related: ["curl", "aria2c", "axel", "scp"],
  },
  lsblk: {
    name: "lsblk", description: "List information about block devices", syntax: "lsblk [OPTIONS]", category: "Disk Management", difficulty: "Beginner",
    options: [
      { flag: "-f", description: "Show filesystem info" },
      { flag: "-a", description: "Show all devices" },
      { flag: "-o COLUMNS", description: "Specify output columns" },
    ],
    examples: [
      { command: "lsblk", description: "List all block devices" },
      { command: "lsblk -f", description: "Show filesystems and labels" },
      { command: "lsblk -o NAME,SIZE,TYPE,MOUNTPOINT", description: "Custom column output" },
    ],
    related: ["df", "fdisk", "mount", "blkid"],
  },
};

const categories = [...new Set(Object.values(commandDatabase).map(c => c.category))].sort();

const difficultyColors: Record<string, string> = {
  Beginner: "bg-emerald-500/10 text-emerald-500 border-emerald-500/20",
  Intermediate: "bg-amber-500/10 text-amber-500 border-amber-500/20",
  Advanced: "bg-red-500/10 text-red-500 border-red-500/20",
};

const CommandLibrary = () => {
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedCommand, setSelectedCommand] = useState<CommandInfo | null>(null);
  const [copiedCommand, setCopiedCommand] = useState<string | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [recentSearches, setRecentSearches] = useState<string[]>([]);
  const [showSuggestions, setShowSuggestions] = useState(false);

  // AI Command Finder
  const [aiQuery, setAiQuery] = useState("");
  const [aiResult, setAiResult] = useState<any>(null);
  const [aiLoading, setAiLoading] = useState(false);

  const allCommands = useMemo(() => Object.values(commandDatabase).sort((a, b) => a.name.localeCompare(b.name)), []);

  const filteredCommands = useMemo(() => {
    let cmds = allCommands;
    if (selectedCategory) cmds = cmds.filter(c => c.category === selectedCategory);
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      cmds = cmds.filter(c => c.name.includes(q) || c.description.toLowerCase().includes(q) || c.category.toLowerCase().includes(q));
    }
    return cmds;
  }, [allCommands, selectedCategory, searchQuery]);

  const suggestions = useMemo(() => {
    if (!searchQuery.trim()) return [];
    const q = searchQuery.toLowerCase();
    return allCommands.filter(c => c.name.startsWith(q) || c.name.includes(q)).slice(0, 6);
  }, [searchQuery, allCommands]);

  const selectCommand = useCallback((cmd: CommandInfo) => {
    setSelectedCommand(cmd);
    setShowSuggestions(false);
    setRecentSearches(prev => {
      const filtered = prev.filter(n => n !== cmd.name);
      return [cmd.name, ...filtered].slice(0, 8);
    });
  }, []);

  const handleSearch = useCallback(async () => {
    const q = searchQuery.toLowerCase().trim();
    if (!q) return;
    if (commandDatabase[q]) {
      selectCommand(commandDatabase[q]);
    } else if (filteredCommands.length === 1) {
      selectCommand(filteredCommands[0]);
    } else if (filteredCommands.length === 0) {
      // Auto-fallback to AI Command Finder
      setAiQuery(searchQuery);
      setAiLoading(true);
      setAiResult(null);
      setSelectedCommand(null);
      try {
        const { data, error } = await supabase.functions.invoke("command-finder", {
          body: { query: searchQuery },
        });
        if (error) throw error;
        setAiResult(data);
        toast.success("Command not in local database — AI found a result!");
      } catch (err: any) {
        toast.error("AI search failed: " + (err.message || "Unknown error"));
      } finally {
        setAiLoading(false);
      }
    }
  }, [searchQuery, filteredCommands, selectCommand]);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCommand(text);
    toast.success("Copied!");
    setTimeout(() => setCopiedCommand(null), 2000);
  };


  return (
    <Sidebar>
      <div className="min-h-screen bg-background">
        {/* Hero Header */}
        <header className="border-b border-border/50 bg-gradient-to-br from-primary/5 via-background to-accent/5">
          <div className="container mx-auto px-6 py-8">
            <div className="flex items-center gap-3 mb-1">
              <div className="w-10 h-10 rounded-xl bg-primary/10 flex items-center justify-center">
                <Terminal className="w-5 h-5 text-primary" />
              </div>
              <h1 className="text-3xl font-bold text-foreground tracking-tight">Linux Commands</h1>
            </div>
            <p className="text-muted-foreground ml-[52px]">
              Search, learn, and master Linux commands — {allCommands.length} commands available
            </p>
          </div>
        </header>

        <main className="container mx-auto px-6 py-6 space-y-6">
          <div className="w-full space-y-6">
              {/* Search */}
              <div className="relative">
                <div className="flex gap-2">
                  <div className="relative flex-1">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                    <Input
                      value={searchQuery}
                      onChange={(e) => { setSearchQuery(e.target.value); setShowSuggestions(true); }}
                      onKeyDown={(e) => e.key === "Enter" && handleSearch()}
                      onFocus={() => setShowSuggestions(true)}
                      onBlur={() => setTimeout(() => setShowSuggestions(false), 200)}
                      placeholder="Search commands... (e.g., grep, find, tar)"
                      className="pl-10 h-12 text-base bg-card border-border/50"
                    />
                    {/* Autocomplete */}
                    {showSuggestions && suggestions.length > 0 && searchQuery.trim() && (
                      <div className="absolute top-full left-0 right-0 mt-1 bg-card border border-border rounded-lg shadow-xl z-50 overflow-hidden">
                        {suggestions.map(s => (
                          <button
                            key={s.name}
                            onMouseDown={() => selectCommand(s)}
                            className="w-full flex items-center gap-3 px-4 py-2.5 text-left hover:bg-muted/60 transition-colors"
                          >
                            <Terminal className="w-3.5 h-3.5 text-primary shrink-0" />
                            <span className="font-mono text-sm font-medium text-foreground">{s.name}</span>
                            <span className="text-xs text-muted-foreground truncate">{s.description}</span>
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                  <Button onClick={handleSearch} size="lg" className="h-12 px-6">
                    <Search className="w-4 h-4 mr-2" /> Search
                  </Button>
                </div>
              </div>

              {/* Recent */}
              {recentSearches.length > 0 && !selectedCommand && (
                <div className="flex items-center gap-2 flex-wrap">
                  <Clock className="w-3.5 h-3.5 text-muted-foreground" />
                  <span className="text-xs text-muted-foreground">Recent:</span>
                  {recentSearches.map(name => (
                    <button key={name} onClick={() => selectCommand(commandDatabase[name])} className="text-xs font-mono px-2 py-1 rounded-md bg-muted/60 text-foreground hover:bg-muted transition-colors">
                      {name}
                    </button>
                  ))}
                </div>
              )}

              {/* Category Filter */}
              <div className="flex gap-2 flex-wrap">
                <button onClick={() => setSelectedCategory(null)} className={`text-xs px-3 py-1.5 rounded-full border transition-colors ${!selectedCategory ? 'bg-primary text-primary-foreground border-primary' : 'bg-card border-border/50 text-muted-foreground hover:text-foreground'}`}>
                  All
                </button>
                {categories.map(cat => (
                  <button key={cat} onClick={() => setSelectedCategory(cat === selectedCategory ? null : cat)} className={`text-xs px-3 py-1.5 rounded-full border transition-colors ${selectedCategory === cat ? 'bg-primary text-primary-foreground border-primary' : 'bg-card border-border/50 text-muted-foreground hover:text-foreground'}`}>
                    {cat}
                  </button>
                ))}
              </div>

              {/* Selected Command Detail */}
              {selectedCommand ? (
                <div className="space-y-4">
                  <button onClick={() => setSelectedCommand(null)} className="text-sm text-muted-foreground hover:text-foreground flex items-center gap-1">
                    ← Back to all commands
                  </button>

                  {/* Overview */}
                  <Card className="p-6 bg-card/80 backdrop-blur border-border/50">
                    <div className="flex items-start justify-between gap-4 mb-4">
                      <div>
                        <div className="flex items-center gap-3 mb-2">
                          <h2 className="text-2xl font-bold font-mono text-foreground">{selectedCommand.name}</h2>
                          <Badge variant="outline" className={difficultyColors[selectedCommand.difficulty]}>{selectedCommand.difficulty}</Badge>
                          <Badge variant="outline" className="bg-muted/50">{selectedCommand.category}</Badge>
                        </div>
                        <p className="text-muted-foreground">{selectedCommand.description}</p>
                      </div>
                    </div>
                    <div className="bg-muted/30 rounded-lg px-4 py-3 font-mono text-sm flex items-center justify-between">
                      <code className="text-foreground">{selectedCommand.syntax}</code>
                      <Button size="sm" variant="ghost" onClick={() => copyToClipboard(selectedCommand.syntax)} className="h-7 w-7 p-0 shrink-0">
                        {copiedCommand === selectedCommand.syntax ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                      </Button>
                    </div>
                  </Card>

                  <div className="grid lg:grid-cols-2 gap-4">
                    {/* Examples */}
                    <Card className="p-6 bg-card/80 backdrop-blur border-border/50">
                      <h3 className="font-semibold text-foreground mb-4 flex items-center gap-2">
                        <Zap className="w-4 h-4 text-primary" /> Real-World Examples
                      </h3>
                      <div className="space-y-2">
                        {selectedCommand.examples.map((ex, i) => (
                          <div key={i} className="group rounded-lg bg-muted/20 hover:bg-muted/40 transition-colors p-3">
                            <div className="flex items-start justify-between gap-2">
                              <code className="font-mono text-sm text-foreground break-all">{ex.command}</code>
                              <Button size="sm" variant="ghost" onClick={() => copyToClipboard(ex.command)} className="opacity-0 group-hover:opacity-100 transition-opacity h-6 w-6 p-0 shrink-0">
                                {copiedCommand === ex.command ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                              </Button>
                            </div>
                            <p className="text-xs text-muted-foreground mt-1">{ex.description}</p>
                          </div>
                        ))}
                      </div>
                    </Card>

                    {/* Options + Related */}
                    <div className="space-y-4">
                      <Card className="p-6 bg-card/80 backdrop-blur border-border/50">
                        <h3 className="font-semibold text-foreground mb-4 flex items-center gap-2">
                          <Tag className="w-4 h-4 text-primary" /> Options & Flags
                        </h3>
                        <div className="space-y-2">
                          {selectedCommand.options.map((opt, i) => (
                            <div key={i} className="flex items-start gap-3 py-1.5">
                              <code className="font-mono text-sm font-medium text-primary bg-primary/10 px-2 py-0.5 rounded shrink-0">{opt.flag}</code>
                              <span className="text-sm text-muted-foreground">{opt.description}</span>
                            </div>
                          ))}
                        </div>
                      </Card>

                      {selectedCommand.related.length > 0 && (
                        <Card className="p-6 bg-card/80 backdrop-blur border-border/50">
                          <h3 className="font-semibold text-foreground mb-3 flex items-center gap-2">
                            <ArrowRight className="w-4 h-4 text-primary" /> Related Commands
                          </h3>
                          <div className="flex gap-2 flex-wrap">
                            {selectedCommand.related.map(r => (
                              <button
                                key={r}
                                onClick={() => commandDatabase[r] && selectCommand(commandDatabase[r])}
                                className={`font-mono text-sm px-3 py-1.5 rounded-lg border transition-colors ${
                                  commandDatabase[r]
                                    ? 'bg-muted/30 border-border/50 text-foreground hover:bg-primary/10 hover:border-primary/30 cursor-pointer'
                                    : 'bg-muted/10 border-border/30 text-muted-foreground cursor-default'
                                }`}
                              >
                                {r}
                              </button>
                            ))}
                          </div>
                        </Card>
                      )}
                    </div>
                  </div>
                </div>
              ) : (
                /* Command Grid */
                <div className="grid sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
                  {filteredCommands.map(cmd => (
                    <button key={cmd.name} onClick={() => selectCommand(cmd)} className="text-left group">
                      <Card className="p-4 h-full bg-card/80 backdrop-blur border-border/50 hover:border-primary/30 hover:shadow-lg hover:shadow-primary/5 transition-all duration-200">
                        <div className="flex items-center justify-between mb-2">
                          <code className="font-mono font-bold text-foreground group-hover:text-primary transition-colors">{cmd.name}</code>
                          <Badge variant="outline" className={`text-[10px] ${difficultyColors[cmd.difficulty]}`}>{cmd.difficulty}</Badge>
                        </div>
                        <p className="text-xs text-muted-foreground leading-relaxed line-clamp-2">{cmd.description}</p>
                        <div className="mt-2">
                          <span className="text-[10px] text-muted-foreground/60">{cmd.category}</span>
                        </div>
                      </Card>
                    </button>
                  ))}
                  {filteredCommands.length === 0 && !aiLoading && !aiResult && (
                    <div className="col-span-full text-center py-12 text-muted-foreground">
                      <Terminal className="w-12 h-12 mx-auto mb-3 opacity-30" />
                      <p>No commands found. Press Search to use AI Command Finder!</p>
                    </div>
                  )}
                </div>
              )}

              {/* AI Loading */}
              {aiLoading && (
                <Card className="p-8 bg-card/80 backdrop-blur border-border/50">
                  <div className="flex flex-col items-center justify-center text-muted-foreground">
                    <Loader2 className="w-8 h-8 animate-spin mb-3 text-primary" />
                    <p className="text-sm">AI is finding the right command...</p>
                  </div>
                </Card>
              )}

              {/* AI Result (inline) */}
              {aiResult && !selectedCommand && (
                <div className="space-y-4">
                  <div className="flex items-center gap-2 mb-2">
                    <Sparkles className="w-4 h-4 text-primary" />
                    <span className="text-sm font-medium text-primary">AI Command Finder Result</span>
                    <button onClick={() => setAiResult(null)} className="text-xs text-muted-foreground hover:text-foreground ml-auto">✕ Clear</button>
                  </div>
                  <Card className="p-6 bg-card/80 backdrop-blur border-border/50">
                    <div className="flex items-center gap-2 mb-3">
                      <Star className="w-4 h-4 text-primary" />
                      <h3 className="font-semibold text-foreground">Recommended Command</h3>
                    </div>
                    <div className="bg-muted/30 rounded-lg px-4 py-3 font-mono text-sm flex items-center justify-between mb-3">
                      <code className="text-foreground break-all">{aiResult.command}</code>
                      <Button size="sm" variant="ghost" onClick={() => copyToClipboard(aiResult.command)} className="h-7 w-7 p-0 shrink-0">
                        {copiedCommand === aiResult.command ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                      </Button>
                    </div>
                    <p className="text-sm text-muted-foreground">{aiResult.explanation}</p>
                  </Card>

                  {aiResult.examples?.length > 0 && (
                    <Card className="p-6 bg-card/80 backdrop-blur border-border/50">
                      <h3 className="font-semibold text-foreground mb-4 flex items-center gap-2">
                        <Zap className="w-4 h-4 text-primary" /> Examples
                      </h3>
                      <div className="space-y-2">
                        {aiResult.examples.map((ex: any, i: number) => (
                          <div key={i} className="group rounded-lg bg-muted/20 hover:bg-muted/40 transition-colors p-3">
                            <div className="flex items-start justify-between gap-2">
                              <code className="font-mono text-sm text-foreground break-all">{ex.command}</code>
                              <Button size="sm" variant="ghost" onClick={() => copyToClipboard(ex.command)} className="opacity-0 group-hover:opacity-100 transition-opacity h-6 w-6 p-0 shrink-0">
                                {copiedCommand === ex.command ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                              </Button>
                            </div>
                            <p className="text-xs text-muted-foreground mt-1">{ex.description}</p>
                          </div>
                        ))}
                      </div>
                    </Card>
                  )}

                  <div className="grid md:grid-cols-2 gap-4">
                    {aiResult.alternatives?.length > 0 && (
                      <Card className="p-6 bg-card/80 backdrop-blur border-border/50">
                        <h3 className="font-semibold text-foreground mb-3 flex items-center gap-2">
                          <ArrowRight className="w-4 h-4 text-primary" /> Alternatives
                        </h3>
                        <div className="space-y-2">
                          {aiResult.alternatives.map((alt: string, i: number) => (
                            <div key={i} className="flex items-center justify-between bg-muted/20 rounded-lg px-3 py-2">
                              <code className="font-mono text-sm text-foreground break-all">{alt}</code>
                              <Button size="sm" variant="ghost" onClick={() => copyToClipboard(alt)} className="h-6 w-6 p-0 shrink-0">
                                {copiedCommand === alt ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                              </Button>
                            </div>
                          ))}
                        </div>
                      </Card>
                    )}

                    {aiResult.caution && (
                      <Card className="p-6 bg-destructive/5 border-destructive/20">
                        <h3 className="font-semibold text-foreground mb-2 flex items-center gap-2">
                          <AlertTriangle className="w-4 h-4 text-destructive" /> Caution
                        </h3>
                        <p className="text-sm text-muted-foreground">{aiResult.caution}</p>
                      </Card>
                    )}
                  </div>
                </div>
              )}
          </div>
        </main>
      </div>
    </Sidebar>
  );
};

export default CommandLibrary;
