import { useState } from "react";
import { Terminal, Search, BookOpen, ExternalLink, Copy, Check, Info } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Sidebar } from "@/components/Sidebar";
import { toast } from "sonner";

interface CommandInfo {
  name: string;
  description: string;
  syntax: string;
  options: { flag: string; description: string }[];
  examples: { command: string; description: string }[];
  category: string;
}

const commandDatabase: Record<string, CommandInfo> = {
  ls: {
    name: "ls",
    description: "List directory contents. Display information about files and directories.",
    syntax: "ls [OPTION]... [FILE]...",
    category: "File Management",
    options: [
      { flag: "-l", description: "Use long listing format" },
      { flag: "-a", description: "Show hidden files (starting with .)" },
      { flag: "-h", description: "Human-readable sizes (e.g., 1K, 234M)" },
      { flag: "-R", description: "List subdirectories recursively" },
      { flag: "-t", description: "Sort by modification time" },
      { flag: "-S", description: "Sort by file size" },
    ],
    examples: [
      { command: "ls -la", description: "List all files including hidden in long format" },
      { command: "ls -lh /var/log", description: "List files in /var/log with human-readable sizes" },
      { command: "ls -lt", description: "List files sorted by modification time" },
    ],
  },
  cd: {
    name: "cd",
    description: "Change the current working directory.",
    syntax: "cd [DIRECTORY]",
    category: "Navigation",
    options: [
      { flag: "-", description: "Change to previous directory" },
      { flag: "~", description: "Change to home directory" },
      { flag: "..", description: "Move up one directory level" },
    ],
    examples: [
      { command: "cd /var/log", description: "Change to /var/log directory" },
      { command: "cd ~", description: "Change to home directory" },
      { command: "cd -", description: "Change to previous directory" },
    ],
  },
  grep: {
    name: "grep",
    description: "Search for patterns in files. Print lines matching a pattern.",
    syntax: "grep [OPTIONS] PATTERN [FILE...]",
    category: "Text Processing",
    options: [
      { flag: "-i", description: "Ignore case distinctions" },
      { flag: "-r", description: "Search recursively in directories" },
      { flag: "-n", description: "Print line numbers" },
      { flag: "-v", description: "Invert match (show non-matching lines)" },
      { flag: "-c", description: "Count matching lines" },
      { flag: "-E", description: "Use extended regular expressions" },
    ],
    examples: [
      { command: "grep 'error' /var/log/syslog", description: "Search for 'error' in syslog" },
      { command: "grep -ri 'TODO' ./src", description: "Recursively search for TODO (case-insensitive)" },
      { command: "grep -n 'pattern' file.txt", description: "Show line numbers with matches" },
    ],
  },
  cat: {
    name: "cat",
    description: "Concatenate files and print on standard output.",
    syntax: "cat [OPTION]... [FILE]...",
    category: "File Management",
    options: [
      { flag: "-n", description: "Number all output lines" },
      { flag: "-b", description: "Number non-empty lines only" },
      { flag: "-s", description: "Squeeze multiple blank lines" },
      { flag: "-E", description: "Display $ at end of each line" },
    ],
    examples: [
      { command: "cat file.txt", description: "Display contents of file.txt" },
      { command: "cat file1.txt file2.txt", description: "Concatenate two files" },
      { command: "cat -n file.txt", description: "Display with line numbers" },
    ],
  },
  chmod: {
    name: "chmod",
    description: "Change file mode bits (permissions).",
    syntax: "chmod [OPTION]... MODE[,MODE]... FILE...",
    category: "Permissions",
    options: [
      { flag: "-R", description: "Change files and directories recursively" },
      { flag: "-v", description: "Verbose, output for every file processed" },
      { flag: "-c", description: "Report only when a change is made" },
    ],
    examples: [
      { command: "chmod 755 script.sh", description: "Set rwxr-xr-x permissions" },
      { command: "chmod +x script.sh", description: "Add execute permission" },
      { command: "chmod -R 644 /var/www", description: "Recursively set permissions" },
    ],
  },
  chown: {
    name: "chown",
    description: "Change file owner and group.",
    syntax: "chown [OPTION]... [OWNER][:[GROUP]] FILE...",
    category: "Permissions",
    options: [
      { flag: "-R", description: "Operate on files and directories recursively" },
      { flag: "-v", description: "Verbose output" },
      { flag: "--reference", description: "Use RFILE's owner and group" },
    ],
    examples: [
      { command: "chown root:root file.txt", description: "Change owner and group to root" },
      { command: "chown -R www-data /var/www", description: "Recursively change owner" },
      { command: "chown :admin file.txt", description: "Change only the group" },
    ],
  },
  curl: {
    name: "curl",
    description: "Transfer data from or to a server using various protocols.",
    syntax: "curl [OPTIONS] [URL]",
    category: "Networking",
    options: [
      { flag: "-o", description: "Write output to file" },
      { flag: "-O", description: "Write output to file named as remote file" },
      { flag: "-L", description: "Follow redirects" },
      { flag: "-I", description: "Fetch headers only" },
      { flag: "-X", description: "Specify request method (GET, POST, etc.)" },
      { flag: "-d", description: "Send data in POST request" },
      { flag: "-H", description: "Add custom header" },
    ],
    examples: [
      { command: "curl https://example.com", description: "Fetch a webpage" },
      { command: "curl -O https://example.com/file.zip", description: "Download file" },
      { command: "curl -X POST -d 'data' https://api.example.com", description: "POST request with data" },
    ],
  },
  tar: {
    name: "tar",
    description: "Archive utility for creating and extracting tar archives.",
    syntax: "tar [OPTIONS] [FILE]...",
    category: "Archiving",
    options: [
      { flag: "-c", description: "Create a new archive" },
      { flag: "-x", description: "Extract files from archive" },
      { flag: "-v", description: "Verbose output" },
      { flag: "-f", description: "Specify archive filename" },
      { flag: "-z", description: "Filter through gzip" },
      { flag: "-j", description: "Filter through bzip2" },
    ],
    examples: [
      { command: "tar -cvzf archive.tar.gz /path/to/dir", description: "Create gzipped archive" },
      { command: "tar -xvzf archive.tar.gz", description: "Extract gzipped archive" },
      { command: "tar -tvf archive.tar", description: "List contents of archive" },
    ],
  },
  find: {
    name: "find",
    description: "Search for files in a directory hierarchy.",
    syntax: "find [PATH] [OPTIONS] [EXPRESSION]",
    category: "File Management",
    options: [
      { flag: "-name", description: "Search by filename pattern" },
      { flag: "-type", description: "Search by type (f=file, d=directory)" },
      { flag: "-size", description: "Search by file size" },
      { flag: "-mtime", description: "Search by modification time" },
      { flag: "-exec", description: "Execute command on found files" },
      { flag: "-delete", description: "Delete found files" },
    ],
    examples: [
      { command: "find /var -name '*.log'", description: "Find all .log files in /var" },
      { command: "find . -type f -size +100M", description: "Find files larger than 100MB" },
      { command: "find . -mtime -7", description: "Find files modified in last 7 days" },
    ],
  },
  ssh: {
    name: "ssh",
    description: "OpenSSH remote login client.",
    syntax: "ssh [OPTIONS] [user@]hostname [command]",
    category: "Networking",
    options: [
      { flag: "-p", description: "Port to connect to on remote host" },
      { flag: "-i", description: "Identity file (private key)" },
      { flag: "-v", description: "Verbose mode for debugging" },
      { flag: "-L", description: "Local port forwarding" },
      { flag: "-R", description: "Remote port forwarding" },
    ],
    examples: [
      { command: "ssh user@hostname", description: "Connect to remote host" },
      { command: "ssh -p 2222 user@host", description: "Connect on custom port" },
      { command: "ssh -i ~/.ssh/key.pem user@host", description: "Connect with private key" },
    ],
  },
  systemctl: {
    name: "systemctl",
    description: "Control the systemd system and service manager.",
    syntax: "systemctl [OPTIONS] COMMAND [UNIT]",
    category: "System",
    options: [
      { flag: "start", description: "Start a service" },
      { flag: "stop", description: "Stop a service" },
      { flag: "restart", description: "Restart a service" },
      { flag: "status", description: "Show service status" },
      { flag: "enable", description: "Enable service at boot" },
      { flag: "disable", description: "Disable service at boot" },
    ],
    examples: [
      { command: "systemctl status nginx", description: "Check nginx status" },
      { command: "systemctl restart apache2", description: "Restart Apache" },
      { command: "systemctl enable docker", description: "Enable Docker at boot" },
    ],
  },
  ps: {
    name: "ps",
    description: "Report a snapshot of current processes.",
    syntax: "ps [OPTIONS]",
    category: "Process Management",
    options: [
      { flag: "aux", description: "Show all processes for all users" },
      { flag: "-e", description: "Select all processes" },
      { flag: "-f", description: "Full format listing" },
      { flag: "--forest", description: "Display process tree" },
    ],
    examples: [
      { command: "ps aux", description: "List all running processes" },
      { command: "ps aux | grep nginx", description: "Find nginx processes" },
      { command: "ps -ef --forest", description: "Show process tree" },
    ],
  },
  kill: {
    name: "kill",
    description: "Send a signal to a process.",
    syntax: "kill [OPTIONS] PID...",
    category: "Process Management",
    options: [
      { flag: "-9", description: "SIGKILL - Force kill" },
      { flag: "-15", description: "SIGTERM - Graceful termination (default)" },
      { flag: "-l", description: "List signal names" },
    ],
    examples: [
      { command: "kill 1234", description: "Send SIGTERM to process 1234" },
      { command: "kill -9 1234", description: "Force kill process 1234" },
      { command: "killall nginx", description: "Kill all nginx processes" },
    ],
  },
  df: {
    name: "df",
    description: "Report file system disk space usage.",
    syntax: "df [OPTION]... [FILE]...",
    category: "Disk Management",
    options: [
      { flag: "-h", description: "Human-readable sizes" },
      { flag: "-T", description: "Show filesystem type" },
      { flag: "-i", description: "Show inode information" },
    ],
    examples: [
      { command: "df -h", description: "Show disk usage in human-readable format" },
      { command: "df -hT", description: "Show disk usage with filesystem types" },
      { command: "df -i", description: "Show inode usage" },
    ],
  },
  du: {
    name: "du",
    description: "Estimate file space usage.",
    syntax: "du [OPTION]... [FILE]...",
    category: "Disk Management",
    options: [
      { flag: "-h", description: "Human-readable sizes" },
      { flag: "-s", description: "Display only total for each argument" },
      { flag: "-d", description: "Max depth of directory traversal" },
      { flag: "--max-depth", description: "Print total for directory depth" },
    ],
    examples: [
      { command: "du -sh /var", description: "Total size of /var directory" },
      { command: "du -h --max-depth=1", description: "Size of each subdirectory" },
      { command: "du -sh * | sort -h", description: "Sort directories by size" },
    ],
  },
  awk: {
    name: "awk",
    description: "Pattern scanning and text processing language.",
    syntax: "awk [OPTIONS] 'PROGRAM' [FILE...]",
    category: "Text Processing",
    options: [
      { flag: "-F", description: "Set field separator" },
      { flag: "-v", description: "Assign variable before execution" },
      { flag: "-f", description: "Read program from file" },
    ],
    examples: [
      { command: "awk '{print $1}' file.txt", description: "Print first column" },
      { command: "awk -F: '{print $1}' /etc/passwd", description: "Print usernames from passwd" },
      { command: "awk '/pattern/ {print}' file.txt", description: "Print lines matching pattern" },
    ],
  },
  sed: {
    name: "sed",
    description: "Stream editor for filtering and transforming text.",
    syntax: "sed [OPTIONS] 'SCRIPT' [FILE...]",
    category: "Text Processing",
    options: [
      { flag: "-i", description: "Edit files in place" },
      { flag: "-n", description: "Suppress automatic printing" },
      { flag: "-e", description: "Add script to commands" },
    ],
    examples: [
      { command: "sed 's/old/new/g' file.txt", description: "Replace all occurrences of 'old' with 'new'" },
      { command: "sed -i 's/old/new/g' file.txt", description: "Replace in place" },
      { command: "sed -n '5,10p' file.txt", description: "Print lines 5-10" },
    ],
  },
  netstat: {
    name: "netstat",
    description: "Print network connections, routing tables, and interface statistics.",
    syntax: "netstat [OPTIONS]",
    category: "Networking",
    options: [
      { flag: "-t", description: "Show TCP connections" },
      { flag: "-u", description: "Show UDP connections" },
      { flag: "-l", description: "Show listening sockets" },
      { flag: "-n", description: "Show numerical addresses" },
      { flag: "-p", description: "Show PID/program name" },
    ],
    examples: [
      { command: "netstat -tulnp", description: "Show all listening ports with PIDs" },
      { command: "netstat -an | grep ESTABLISHED", description: "Show established connections" },
      { command: "netstat -r", description: "Show routing table" },
    ],
  },
  ip: {
    name: "ip",
    description: "Show and manipulate routing, devices, policy routing and tunnels.",
    syntax: "ip [OPTIONS] OBJECT { COMMAND }",
    category: "Networking",
    options: [
      { flag: "addr", description: "Show/manipulate IP addresses" },
      { flag: "link", description: "Show/manipulate network devices" },
      { flag: "route", description: "Show/manipulate routing table" },
      { flag: "-c", description: "Use color output" },
    ],
    examples: [
      { command: "ip addr show", description: "Show all IP addresses" },
      { command: "ip route show", description: "Show routing table" },
      { command: "ip link set eth0 up", description: "Bring interface up" },
    ],
  },
  top: {
    name: "top",
    description: "Display Linux processes in real-time.",
    syntax: "top [OPTIONS]",
    category: "Process Management",
    options: [
      { flag: "-d", description: "Delay between updates (seconds)" },
      { flag: "-u", description: "Show only processes for specified user" },
      { flag: "-p", description: "Monitor specific PIDs" },
      { flag: "-b", description: "Batch mode (useful for logging)" },
    ],
    examples: [
      { command: "top", description: "Start interactive process viewer" },
      { command: "top -u www-data", description: "Show only www-data processes" },
      { command: "top -bn1", description: "Run once in batch mode" },
    ],
  },
};

const CommandLibrary = () => {
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedCommand, setSelectedCommand] = useState<CommandInfo | null>(null);
  const [copiedCommand, setCopiedCommand] = useState<string | null>(null);

  const handleSearch = () => {
    const query = searchQuery.toLowerCase().trim();
    if (commandDatabase[query]) {
      setSelectedCommand(commandDatabase[query]);
    } else {
      toast.error(`Command "${searchQuery}" not found in library`);
      setSelectedCommand(null);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      handleSearch();
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCommand(text);
    toast.success("Copied to clipboard!");
    setTimeout(() => setCopiedCommand(null), 2000);
  };

  const allCommands = Object.keys(commandDatabase).sort();

  return (
    <Sidebar>
      <div className="min-h-screen bg-background">
        {/* Header */}
        <header className="border-b border-border bg-card">
          <div className="container mx-auto px-4 py-6">
            <div className="flex items-center gap-3">
              <Terminal className="w-8 h-8 text-primary" />
              <div>
                <h1 className="text-2xl font-bold text-foreground">Linux Command Library</h1>
                <p className="text-sm text-muted-foreground">
                  Summon the Magic of Linux! Type a Command and Uncover Its Secrets
                </p>
              </div>
            </div>
          </div>
        </header>

        {/* Main Content */}
        <main className="container mx-auto px-4 py-8">

        {/* Search Card */}
        <Card className="p-6 mb-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <Terminal className="w-6 h-6 text-primary" />
              <div>
                <h2 className="text-lg font-semibold text-foreground">Linux Command Information Library</h2>
                <p className="text-sm text-muted-foreground">
                  Summon the Magic of Linux! Type a Command and Uncover Its Secrets! - search commands, syntax, and usage
                </p>
              </div>
            </div>
            <a
              href="https://man7.org/linux/man-pages/"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 text-primary hover:underline text-sm"
            >
              <BookOpen className="w-4 h-4" />
              Documentation
              <ExternalLink className="w-3 h-3" />
            </a>
          </div>

          <div className="flex gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
              <Input
                type="text"
                placeholder="Enter command (e.g., ls, git commit, curl)"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={handleKeyDown}
                className="pl-10"
              />
            </div>
            <Button onClick={handleSearch} className="gap-2">
              <Terminal className="w-4 h-4" />
              Search
            </Button>
          </div>
        </Card>

        {/* Command Result */}
        {selectedCommand && (
          <Card className="p-6 mb-6">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-3">
                <div className="bg-primary/10 p-2 rounded-lg">
                  <Terminal className="w-5 h-5 text-primary" />
                </div>
                <div>
                  <h3 className="text-xl font-bold text-foreground font-mono">{selectedCommand.name}</h3>
                  <span className="text-xs bg-secondary text-secondary-foreground px-2 py-0.5 rounded">
                    {selectedCommand.category}
                  </span>
                </div>
              </div>
            </div>

            <p className="text-muted-foreground mb-4">{selectedCommand.description}</p>

            {/* Syntax */}
            <div className="mb-6">
              <h4 className="text-sm font-semibold text-foreground mb-2">Syntax</h4>
              <div className="bg-muted rounded-lg p-3 font-mono text-sm flex items-center justify-between">
                <code className="text-foreground">{selectedCommand.syntax}</code>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => copyToClipboard(selectedCommand.syntax)}
                  className="h-8 w-8 p-0"
                >
                  {copiedCommand === selectedCommand.syntax ? (
                    <Check className="w-4 h-4 text-green-500" />
                  ) : (
                    <Copy className="w-4 h-4" />
                  )}
                </Button>
              </div>
            </div>

            {/* Options */}
            <div className="mb-6">
              <h4 className="text-sm font-semibold text-foreground mb-2">Common Options</h4>
              <div className="bg-muted rounded-lg overflow-hidden">
                <table className="w-full text-sm">
                  <tbody>
                    {selectedCommand.options.map((option, index) => (
                      <tr key={index} className={index % 2 === 0 ? "bg-muted" : "bg-muted/50"}>
                        <td className="px-3 py-2 font-mono text-primary font-medium w-24">{option.flag}</td>
                        <td className="px-3 py-2 text-muted-foreground">{option.description}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Examples */}
            <div>
              <h4 className="text-sm font-semibold text-foreground mb-2">Examples</h4>
              <div className="space-y-2">
                {selectedCommand.examples.map((example, index) => (
                  <div key={index} className="bg-muted rounded-lg p-3">
                    <div className="flex items-center justify-between mb-1">
                      <code className="font-mono text-sm text-foreground">{example.command}</code>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => copyToClipboard(example.command)}
                        className="h-8 w-8 p-0"
                      >
                        {copiedCommand === example.command ? (
                          <Check className="w-4 h-4 text-green-500" />
                        ) : (
                          <Copy className="w-4 h-4" />
                        )}
                      </Button>
                    </div>
                    <p className="text-xs text-muted-foreground">{example.description}</p>
                  </div>
                ))}
              </div>
            </div>
          </Card>
        )}

        {/* Available Commands */}
        <Card className="p-4 bg-accent/10 border-accent/20">
          <div className="flex gap-3">
            <Info className="w-5 h-5 text-accent shrink-0 mt-0.5" />
            <div>
              <p className="font-medium text-foreground mb-2">Available Commands</p>
              <div className="flex flex-wrap gap-2">
                {allCommands.map((cmd) => (
                  <button
                    key={cmd}
                    onClick={() => {
                      setSearchQuery(cmd);
                      setSelectedCommand(commandDatabase[cmd]);
                    }}
                    className="px-2 py-1 bg-secondary text-secondary-foreground rounded text-xs font-mono hover:bg-secondary/80 transition-colors"
                  >
                    {cmd}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </Card>
      </main>
    </div>
  </Sidebar>
  );
};

export default CommandLibrary;
