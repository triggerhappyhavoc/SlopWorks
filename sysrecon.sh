#!/usr/bin/env bash
#
# sysrecon.sh - Local host enumeration for AUTHORIZED security assessments.
#
# Read-only reconnaissance of the host it runs on, in the LinPEAS / LinEnum
# family. It only READS system state (files, package DBs, process/socket/
# service/cron listings) and reports what it finds; it never writes to,
# modifies, downloads, or exploits anything. Use only on systems you are
# authorized to assess (pentest engagements, CTFs, your own machines).
#
# Supports Debian/Ubuntu and RedHat-family (RHEL/CentOS/Fedora/Rocky/Alma).
# The GTFOBins match list and the kernel-CVE list are STATIC SNAPSHOTS baked
# into this file (snapshot date 2026-11-05) - no network calls are made.
#
# Usage:
#   ./sysrecon.sh            # full run (includes slow full-'/' find scans)
#   ./sysrecon.sh --fast     # skip the slow full-'/' find scans (SUID/SGID/sticky)
#   ./sysrecon.sh --full     # remove the output caps on find/daemon scans
#   ./sysrecon.sh | tee out  # keep a copy; colour auto-disables when piped
#   NO_COLOR=1 ./sysrecon.sh # force plain output
#
# Many checks read more when run as root (e.g. /etc/shadow, other users'
# crontabs, /proc/<pid>/environ). As a normal user those are reported as
# limited rather than failing. Exits 0 always; missing tools are skipped.

# No `set -e`: on a stripped-down target half the tools may be absent and we
# want every check to run regardless of individual failures.
set -u
export LC_ALL=C

# ---------------------------------------------------------------------------
# Presentation helpers
# ---------------------------------------------------------------------------
if [[ -t 1 && -z ${NO_COLOR:-} ]]; then
    C_HDR=$'\033[1;36m'; C_SUB=$'\033[1;33m'; C_HIT=$'\033[1;31m'
    C_OK=$'\033[0;32m';  C_DIM=$'\033[0;90m';  C_RST=$'\033[0m'
else
    C_HDR= C_SUB= C_HIT= C_OK= C_DIM= C_RST=
fi
section() { printf '\n%s======[ %s ]======%s\n' "$C_HDR" "$*" "$C_RST"; }
sub()     { printf '%s--- %s%s\n' "$C_SUB" "$*" "$C_RST"; }
hit()     { printf '%s  [!] %s%s\n' "$C_HIT" "$*" "$C_RST"; }   # noteworthy / possibly abusable
ok()      { printf '%s  [+] %s%s\n' "$C_OK" "$*" "$C_RST"; }
info()    { printf '      %s\n' "$*"; }
dim()     { printf '%s      %s%s\n' "$C_DIM" "$*" "$C_RST"; }
have()    { command -v "$1" >/dev/null 2>&1; }
missing() { dim "($1 not installed / not in PATH, skipping)"; }
indent()  { sed 's/^/      /'; }

# ---------------------------------------------------------------------------
# Options / scan mode
# ---------------------------------------------------------------------------
FAST=0; FULL=0
FIND_CAP=200          # max lines kept from each capped scan in normal mode
for arg in "$@"; do
    case $arg in
        --fast) FAST=1 ;;
        --full) FULL=1 ;;
        -h|--help) sed -n '3,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) printf 'sysrecon.sh: unknown option %q (try --help)\n' "$arg" >&2; exit 2 ;;
    esac
done
(( FAST && FULL )) && { printf 'sysrecon.sh: --fast and --full are mutually exclusive\n' >&2; exit 2; }
cap() { if (( FULL )); then cat; else awk -v n="$FIND_CAP" 'NR<=n; NR==n+1{print "      ... (capped at "n"; re-run with --full for all)"}'; fi; }
skipped_fullscan() { dim "skipped in --fast mode (full-filesystem scan); re-run without --fast to include"; }

# ---------------------------------------------------------------------------
# Environment facts reused throughout
# ---------------------------------------------------------------------------
ME=$(id -un 2>/dev/null); MY_UID=$(id -u 2>/dev/null)
MY_GROUPS=$(id -nG 2>/dev/null)
AM_ROOT=0; [[ ${MY_UID:-x} == 0 ]] && AM_ROOT=1
# $HOME may be unset in a stripped shell (sudo/cron/limited exploit context);
# under `set -u` a bare $HOME would then abort the script. Resolve a safe value.
MY_HOME=${HOME:-}
[[ -z $MY_HOME ]] && MY_HOME=$(getent passwd "${ME:-}" 2>/dev/null | cut -d: -f6)
OS_ID=""; OS_LIKE=""
if [[ -r /etc/os-release ]]; then
    OS_ID=$(.  /etc/os-release 2>/dev/null; echo "${ID:-}")
    OS_LIKE=$(. /etc/os-release 2>/dev/null; echo "${ID_LIKE:-}")
fi
is_debian() { [[ $OS_ID == debian || $OS_ID == ubuntu || $OS_LIKE == *debian* ]] || have dpkg-query; }
is_redhat() { [[ $OS_ID == rhel || $OS_ID == centos || $OS_ID == fedora || $OS_ID == rocky || $OS_ID == almalinux || $OS_ID == redhat || $OS_LIKE == *rhel* || $OS_LIKE == *fedora* ]] || have rpm; }

# Groups that confer (near) root. Membership is a red flag.
PRIV_GROUPS='root sudo wheel admin adm docker lxd disk shadow'
# Pattern that looks sensitive in history / env / config files.
SENSITIVE_RE='pass(wd|word)?=|secret|token|api[_-]?key|private[_-]?key|credential|BEGIN [A-Z ]*PRIVATE KEY|aws_(secret|access)|-p[^ ]+|--password'

# GTFOBins STATIC SNAPSHOT (2026-11-05): binaries with a known sudo/SUID
# escalation technique. Union of the sudo and suid function lists; a basename
# match is flagged as "abusable per GTFOBins" - verify the exact technique.
GTFO='aa-exec|ab|agetty|alpine|ansible-playbook|aoss|apt|apt-get|ar|aria2c|arj|arp|as|ascii-xfr|ash|aspell|atobm|awk|aws|base32|base64|basenc|bash|batcat|bconsole|bpftrace|bridge|bundle|bundler|busctl|busybox|byebug|bzip2|c89|c99|cabal|capsh|cat|cdist|certbot|check_by_ssh|check_cmd|check_log|check_memory|check_raid|check_ssl_cert|check_statusfile|chmod|choom|chown|chroot|clamscan|cmp|cobc|column|comm|composer|cowsay|cowthink|cp|cpan|cpio|cpulimit|crash|crontab|csh|csplit|csvtool|cupsfilter|curl|cut|dash|date|dc|dd|debugfs|dialog|diff|dig|distcc|dmesg|dmidecode|dmsetup|dnf|docker|dosbox|dotnet|dpkg|dstat|dvips|easy_install|ed|efax|elvish|emacs|env|eqn|espeak|ex|exiftool|expand|expect|facter|file|find|finger|fish|flock|fmt|fold|fping|ftp|gawk|gcc|gcore|gdb|gem|genie|genisoimage|ghc|ghci|gimp|ginsh|git|grc|grep|gtester|gzip|hd|head|hexdump|highlight|hping3|iconv|iftop|install|ionice|ip|irb|ispell|jjs|joe|join|journalctl|jq|jrunscript|jtag|julia|knife|ksh|ksshell|kubectl|latex|latexmk|ld.so|ldconfig|less|lftp|links|ln|loginctl|logsave|look|lp|ltrace|lua|lualatex|luatex|lwp-download|lwp-request|mail|make|man|mawk|minicom|more|mosquitto|mount|msfconsole|msgattrib|msgcat|msgconv|msgfilter|msgmerge|msguniq|mtr|multitime|mv|mysql|nano|nasm|nawk|nc|ncdu|ncftp|neofetch|nft|nice|nl|nmap|node|nohup|npm|nroff|nsenter|octave|od|openssl|openvpn|openvt|opkg|pandoc|paste|pdb|pdflatex|pdftex|perf|perl|pexec|pg|php|pic|pico|pidstat|pip|pkexec|pkg|posh|pr|pry|psql|ptx|puppet|python|python2|python3|rake|rc|readelf|red|redcarpet|redis|restic|rev|rlogin|rlwrap|rpm|rpmdb|rpmquery|rpmverify|rsync|rtorrent|ruby|run-mailcap|run-parts|runscript|rview|rvim|sash|scanmem|scp|screen|script|scrot|sed|service|setarch|setfacl|setlock|sftp|sg|shuf|slsh|smbclient|snap|socat|soelim|softlimit|sort|split|sqlite3|sqlmap|ss|ssh|ssh-agent|ssh-keygen|ssh-keyscan|sshpass|start-stop-daemon|stdbuf|strace|strings|su|sudo|sysctl|systemctl|systemd-resolve|tac|tail|tar|task|taskset|tbl|tclsh|tcpdump|tdbtool|tee|telnet|terraform|tex|tftp|tic|time|timedatectl|timeout|tmate|tmux|top|torify|torsocks|troff|tshark|ul|unexpand|uniq|unshare|unsquashfs|unzip|update-alternatives|uudecode|uuencode|vagrant|valgrind|vi|view|vigr|vim|vimdiff|vipw|virsh|volatility|w3m|wall|watch|wc|wget|whiptail|whois|wireshark|wish|xargs|xdg-user-dir|xdotool|xelatex|xetex|xmodmap|xmore|xpad|xxd|xz|yarn|yash|yelp|yum|zathura|zip|zsh|zsoelim|zypper'

# ===========================================================================
# 1. USEFUL TOOLS PRESENT
# ===========================================================================
section "USEFUL TOOLS"
tool_report() {
    local name=$1; shift
    local bin ver vflag
    for bin in "$@"; do
        if have "$bin"; then
            ver=""
            # Best-effort version string. stdin from /dev/null so nothing can
            # block waiting for input; take only the first line; try the common
            # version flags (ssh/openssl use -V, most GNU tools use --version).
            for vflag in --version -V -version; do
                ver=$("$bin" "$vflag" </dev/null 2>&1 | head -n1)
                [[ $ver == *[0-9]* ]] && break || ver=""
            done
            ver=${ver:0:100}
            ok "$name: $(command -v "$bin")${ver:+  [$ver]}"
            return
        fi
    done
    missing "$name"
}
tool_report "Perl"        perl
tool_report "Python"      python3 python python2
tool_report "GCC/clang"   gcc cc clang
tool_report "make"        make
tool_report "Netcat/nc"   nc ncat netcat
tool_report "Nmap"        nmap
tool_report "SSH client"  ssh
tool_report "gcore"       gcore
have gdb && ok "gdb: $(command -v gdb)"
# These are handy for pulling tooling onto a box; note their presence.
for t in curl wget socat tcpdump; do have "$t" && info "also present: $t ($(command -v "$t"))"; done

# ===========================================================================
# 2. CURRENT USER: groups, sudo rights, /etc/sudoers entry
# ===========================================================================
section "CURRENT USER"
info "user:   ${ME:-?} (uid ${MY_UID:-?})"
info "id:     $(id 2>/dev/null)"
sub "group memberships"
info "${MY_GROUPS:-?}"
for g in $MY_GROUPS; do
    for pg in $PRIV_GROUPS; do
        [[ $g == "$pg" ]] && hit "member of privileged group '$g'"
    done
done
(( AM_ROOT )) && hit "running as root (uid 0)"

sub "sudo privileges (sudo -n -l, never prompts)"
if have sudo; then
    out=$(sudo -n -l 2>/dev/null)
    if [[ -n $out ]]; then
        printf '%s\n' "$out" | indent
        grep -qE 'NOPASSWD'          <<<"$out" && hit "a rule allows NOPASSWD (no password needed)"
        grep -qE '\(ALL(\s*:\s*ALL)?\)\s*ALL' <<<"$out" && hit "a rule grants ALL commands (full root)"
        grep -qiE 'SETENV|env_keep' <<<"$out" && hit "SETENV/env_keep present (LD_PRELOAD-style abuse possible)"
    else
        dim "no passwordless sudo, or a password is required (not probed)"
    fi
else
    missing sudo
fi

sub "my entries in sudoers config (if readable)"
sudoers_hit=0
for sf in /etc/sudoers /etc/sudoers.d/*; do
    [[ -r $sf ]] || continue
    # Match the username directly, or any of my groups as %group.
    grp_alt=${MY_GROUPS// /|}
    pat="^[[:space:]]*(${ME}|%(${grp_alt}))[[:space:]]"
    matches=$(grep -nE "$pat" "$sf" 2>/dev/null)
    if [[ -n $matches ]]; then
        sudoers_hit=1
        printf '%s\n' "$matches" | sed "s|^|      ${sf}: |"
    fi
done
(( sudoers_hit )) && hit "current user (or one of its groups) is named in sudoers" \
    || dim "no readable sudoers entry references this user (file may be root-only)"

# ===========================================================================
# 3. ALL LOCAL USERS (flag non-standard + interactive + privilege-capable)
# ===========================================================================
section "LOCAL USERS"
# Human-account UID window, straight from the host's own policy.
UID_MIN=1000; UID_MAX=60000
if [[ -r /etc/login.defs ]]; then
    v=$(awk '$1=="UID_MIN"{print $2}' /etc/login.defs 2>/dev/null); [[ $v =~ ^[0-9]+$ ]] && UID_MIN=$v
    v=$(awk '$1=="UID_MAX"{print $2}' /etc/login.defs 2>/dev/null); [[ $v =~ ^[0-9]+$ ]] && UID_MAX=$v
fi
dim "human UID range per /etc/login.defs: ${UID_MIN}-${UID_MAX}"
valid_shells=$( [[ -r /etc/shells ]] && grep -v '^#' /etc/shells 2>/dev/null )
is_interactive_shell() {
    case $1 in */nologin|*/false|/bin/sync|/sbin/nologin|"") return 1 ;; esac
    [[ -z $valid_shells ]] && return 0        # no /etc/shells to check against: assume yes
    grep -qxF "$1" <<<"$valid_shells"
}
can_elevate() {                               # $1 = username
    local u=$1 grps
    grps=$(id -nG "$u" 2>/dev/null)
    for g in $grps; do
        for pg in $PRIV_GROUPS; do [[ $g == "$pg" ]] && return 0; done
    done
    grep -rhsE "^[[:space:]]*${u}[[:space:]]" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -q . && return 0
    return 1
}
if [[ -r /etc/passwd ]]; then
    while IFS=: read -r name _ uid gid _ home shell; do
        [[ $uid =~ ^[0-9]+$ ]] || continue
        tags=""; flag=0
        if (( uid == 0 )); then tags+=" UID0"; (( uid==0 )) && [[ $name != root ]] && flag=1
        elif (( uid >= UID_MIN && uid <= UID_MAX )); then tags+=" regular"; flag=1
        else tags+=" system"; fi
        if is_interactive_shell "$shell"; then tags+=" interactive-shell"; else flag=0; fi
        if can_elevate "$name"; then tags+=" PRIV-CAPABLE"; flag=1; fi
        line="$name  uid=$uid gid=$gid  shell=$shell  home=$home  [${tags# }]"
        if (( flag )) && is_interactive_shell "$shell"; then hit "$line"
        elif [[ $tags == *PRIV-CAPABLE* ]]; then hit "$line"
        else info "$line"; fi
    done < /etc/passwd
else
    hit "/etc/passwd not readable (unusual)"
fi
dim "highlighted = non-standard/human account with a login shell, or able to elevate (sudoers/privileged group)"

# ===========================================================================
# 4. SENSITIVE FILE PERMISSIONS (passwd/shadow/sudoers + nearby backups)
# ===========================================================================
section "SENSITIVE FILE PERMISSIONS"
check_perm() {
    local f=$1 expect=$2 perm owner
    if [[ -e $f ]]; then
        perm=$(stat -c '%a'    "$f" 2>/dev/null)
        owner=$(stat -c '%U:%G' "$f" 2>/dev/null)
        printf '      %-24s mode=%-5s owner=%s' "$f" "$perm" "$owner"
        [[ -r $f ]] && printf '  %s[readable by me]%s' "$C_HIT" "$C_RST"
        [[ -w $f ]] && printf '  %s[WRITABLE by me]%s' "$C_HIT" "$C_RST"
        printf '\n'
        [[ -n $expect && -n $perm && $perm != "$expect" ]] && hit "$f mode $perm differs from the usual $expect"
    else
        dim "$f does not exist"
    fi
}
sub "passwd / shadow family (incl. nearby backups)"
for f in /etc/passwd /etc/passwd- /etc/shadow /etc/shadow- /etc/shadow.bak \
         /etc/shadow.old /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/group /etc/group-; do
    case $f in
        /etc/shadow*|/etc/gshadow*) exp=640 ;;
        *) exp=644 ;;
    esac
    [[ -e $f ]] && check_perm "$f" "$exp"
done
[[ -w /etc/passwd ]] && hit "/etc/passwd is writable -> can add a UID 0 account"
[[ -r /etc/shadow ]] && hit "/etc/shadow is readable -> offline hash cracking possible"
sub "sudoers family"
check_perm /etc/sudoers 440
if [[ -d /etc/sudoers.d ]]; then
    for f in /etc/sudoers.d/*; do [[ -e $f ]] && check_perm "$f" 440; done
fi
[[ -e /etc/sudo.conf ]] && check_perm /etc/sudo.conf 644

# ===========================================================================
# 5. SUDO-ABUSABLE BINARIES (GTFOBins) from sudo -l
# ===========================================================================
section "SUDO-ABUSABLE BINARIES (GTFOBins snapshot)"
if have sudo; then
    sl=$(sudo -n -l 2>/dev/null)
    if [[ -n $sl ]]; then
        # Pull the command paths allowed after the (runas) spec, one per line.
        printf '%s\n' "$sl" \
            | sed -n 's/.*)\s*\(NOPASSWD:\s*\)\?//p' \
            | tr ',' '\n' | sed 's/^\s*//; s/\s.*$//' | grep -E '^/' | sort -u \
            | while read -r cmd; do
                base=${cmd##*/}
                if [[ $base =~ ^($GTFO)$ ]]; then
                    hit "sudo allows $cmd -> '$base' is in GTFOBins (shell/file read-write as target user)"
                else
                    info "sudo allows $cmd"
                fi
              done
        grep -qE '\(ALL(\s*:\s*ALL)?\)\s*ALL' <<<"$sl" && hit "sudo grants ALL -> any binary is abusable"
    else
        dim "sudo -l returned nothing without a password; cannot enumerate allowed commands"
    fi
else
    missing sudo
fi

# ===========================================================================
# 6. SUID / SGID / STICKY-BIT BINARIES (highlight GTFO-abusable)
# ===========================================================================
section "SUID / SGID / STICKY-BIT FILES"
if (( FAST )); then
    skipped_fullscan
else
    PRUNE='( -path /proc -o -path /sys -o -path /dev -o -path /run ) -prune -o'
    sub "SUID binaries (-perm -4000)"
    find / $PRUNE -perm -4000 -type f -print 2>/dev/null | cap | while read -r f; do
        [[ $f == *'(capped at'* ]] && { dim "$f"; continue; }
        base=${f##*/}
        if [[ $base =~ ^($GTFO)$ ]]; then hit "SUID $f  (abusable per GTFOBins)"; else info "SUID $f"; fi
    done
    sub "SGID binaries (-perm -2000)"
    find / $PRUNE -perm -2000 -type f -print 2>/dev/null | cap | while read -r f; do
        [[ $f == *'(capped at'* ]] && { dim "$f"; continue; }
        base=${f##*/}
        if [[ $base =~ ^($GTFO)$ ]]; then hit "SGID $f  (abusable per GTFOBins)"; else info "SGID $f"; fi
    done
    sub "sticky-bit FILES (-perm -1000; unusual on regular files)"
    out=$(find / $PRUNE -perm -1000 -type f -print 2>/dev/null | cap)
    [[ -n $out ]] && printf '%s\n' "$out" | indent || dim "none"
    dim "(sticky bit on DIRECTORIES like /tmp is normal and not listed here)"
fi

# ===========================================================================
# 7. CRON JOBS - current user
# ===========================================================================
section "CRON - CURRENT USER"
out=$(crontab -l 2>/dev/null)
[[ -n $out ]] && printf '%s\n' "$out" | indent || dim "no crontab for ${ME}, or not permitted"

# ===========================================================================
# 8. CRON JOBS - host-wide
# ===========================================================================
section "CRON - HOST-WIDE"
sub "/etc/crontab"
[[ -r /etc/crontab ]] && grep -vE '^\s*(#|$)' /etc/crontab 2>/dev/null | indent || dim "not readable"
for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    [[ -d $d ]] || continue
    sub "$d"
    ls -la "$d" 2>/dev/null | indent
    [[ -w $d ]] && hit "$d is WRITABLE by me (drop-in cron escalation)"
    for e in "$d"/*; do [[ -e $e && -w $e ]] && hit "$e is WRITABLE by me"; done
done
sub "per-user spools"
if (( AM_ROOT )); then
    o=$(ls -la /var/spool/cron/crontabs /var/spool/cron 2>/dev/null)
    [[ -n $o ]] && printf '%s\n' "$o" | indent || dim "none"
else
    dim "need root to read other users' spools (/var/spool/cron)"
fi
if have systemctl; then
    sub "systemd timers (cron-equivalent)"
    o=$(systemctl list-timers --all --no-pager --no-legend 2>/dev/null)
    [[ -n $o ]] && printf '%s\n' "$o" | cap | indent || dim "none"
fi

# ===========================================================================
# 9. PATH
# ===========================================================================
section "PATH"
info "PATH=$PATH"
IFS=: read -ra parts <<<"$PATH"
for p in "${parts[@]}"; do
    case $p in
        /usr/local/sbin|/usr/local/bin|/usr/sbin|/usr/bin|/sbin|/bin|/usr/games|/usr/local/games) ;;
        "") hit "empty PATH element -> treated as current directory (.)" ;;
        .)  hit "'.' (current directory) is in PATH" ;;
        *)  flag=""
            [[ -w $p ]] && flag+=" (WRITABLE by me)"
            [[ ! -d $p ]] && flag+=" (does not exist)"
            [[ -n $flag ]] && hit "non-standard PATH entry: $p$flag" || info "non-standard PATH entry: $p" ;;
    esac
done

# ===========================================================================
# 10. NETWORK INTERFACES
# ===========================================================================
section "NETWORK INTERFACES"
if have ip; then
    o=$(ip -br addr 2>/dev/null); [[ -z $o ]] && o=$(ip addr 2>/dev/null)
    [[ -n $o ]] && printf '%s\n' "$o" | indent || dim "none"
elif have ifconfig; then
    ifconfig -a 2>/dev/null | indent
else
    missing "ip/ifconfig"
fi

# ===========================================================================
# 11. ROUTING TABLE
# ===========================================================================
section "ROUTING TABLE"
if have ip; then
    sub "IPv4"; ip route show 2>/dev/null | indent
    sub "IPv6"; ip -6 route show 2>/dev/null | indent
elif have netstat; then
    netstat -rn 2>/dev/null | indent
elif have route; then
    route -n 2>/dev/null | indent
else
    missing "ip/netstat/route"
fi

# ===========================================================================
# 12. SHELL HISTORY - full, current user (highlight sensitive)
# ===========================================================================
section "SHELL HISTORY (current user, full)"
found=0
for hf in "$MY_HOME/.bash_history" "$MY_HOME/.zsh_history" "$MY_HOME/.sh_history" \
          "$MY_HOME/.ash_history" "$MY_HOME/.local/share/fish/fish_history" \
          "$MY_HOME/.python_history" "$MY_HOME/.mysql_history" "$MY_HOME/.psql_history" \
          "$MY_HOME/.rediscli_history" "$MY_HOME/.lesshst"; do
    [[ -r $hf ]] || continue
    found=1
    sub "$hf"
    # Print the whole file, tagging lines that look credential-bearing.
    grep -nE '' "$hf" 2>/dev/null | while IFS= read -r line; do
        if grep -qiE "$SENSITIVE_RE" <<<"$line"; then
            printf '      %s[sensitive]%s %s\n' "$C_HIT" "$C_RST" "$line"
        else
            printf '      %s\n' "$line"
        fi
    done
done
(( found )) || dim "no readable history files for ${ME}"

# ===========================================================================
# 13. ACTIVE TCP / UDP CONNECTIONS
# ===========================================================================
section "ACTIVE TCP/UDP CONNECTIONS"
if have ss; then
    sub "all TCP sockets (ss -tnap)";  ss -tnap 2>/dev/null | cap | indent
    sub "all UDP sockets (ss -unap)";  ss -unap 2>/dev/null | cap | indent
elif have netstat; then
    sub "all connections (netstat -tunap)"; netstat -tunap 2>/dev/null | cap | indent
else
    missing "ss/netstat"
fi

# ===========================================================================
# 14. INSTALLED APPLICATIONS + VERSIONS
# ===========================================================================
section "INSTALLED PACKAGES & VERSIONS"
if is_debian && have dpkg-query; then
    sub "dpkg packages"
    dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null | sort | cap | indent
elif is_redhat && have rpm; then
    sub "rpm packages"
    rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' 2>/dev/null | sort | cap | indent
else
    dim "no dpkg/rpm database found; trying other sources"
fi
have snap    && { sub "snap";    snap list        2>/dev/null | cap | indent; }
have flatpak && { sub "flatpak"; flatpak list     2>/dev/null | cap | indent; }
have pip3    && { sub "pip3";    pip3 list         2>/dev/null | cap | indent; }

# ===========================================================================
# 15. RUNNING APPLICATIONS + PORT CORRELATION
# ===========================================================================
section "RUNNING APPS & LISTENING PORTS"
if have ss; then
    sub "listening sockets with owning process (ss -tulnp)"
    ss -tulnp 2>/dev/null | indent
    sub "port -> process map"
    ss -tulnp 2>/dev/null | awk 'NR>1 {
        proto=$1; local=$5; proc=$NF;
        n=split(local,a,":"); port=a[n];
        gsub(/users:\(\(|\)\).*$|"/,"",proc);
        printf "      %-4s %-20s %s\n", proto, local, proc
    }'
elif have netstat; then
    sub "listening sockets (netstat -tulnp)"
    netstat -tulnp 2>/dev/null | indent
else
    missing "ss/netstat"
fi
sub "process list (ps -eo)"
{ ps -eo pid,ppid,user,stat,pcpu,pmem,comm,args 2>/dev/null || ps aux 2>/dev/null; } | cap | indent

# ===========================================================================
# 16/17. CONTAINERS - Docker / LXC + running containers
# ===========================================================================
section "CONTAINERS (Docker / LXC)"
# Are we running INSIDE a container?
if [[ -f /.dockerenv ]] || grep -qaE '(docker|lxc|containerd|kubepods)' /proc/1/cgroup 2>/dev/null; then
    hit "this host appears to BE a container (/.dockerenv or container cgroup present)"
fi
if have docker; then
    hit "docker client present: $(command -v docker)"
    echo "$MY_GROUPS" | tr ' ' '\n' | grep -qx docker && hit "current user is in 'docker' group -> root-equivalent on host"
    sub "docker ps (needs daemon access)"
    o=$(docker ps 2>/dev/null)
    [[ -n $o ]] && printf '%s\n' "$o" | cap | indent || dim "cannot talk to docker daemon (permission or not running)"
else
    dim "docker client not installed"
fi
if [[ -S /var/run/docker.sock ]]; then
    hit "/var/run/docker.sock exists"
    [[ -w /var/run/docker.sock ]] && hit "docker.sock is WRITABLE by me -> container breakout to host root"
fi
for c in lxc lxd lxc-start lxc-attach; do have "$c" && hit "$c present: $(command -v "$c")"; done
echo "$MY_GROUPS" | tr ' ' '\n' | grep -qx lxd && hit "current user is in 'lxd' group -> root-equivalent on host"
if have lxc; then
    sub "lxc list"
    o=$(lxc list 2>/dev/null)
    [[ -n $o ]] && printf '%s\n' "$o" | cap | indent || dim "cannot list (permission or not running)"
fi

# ===========================================================================
# 18. OS VERSION
# ===========================================================================
section "OS VERSION"
if [[ -r /etc/os-release ]]; then
    info "$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
    info "ID=${OS_ID:-?}  ID_LIKE=${OS_LIKE:-?}"
fi
have lsb_release && lsb_release -a 2>/dev/null | indent
for f in /etc/redhat-release /etc/debian_version; do [[ -r $f ]] && info "$f: $(cat "$f" 2>/dev/null)"; done
info "hostname: $(hostname 2>/dev/null)"

# ===========================================================================
# 19. KERNEL VERSION + KNOWN ESCALATION CVEs (LES-style, static snapshot)
# ===========================================================================
section "KERNEL VERSION & KNOWN ESCALATION CVEs"
krel=$(uname -r 2>/dev/null); kver=${krel%%-*}
info "release: $krel"
info "version: $(uname -v 2>/dev/null)"
info "arch:    $(uname -m 2>/dev/null)"
IFS=. read -r kmaj kmin kpatch _ <<<"$kver"
kmaj=${kmaj:-0}; kmin=${kmin:-0}; kpatch=${kpatch:-0}
knum=$(( 10#$kmaj*1000000 + 10#$kmin*1000 + 10#$kpatch ))
ver_lt() { (( knum < $1*1000000 + $2*1000 + $3 )); }
ver_in() { local lo=$(( $1*1000000 + $2*1000 + $3 )) hi=$(( $4*1000000 + $5*1000 + $6 )); (( knum >= lo && knum < hi )); }
is_ubuntu() { [[ $OS_ID == ubuntu ]] || { [[ -r /etc/os-release ]] && grep -qi ubuntu /etc/os-release 2>/dev/null; }; }
CVE_ROWS=()
add_cve() { CVE_ROWS+=("$1	$2	$3	$4	$5	$6	$7"); }

ver_lt 4 8 3 && add_cve 3 " " CVE-2016-5195 "Dirty COW" "kernel<4.8.3" \
    "COW race; reliable on most pre-4.8.3 builds" "https://dirtycow.ninja/"
if ver_lt 3 19 1; then
    if is_ubuntu; then m="+"; else m=" "; fi
    add_cve 2 "$m" CVE-2015-1328 "overlayfs (Ubuntu)" "ubuntu,kernel<3.19.1" \
        "Ubuntu overlayfs permission bug" "https://www.exploit-db.com/exploits/37292"
fi
dirty_pipe() {
    ver_in 5 8 0 5 16 11 || return 1
    (( kmaj==5 && kmin==15 )) && ! ver_lt 5 15 25  && return 1
    (( kmaj==5 && kmin==10 )) && ! ver_lt 5 10 102 && return 1
    return 0
}
dirty_pipe && add_cve 3 " " CVE-2022-0847 "Dirty Pipe" "kernel=5.8-5.16.11" \
    "excludes 5.15.25+/5.10.102+ stable fixes; distro backports need manual check" "https://dirtypipe.cm4all.com/"
if have pkexec; then
    pkver=$(pkexec --version 2>/dev/null | awk '{print $NF}')
    add_cve 3 "+" CVE-2021-4034 "PwnKit (pkexec)" "pkexec=${pkver:-unknown}" \
        "exploitable unless polkit patched; near-universal pre-2022" "https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt"
fi
ver_in 5 10 0 6 4 0 && add_cve 1 " " CVE-2022-32250 "netfilter nf_tables LPE family" "kernel=5.10-6.3" \
    "several nf_tables CVEs in this span (also 2023-32233); match exact patch" "https://github.com/search?q=nf_tables+LPE"
if ver_in 5 4 0 6 2 0 && is_ubuntu; then
    add_cve 2 "+" CVE-2023-2640 "GameOver(lay) (Ubuntu)" "ubuntu,kernel=5.4-6.1" \
        "pairs with CVE-2023-32629; confirm Ubuntu kernel build" "https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629"
fi
if (( ${#CVE_ROWS[@]} == 0 )); then
    ok "no matches from the built-in candidate list"
else
    printf '%s\n' "${CVE_ROWS[@]}" | sort -t'	' -k1,1nr | while IFS=$'\t' read -r w mark cve name tags comment url; do
        [[ $w -ge 2 ]] && col=$C_HIT || col=$C_DIM
        printf '%s  [%s] [%s] %s%s\n' "$col" "$mark" "$cve" "$name" "$C_RST"
        printf '        Tags:     %s\n' "$tags"
        printf '        Comments: %s\n' "$comment"
        printf '        Details:  %s\n' "$url"
    done
fi
dim "Candidate list, NOT proof: [+] passed an environment check, [ ] matched version range only."
dim "Distros backport fixes without bumping the version string - confirm against the exact build."
dim "For a maintained database use standalone linux-exploit-suggester / -2."

# ===========================================================================
# 20. SYSTEM DAEMONS - sensitive information
#     (inspect unit files, systemctl environment, and /proc/<pid>/environ)
# ===========================================================================
section "SYSTEM DAEMONS - SENSITIVE INFORMATION"
if have systemctl; then
    sub "running services"
    SVCS=()
    mapfile -t SVCS < <(systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk '{print $1}')
    if (( ${#SVCS[@]} )); then printf '%s\n' "${SVCS[@]}" | sed '/^$/d' | cap | indent; else dim "none enumerated"; fi

    sub "secrets in service Environment= / unit files"
    scanned=0
    for svc in ${SVCS[@]+"${SVCS[@]}"}; do
        [[ -n $svc ]] || continue
        (( FULL )) || { (( scanned >= 60 )) && { dim "... (scanned 60 services; --full for all)"; break; }; }
        ((scanned++))
        # Environment= declared on the unit (visible without root).
        env=$(systemctl show "$svc" -p Environment --value 2>/dev/null)
        if [[ -n $env ]] && grep -qiE "$SENSITIVE_RE" <<<"$env"; then
            hit "$svc Environment= contains a sensitive-looking value:"
            grep -oiE "$SENSITIVE_RE[^ ]*" <<<"$env" | sed 's/^/        /'
        fi
        # EnvironmentFile= contents, if we can read them.
        for ef in $(systemctl show "$svc" -p EnvironmentFiles --value 2>/dev/null | grep -oE '/[^ ]+'); do
            [[ -r $ef ]] || continue
            if grep -qiE "$SENSITIVE_RE" "$ef" 2>/dev/null; then
                hit "$svc EnvironmentFile $ef contains sensitive-looking lines:"
                grep -inE "$SENSITIVE_RE" "$ef" 2>/dev/null | cap | sed 's/^/        /'
            fi
        done
        # The unit file itself.
        frag=$(systemctl show "$svc" -p FragmentPath --value 2>/dev/null)
        if [[ -r $frag ]] && grep -qiE "$SENSITIVE_RE" "$frag" 2>/dev/null; then
            hit "$svc unit file $frag contains sensitive-looking lines:"
            grep -inE "$SENSITIVE_RE" "$frag" 2>/dev/null | sed 's/^/        /'
        fi
    done
    (( scanned == 0 )) && dim "no running services enumerated"

    sub "process environments (/proc/<pid>/environ)"
    if (( AM_ROOT )) && (( ${#SVCS[@]} )); then
        found_env=0
        for pid in $(systemctl show "${SVCS[@]}" -p MainPID --value 2>/dev/null | grep -E '^[0-9]+$' | grep -v '^0$'); do
            [[ -r /proc/$pid/environ ]] || continue
            hits=$(tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | grep -iE "$SENSITIVE_RE")
            if [[ -n $hits ]]; then
                found_env=1
                comm=$(cat "/proc/$pid/comm" 2>/dev/null)
                hit "pid $pid ($comm) environment:"
                printf '%s\n' "$hits" | sed 's/^/        /'
            fi
        done
        (( found_env )) || dim "no sensitive-looking values in daemon environments"
    else
        dim "need root to read /proc/<pid>/environ of daemons (run as root for this check)"
    fi
else
    missing systemctl
    [[ -d /etc/init.d ]] && { sub "SysV init scripts"; ls /etc/init.d 2>/dev/null | indent; }
fi

printf '\n%sdone.%s\n' "$C_OK" "$C_RST"
