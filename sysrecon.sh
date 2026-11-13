#!/usr/bin/env bash
#
# sysrecon.sh - Local host enumeration for AUTHORIZED security assessments.
#
# Reconnaissance of the host it runs on, in the LinPEAS / LinEnum family. It
# READS system state (files, package DBs, process/socket/service/cron listings)
# and reports what it finds. The ONLY thing it writes is a single CSV inventory
# of installed packages, created in the current working directory (disable with
# --no-csv); it never modifies system state, downloads, or exploits anything.
# Use only on systems you are authorized to assess (pentest engagements, CTFs,
# your own machines).
#
# Supports Debian/Ubuntu and RedHat-family (RHEL/CentOS/Fedora/Rocky/Alma).
# The GTFOBins match list and the kernel-CVE list are STATIC SNAPSHOTS baked
# into this file (snapshot date 2026-11-05) - no network calls are made.
#
# Usage:
#   ./sysrecon.sh            # full run (includes slow full-'/' find scans)
#   ./sysrecon.sh --fast     # skip the slow full-'/' find scans (SUID/SGID/sticky)
#   ./sysrecon.sh --full     # remove the output caps on find/daemon scans
#   ./sysrecon.sh --no-csv   # do not write the installed-packages CSV (read-only)
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
# RFC-4180 CSV field: quote if it contains a comma, quote or newline; double any
# embedded quote. Used by the installed-package CSV export (section 14).
csv_escape() {
    local s=${1-}
    case $s in
        *[,\"$'\n'$'\r']*) printf '"%s"' "${s//\"/\"\"}" ;;
        *)                 printf '%s' "$s" ;;
    esac
}

# ---------------------------------------------------------------------------
# Options / scan mode
# ---------------------------------------------------------------------------
FAST=0; FULL=0; WRITE_CSV=1
FIND_CAP=200          # max lines kept from each capped scan in normal mode
for arg in "$@"; do
    case $arg in
        --fast) FAST=1 ;;
        --full) FULL=1 ;;
        --no-csv) WRITE_CSV=0 ;;
        -h|--help) sed -n '3,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
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

# Groups whose membership is a path to root on its own. sudo/wheel/admin
# (SUDO_GROUPS) are root-capable only because stock sudoers/polkit configs grant
# them, so where those configs are readable the LOCAL USERS check uses the actual
# rules instead of the group name.
PRIV_GROUPS_ROOT='sudo wheel admin docker lxd incus-admin libvirt libvirtd disk microk8s'
SUDO_GROUPS='sudo wheel admin'
# Groups granting privileged READ access - useful for escalation, not root alone.
PRIV_GROUPS_PARTIAL='root adm shadow systemd-journal'
# priv_group_note GROUP -> sets PG_NOTE to why the group matters; false if it doesn't.
priv_group_note() {
    case $1 in
        sudo|wheel|admin) PG_NOTE="conventional sudo group" ;;
        docker)           PG_NOTE="docker daemon access, root via a host mount" ;;
        lxd|incus-admin)  PG_NOTE="privileged container with the host / mounted" ;;
        libvirt|libvirtd) PG_NOTE="manages system VMs, can attach host disks" ;;
        disk)             PG_NOTE="raw block-device access (debugfs)" ;;
        microk8s)         PG_NOTE="cluster admin, privileged pods" ;;
        root)             PG_NOTE="GID 0, reads root-group files such as /etc/sudoers" ;;
        adm)              PG_NOTE="reads most of /var/log" ;;
        shadow)           PG_NOTE="reads /etc/shadow hashes" ;;
        systemd-journal)  PG_NOTE="reads the full systemd journal" ;;
        *) PG_NOTE=""; return 1 ;;
    esac
}
in_list() { case " $2 " in *" $1 "*) return 0 ;; esac; return 1; }   # in_list WORD "SPACE LIST"
# Pattern that looks sensitive in history / env / config files.
SENSITIVE_RE='pass(wd|word)?=|secret|token|api[_-]?key|private[_-]?key|credential|BEGIN [A-Z ]*PRIVATE KEY|aws_(secret|access)|-p[^ ]+|--password'

# GTFOBins STATIC SNAPSHOT (2026-11-05): binaries with a known sudo/SUID
# escalation technique. Union of the sudo and suid function lists; a basename
# match is flagged as "abusable per GTFOBins" - verify the exact technique.
GTFO='aa-exec|ab|agetty|alpine|ansible-playbook|aoss|apt|apt-get|ar|aria2c|arj|arp|as|ascii-xfr|ash|aspell|atobm|awk|aws|base32|base64|basenc|bash|batcat|bconsole|bpftrace|bridge|bundle|bundler|busctl|busybox|byebug|bzip2|c89|c99|cabal|capsh|cat|cdist|certbot|check_by_ssh|check_cmd|check_log|check_memory|check_raid|check_ssl_cert|check_statusfile|chmod|choom|chown|chroot|clamscan|cmp|cobc|column|comm|composer|cowsay|cowthink|cp|cpan|cpio|cpulimit|crash|crontab|csh|csplit|csvtool|cupsfilter|curl|cut|dash|date|dc|dd|debugfs|dialog|diff|dig|distcc|dmesg|dmidecode|dmsetup|dnf|docker|dosbox|dotnet|dpkg|dstat|dvips|easy_install|ed|efax|elvish|emacs|env|eqn|espeak|ex|exiftool|expand|expect|facter|file|find|finger|fish|flock|fmt|fold|fping|ftp|gawk|gcc|gcore|gdb|gem|genie|genisoimage|ghc|ghci|gimp|ginsh|git|grc|grep|gtester|gzip|hd|head|hexdump|highlight|hping3|iconv|iftop|install|ionice|ip|irb|ispell|jjs|joe|join|journalctl|jq|jrunscript|jtag|julia|knife|ksh|ksshell|kubectl|latex|latexmk|ld.so|ldconfig|less|lftp|links|ln|loginctl|logsave|look|lp|ltrace|lua|lualatex|luatex|lwp-download|lwp-request|mail|make|man|mawk|minicom|more|mosquitto|mount|msfconsole|msgattrib|msgcat|msgconv|msgfilter|msgmerge|msguniq|mtr|multitime|mv|mysql|nano|nasm|nawk|nc|ncdu|ncftp|neofetch|nft|nice|nl|nmap|node|nohup|npm|nroff|nsenter|octave|od|openssl|openvpn|openvt|opkg|pandoc|paste|pdb|pdflatex|pdftex|perf|perl|pexec|pg|php|pic|pico|pidstat|pip|pkexec|pkg|posh|pr|pry|psql|ptx|puppet|python|python2|python3|rake|rc|readelf|red|redcarpet|redis|restic|rev|rlogin|rlwrap|rpm|rpmdb|rpmquery|rpmverify|rsync|rtorrent|ruby|run-mailcap|run-parts|runscript|rview|rvim|sash|scanmem|scp|screen|script|scrot|sed|service|setarch|setfacl|setlock|sftp|sg|shuf|slsh|smbclient|snap|socat|soelim|softlimit|sort|split|sqlite3|sqlmap|ss|ssh|ssh-agent|ssh-keygen|ssh-keyscan|sshpass|start-stop-daemon|stdbuf|strace|strings|su|sudo|sysctl|systemctl|systemd-resolve|tac|tail|tar|task|taskset|tbl|tclsh|tcpdump|tdbtool|tee|telnet|terraform|tex|tftp|tic|time|timedatectl|timeout|tmate|tmux|top|torify|torsocks|troff|tshark|ul|unexpand|uniq|unshare|unsquashfs|unzip|update-alternatives|uudecode|uuencode|vagrant|valgrind|vi|view|vigr|vim|vimdiff|vipw|virsh|volatility|w3m|wall|watch|wc|wget|whiptail|whois|wireshark|wish|xargs|xdg-user-dir|xdotool|xelatex|xetex|xmodmap|xmore|xpad|xxd|xz|yarn|yash|yelp|yum|zathura|zip|zsh|zsoelim|zypper'

# Typical service for a port number (STATIC SNAPSHOT, mirrors IANA / nmap-services
# common assignments). This is only the conventional occupant of the port - a hint
# for reading the listening-port map, not a check of what is actually bound there.
# Call as `service_name <port> [tcp|udp]`; prints a short name, or nothing if unknown.
service_name() {
    local port=$1 proto=${2:-tcp}
    # A handful of ports carry a different well-known service on UDP than on TCP.
    case $proto:$port in
        udp:67|udp:68)  echo "dhcp";        return ;;
        udp:69)         echo "tftp";        return ;;
        udp:123)        echo "ntp";         return ;;
        udp:137)        echo "netbios-ns";  return ;;
        udp:138)        echo "netbios-dgm"; return ;;
        udp:161)        echo "snmp";        return ;;
        udp:162)        echo "snmptrap";    return ;;
        udp:500)        echo "isakmp/ike";  return ;;
        udp:514)        echo "syslog";      return ;;
        udp:520)        echo "rip";         return ;;
        udp:1194)       echo "openvpn";     return ;;
        udp:1900)       echo "ssdp/upnp";   return ;;
        udp:4500)       echo "ipsec-nat-t"; return ;;
        udp:5060)       echo "sip";         return ;;
        udp:5353)       echo "mdns";        return ;;
    esac
    case $port in
        7)       echo "echo" ;;
        19)      echo "chargen" ;;
        20)      echo "ftp-data" ;;
        21)      echo "ftp" ;;
        22)      echo "ssh" ;;
        23)      echo "telnet" ;;
        25)      echo "smtp" ;;
        37)      echo "time" ;;
        43)      echo "whois" ;;
        49)      echo "tacacs" ;;
        53)      echo "domain/dns" ;;
        67|68)   echo "dhcp" ;;
        69)      echo "tftp" ;;
        70)      echo "gopher" ;;
        79)      echo "finger" ;;
        80)      echo "http" ;;
        88)      echo "kerberos" ;;
        102)     echo "iso-tsap/s7" ;;
        110)     echo "pop3" ;;
        111)     echo "rpcbind/nfs" ;;
        113)     echo "ident" ;;
        119)     echo "nntp" ;;
        123)     echo "ntp" ;;
        135)     echo "msrpc" ;;
        137)     echo "netbios-ns" ;;
        138)     echo "netbios-dgm" ;;
        139)     echo "netbios-ssn" ;;
        143)     echo "imap" ;;
        161)     echo "snmp" ;;
        162)     echo "snmptrap" ;;
        179)     echo "bgp" ;;
        194)     echo "irc" ;;
        389)     echo "ldap" ;;
        427)     echo "svrloc/slp" ;;
        443)     echo "https" ;;
        445)     echo "microsoft-ds/smb" ;;
        464)     echo "kpasswd" ;;
        465)     echo "smtps" ;;
        500)     echo "isakmp/ike" ;;
        502)     echo "modbus" ;;
        512)     echo "exec" ;;
        513)     echo "login/rlogin" ;;
        514)     echo "shell/syslog" ;;
        515)     echo "printer/lpd" ;;
        520)     echo "rip" ;;
        523)     echo "db2" ;;
        540)     echo "uucp" ;;
        543)     echo "klogin" ;;
        544)     echo "kshell" ;;
        546|547) echo "dhcpv6" ;;
        548)     echo "afp" ;;
        554)     echo "rtsp" ;;
        587)     echo "submission/smtp" ;;
        593)     echo "http-rpc-epmap" ;;
        623)     echo "ipmi/asf-rmcp" ;;
        631)     echo "ipp/cups" ;;
        636)     echo "ldaps" ;;
        873)     echo "rsync" ;;
        902)     echo "vmware-auth" ;;
        989)     echo "ftps-data" ;;
        990)     echo "ftps" ;;
        993)     echo "imaps" ;;
        995)     echo "pop3s" ;;
        1080)    echo "socks" ;;
        1099)    echo "java-rmi" ;;
        1194)    echo "openvpn" ;;
        1352)    echo "lotus-notes" ;;
        1433)    echo "ms-sql-s" ;;
        1434)    echo "ms-sql-m" ;;
        1521)    echo "oracle-tns" ;;
        1723)    echo "pptp" ;;
        1812)    echo "radius" ;;
        1813)    echo "radius-acct" ;;
        1883)    echo "mqtt" ;;
        1900)    echo "ssdp/upnp" ;;
        2049)    echo "nfs" ;;
        2082|2083) echo "cpanel" ;;
        2086|2087) echo "whm" ;;
        2121)    echo "ftp-alt" ;;
        2181)    echo "zookeeper" ;;
        2222)    echo "ssh-alt" ;;
        2375)    echo "docker" ;;
        2376)    echo "docker-tls" ;;
        2379|2380) echo "etcd" ;;
        2483)    echo "oracle" ;;
        2484)    echo "oracle-ssl" ;;
        3000)    echo "http-dev/grafana" ;;
        3128)    echo "squid-proxy" ;;
        3260)    echo "iscsi" ;;
        3268)    echo "globalcat-ldap" ;;
        3269)    echo "globalcat-ldaps" ;;
        3306)    echo "mysql" ;;
        3389)    echo "rdp/ms-wbt" ;;
        3632)    echo "distcc" ;;
        3690)    echo "svn" ;;
        4369)    echo "epmd/erlang" ;;
        4444)    echo "metasploit/krb524" ;;
        4500)    echo "ipsec-nat-t" ;;
        4505|4506) echo "saltstack" ;;
        4786)    echo "cisco-smi" ;;
        4848)    echo "glassfish-admin" ;;
        5000)    echo "upnp/http-dev" ;;
        5038)    echo "asterisk-ami" ;;
        5060)    echo "sip" ;;
        5061)    echo "sips" ;;
        5222)    echo "xmpp-client" ;;
        5269)    echo "xmpp-server" ;;
        5353)    echo "mdns" ;;
        5357)    echo "wsdapi" ;;
        5432)    echo "postgresql" ;;
        5555)    echo "adb/freeciv" ;;
        5601)    echo "kibana" ;;
        5666)    echo "nrpe/nagios" ;;
        5672)    echo "amqp/rabbitmq" ;;
        5683)    echo "coap" ;;
        5800)    echo "vnc-http" ;;
        5900)    echo "vnc" ;;
        5938)    echo "teamviewer" ;;
        5984)    echo "couchdb" ;;
        5985)    echo "winrm-http" ;;
        5986)    echo "winrm-https" ;;
        6000)    echo "x11" ;;
        6379)    echo "redis" ;;
        6443)    echo "kubernetes-api" ;;
        6514)    echo "syslog-tls" ;;
        6666|6667|6697) echo "irc" ;;
        7001)    echo "weblogic" ;;
        7077)    echo "spark" ;;
        7199)    echo "cassandra-jmx" ;;
        7474)    echo "neo4j" ;;
        7547)    echo "cwmp/tr-069" ;;
        8000)    echo "http-alt" ;;
        8009)    echo "ajp13/tomcat" ;;
        8080)    echo "http-proxy/alt" ;;
        8081)    echo "http-alt" ;;
        8086)    echo "influxdb" ;;
        8089)    echo "splunkd" ;;
        8140)    echo "puppet" ;;
        8161)    echo "activemq-web" ;;
        8200)    echo "vault" ;;
        8291)    echo "mikrotik-winbox" ;;
        8443)    echo "https-alt" ;;
        8500)    echo "consul" ;;
        8530)    echo "wsus" ;;
        8531)    echo "wsus-ssl" ;;
        8545)    echo "ethereum-rpc" ;;
        8686)    echo "jmx" ;;
        8761)    echo "eureka" ;;
        8888)    echo "http-alt/jupyter" ;;
        9000)    echo "php-fpm/portainer" ;;
        9001)    echo "tor/supervisor" ;;
        9042)    echo "cassandra-cql" ;;
        9090)    echo "prometheus" ;;
        9092)    echo "kafka" ;;
        9100)    echo "jetdirect/node-exp" ;;
        9200)    echo "elasticsearch" ;;
        9300)    echo "elasticsearch-node" ;;
        9418)    echo "git" ;;
        9443)    echo "https-alt" ;;
        9999)    echo "http-alt" ;;
        10000)   echo "webmin/ndmp" ;;
        10250)   echo "kubelet" ;;
        11211)   echo "memcached" ;;
        15672)   echo "rabbitmq-mgmt" ;;
        16379)   echo "redis-cluster" ;;
        19999)   echo "netdata" ;;
        20000)   echo "dnp3" ;;
        25565)   echo "minecraft" ;;
        27017)   echo "mongodb" ;;
        27018)   echo "mongodb-shard" ;;
        27019)   echo "mongodb-config" ;;
        28017)   echo "mongodb-web" ;;
        50000)   echo "sap/db2" ;;
        61616)   echo "activemq" ;;
        *)       echo "" ;;
    esac
}

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
    priv_group_note "$g" || continue
    if in_list "$g" "$PRIV_GROUPS_ROOT"; then hit "member of root-capable group '$g' ($PG_NOTE)"
    else hit "member of privileged-read group '$g' ($PG_NOTE)"; fi
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
# --- Privilege sources ------------------------------------------------------
# Every account is checked against each local source that can hand out root:
#   groups   PRIV_GROUPS_ROOT / PRIV_GROUPS_PARTIAL (top of file)
#   sudoers  /etc/sudoers plus the files it includes, parsed the way sudo reads
#            them (User_Alias, %group, %#gid, #uid, ALL, '!' negation, comma
#            lists, Runas specs, Cmnd_Alias), so each grant is judged by what it
#            allows rather than by the user merely being named
#   doas     /etc/doas.conf, /usr/local/etc/doas.conf
#   polkit   admin identities (addAdminRule / AdminIdentities=) and rules or
#            .pkla entries that grant actions without admin authentication
#   pam_cap  /etc/security/capability.conf, when pam_cap.so is in /etc/pam.d
# PRIV-CAPABLE = a path to root: sudo/doas ALL or a GTFOBins/wildcard command
#   as root, polkit admin, a root-equivalent group, an ambient dangerous cap.
# PRIV-LIMITED = elevated rights short of root: specific commands, another
#   runas user, log/hash-reading groups, inheritable-only capabilities.
# Sources that exist but cannot be read are listed, so a clean result from an
# unprivileged run is never mistaken for a complete one.
PC_FS=$'\034'; PC_US=$'\037'     # parser output: field / list-item separators
PC_UNREAD=()

# -- sudoers --
SUDO_PRESENT=0; { have sudo || [[ -x /usr/bin/sudo || -x /bin/sudo ]]; } && SUDO_PRESENT=1
SU_FILES=() SU_UNREAD=()
SU_SRC=() SU_USERS=() SU_RUNAS=() SU_RTEXT=() SU_TAGS=() SU_CMD=() SU_ROOT=() SU_RANK=() SU_DESC=()
declare -A SU_SEEN=() SU_UA=() SU_RA=() SU_CA=()
# Collect FILE and, depth-first, what it includes, in sudo's order: relative
# paths resolve against the including file's directory, %h is the short
# hostname, and an includedir skips names containing '.' or ending in '~'.
sudoers_walk() {     # sudoers_walk FILE DEPTH
    local f=$1 line path isdir
    local re='^[[:space:]]*[@#]include(dir)?[[:space:]]+(.*[^[:space:]])[[:space:]]*$'
    (( $2 > 8 )) && return
    [[ -e $f && -z ${SU_SEEN[$f]-} ]] || return
    SU_SEEN[$f]=1
    if [[ ! -r $f ]]; then SU_UNREAD+=("$f"); return; fi
    SU_FILES+=("$f")
    while IFS= read -r line || [[ -n $line ]]; do
        [[ $line =~ $re ]] || continue
        isdir=${BASH_REMATCH[1]} path=${BASH_REMATCH[2]}
        path=${path#\"}; path=${path%\"}; path=${path//"%h"/${HOSTNAME%%.*}}
        [[ $path == /* ]] || path=${f%/*}/$path
        if [[ -n $isdir ]]; then sudoers_walk_dir "$path" $(( $2 + 1 ))
        else sudoers_walk "$path" $(( $2 + 1 )); fi
    done < "$f"
}
sudoers_walk_dir() {     # sudoers_walk_dir DIR DEPTH
    local e base
    [[ -d $1 ]] || return
    if [[ ! -r $1 || ! -x $1 ]]; then SU_UNREAD+=("$1/"); return; fi
    for e in "$1"/*; do
        base=${e##*/}
        [[ -f $e && $base != *.* && $base != *'~' ]] && sudoers_walk "$e" "$2"
    done
}
# Parse sudoers files into records (fields split by \034, lists by \037):
#   UA|RA|CA <name> <member>                           alias definitions
#   R <file:line> <users> <runas-users> <runas-text> <tags> <command>
# <runas-users> is DEFAULT (no Runas spec: root) or SELF (group-only spec).
sudoers_parse() {
    awk '
    BEGIN { FS_ = "\034"; US = "\037"
            OPTRE = "^(ROLE|TYPE|CWD|CHROOT|NOTBEFORE|NOTAFTER|TIMEOUT|APPARMOR_PROFILE|PRIVS|LIMITPRIVS)$" }
    function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
    # "#" starts a comment unless a digit follows (#uid, %#gid); "\#" is literal.
    function strip_comment(s,    i, n, c) {
        n = length(s)
        for (i = 1; i <= n; i++) {
            c = substr(s, i, 1)
            if (c == "\\") { i++; continue }
            if (c == "#" && substr(s, i + 1, 1) !~ /[0-9]/) return substr(s, 1, i - 1)
        }
        return s
    }
    # Split s on sep outside parentheses, keeping backslash escapes.
    function split_top(s, arr, sep,    i, n, c, depth, cur, k) {
        n = length(s); depth = 0; cur = ""; k = 0
        for (i = 1; i <= n; i++) {
            c = substr(s, i, 1)
            if (c == "\\" && i < n) { cur = cur c substr(s, i + 1, 1); i++; continue }
            if (c == "(") depth++
            else if (c == ")" && depth > 0) depth--
            if (c == sep && depth == 0) { arr[++k] = trim(cur); cur = ""; continue }
            cur = cur c
        }
        arr[++k] = trim(cur)
        return k
    }
    function joinlist(s,    a, n, i, out) {
        n = split_top(s, a, ","); out = ""
        for (i = 1; i <= n; i++) if (a[i] != "") out = out (out == "" ? "" : US) a[i]
        return out
    }
    # Length of the first word, honouring "quotes" and backslash escapes.
    function word_len(s,    i, n, c, inq) {
        n = length(s); inq = 0
        for (i = 1; i <= n; i++) {
            c = substr(s, i, 1)
            if (c == "\\") { i++; continue }
            if (c == "\"") { inq = !inq; continue }
            if (!inq && (c == " " || c == "\t")) return i - 1
        }
        return n
    }
    # Position of the ":" that starts the next "Host_List =" spec, or 0.
    function find_hostsep(body,    off, tail, tok) {
        off = 0
        while (match(substr(body, off + 1), /:[ \t]*[^ \t=():]+[ \t]*=/)) {
            tail = substr(body, off + 1)
            tok = trim(substr(tail, RSTART + 1, RLENGTH - 2))
            if (tok !~ OPTRE) return off + RSTART
            off += RSTART
        }
        return 0
    }
    function do_alias(kw, rest,    tag, name, body, n, a, i) {
        tag = ""
        if (kw == "User_Alias") tag = "UA"
        else if (kw == "Runas_Alias") tag = "RA"
        else if (kw == "Cmnd_Alias" || kw == "Cmd_Alias") tag = "CA"
        while (match(rest, /^[A-Z][A-Z0-9_]*[ \t]*=/)) {
            name = trim(substr(rest, 1, RLENGTH - 1))
            body = substr(rest, RLENGTH + 1); rest = ""
            if (match(body, /:[ \t]*[A-Z][A-Z0-9_]*[ \t]*=/)) {
                rest = trim(substr(body, RSTART + 1)); body = substr(body, 1, RSTART - 1)
            }
            if (tag == "") continue
            n = split_top(body, a, ",")
            for (i = 1; i <= n; i++) if (a[i] != "") print tag FS_ name FS_ a[i]
        }
    }
    function do_userspec(s, src,    L, users, rest, p, body, nxt, n, items, i, it, rt, q, ru, rtext, nopw, setenv, t, tags) {
        gsub(/[ \t]*,[ \t]*/, ",", s); gsub(/![ \t]+/, "!", s)
        L = word_len(s)
        users = joinlist(substr(s, 1, L)); rest = trim(substr(s, L + 1))
        while (rest != "") {
            if (!(p = index(rest, "="))) return
            body = substr(rest, p + 1); rest = ""
            if ((nxt = find_hostsep(body))) { rest = trim(substr(body, nxt + 1)); body = substr(body, 1, nxt - 1) }
            ru = "DEFAULT"; rtext = ""; nopw = 0; setenv = 0
            n = split_top(body, items, ",")
            for (i = 1; i <= n; i++) {
                it = items[i]
                if (substr(it, 1, 1) == "(" && (q = index(it, ")")) > 0) {
                    rt = substr(it, 2, q - 2); it = trim(substr(it, q + 1))
                    gsub(/[ \t]/, "", rt); rtext = "(" rt ")"
                    q = index(rt, ":"); ru = q ? substr(rt, 1, q - 1) : rt
                    if (ru == "") ru = q ? "SELF" : "DEFAULT"; else ru = joinlist(ru)
                }
                while (1) {        # Option_Spec, Tag_Spec and digest prefixes before the command
                    if (match(it, /^[A-Z_]+[ \t]*=[ \t]*[^ \t]*[ \t]*/)) {
                        t = trim(substr(it, 1, index(it, "=") - 1))
                        if (t ~ OPTRE) { it = substr(it, RLENGTH + 1); continue }
                    }
                    if (match(it, /^[A-Z_]+:[ \t]*/)) {
                        t = substr(it, 1, index(it, ":") - 1)
                        if (t == "NOPASSWD") nopw = 1
                        else if (t == "PASSWD") nopw = 0
                        else if (t == "SETENV") setenv = 1
                        else if (t == "NOSETENV") setenv = 0
                        it = substr(it, RLENGTH + 1); continue
                    }
                    if (match(it, /^sha(224|256|384|512):[^ \t]+[ \t]+/)) { it = substr(it, RLENGTH + 1); continue }
                    break
                }
                it = trim(it)
                if (it == "") continue
                tags = nopw ? "NOPASSWD" : ""
                if (setenv) tags = tags (tags == "" ? "" : " ") "SETENV"
                print "R" FS_ src FS_ users FS_ ru FS_ rtext FS_ tags FS_ it
            }
        }
    }
    FNR == 1 { buf = "" }
    {
        line = $0; sub(/\r$/, "", line)
        if (buf == "") start = FNR
        if (line ~ /\\$/ && (buf != "" || line !~ /^[ \t]*#([^0-9]|$)/)) {
            buf = buf substr(line, 1, length(line) - 1) " "; next
        }
        line = buf line; buf = ""
        if (line ~ /^[ \t]*[@#]include/) next
        s = trim(strip_comment(line))
        if (s == "" || s ~ /^Defaults([:@>!]|[ \t]|$)/) next
        if (s ~ /^(User_Alias|Runas_Alias|Host_Alias|Cmnd_Alias|Cmd_Alias)[ \t]/) {
            kw = s; sub(/[ \t].*$/, "", kw)
            rest = s; sub(/^[A-Za-z_]+[ \t]+/, "", rest)
            do_alias(kw, rest); next
        }
        do_userspec(s, FILENAME ":" start)
    }' "$@"
}
su_alias() {         # su_alias NAME -> SU_ALIAS_VAL from the User_Alias (M_ALIAS=U) or Runas_Alias (R) table
    if [[ $M_ALIAS == R ]]; then [[ -n ${SU_RA[$1]+x} ]] && SU_ALIAS_VAL=${SU_RA[$1]}
    else [[ -n ${SU_UA[$1]+x} ]] && SU_ALIAS_VAL=${SU_UA[$1]}; fi
}
# su_match LIST DEPTH -> 0 allowed, 1 denied, 2 no match, for the identity in
# M_NAME/M_UID/M_GROUPS/M_GIDS. As in sudo, the LAST item that matches decides
# and '!' inverts it, so "ALL, !alice" excludes alice.
su_match() {
    local item neg r i
    local -a items
    (( $2 > 8 )) && return 2
    IFS=$PC_US read -ra items <<<"$1"
    for (( i = ${#items[@]} - 1; i >= 0; i-- )); do
        item=${items[i]} neg=0 r=2
        while [[ $item == '!'* ]]; do item=${item:1}; neg=$(( !neg )); done
        item=${item//\"/}
        case $item in
            ALL)        r=0 ;;
            '%:'*|'+'*) ;;                       # non-Unix group / netgroup: not evaluated
            '%#'*)      in_list "${item:2}" "$M_GIDS" && r=0 ;;
            '%'*)       in_list "${item:1}" "$M_GROUPS" && r=0 ;;
            '#'*)       [[ ${item:1} == "$M_UID" ]] && r=0 ;;
            *)  if [[ $item =~ ^[A-Z][A-Z0-9_]*$ ]] && su_alias "$item"; then
                    su_match "$SU_ALIAS_VAL" $(( $2 + 1 )); r=$?
                else
                    [[ ${item//\\/} == "$M_NAME" ]] && r=0
                fi ;;
        esac
        (( r == 2 )) && continue
        (( neg )) && r=$(( 1 - r ))
        return "$r"
    done
    return 2
}
# su_cmd_rank CMD DEPTH -> CR = 3 (ALL), 2 (root via a GTFOBins or wildcard
# command), 1 (specific commands), 0 (nothing), and CD = a short description.
su_cmd_rank() {
    local cmd=$1 path base m best=0 bestd=""
    local -a ms
    CR=0 CD=""
    [[ $cmd == '!'* || $2 -gt 8 ]] && return       # a negated command restricts, never grants
    if [[ $cmd == ALL ]]; then CR=3 CD=ALL; return; fi
    if [[ $cmd =~ ^[A-Z][A-Z0-9_]*$ && -n ${SU_CA[$cmd]+x} ]]; then
        IFS=$PC_US read -ra ms <<<"${SU_CA[$cmd]}"
        for m in ${ms[@]+"${ms[@]}"}; do
            su_cmd_rank "$m" $(( $2 + 1 ))
            (( CR > best )) && best=$CR bestd=$CD
        done
        CR=$best CD=$cmd
        (( best >= 2 )) && CD+=" -> $bestd"
        return
    fi
    path=${cmd%%[[:space:]]*} base=${path##*/}
    if [[ $path == sudoedit ]]; then CR=1 CD=$cmd
    elif [[ $path == */ || $path == *[*?[]* ]]; then CR=2 CD="$path (wildcard)"
    elif [[ $base =~ ^($GTFO)$ ]]; then CR=2 CD="$path (GTFOBins)"
    else CR=1 CD=$cmd; fi
}
if (( SUDO_PRESENT )) && [[ -e /etc/sudoers ]]; then
    sudoers_walk /etc/sudoers 0
    # A root-only /etc/sudoers hides its include list: fall back to the stock includedir.
    [[ -r /etc/sudoers ]] || sudoers_walk_dir /etc/sudoers.d 1
fi
if (( ${#SU_FILES[@]} )); then
    while IFS=$PC_FS read -r k a b c d e f; do
        case $k in
            UA) SU_UA[$a]=${SU_UA[$a]-}${SU_UA[$a]+$PC_US}$b ;;
            RA) SU_RA[$a]=${SU_RA[$a]-}${SU_RA[$a]+$PC_US}$b ;;
            CA) SU_CA[$a]=${SU_CA[$a]-}${SU_CA[$a]+$PC_US}$b ;;
            R)  SU_SRC+=("$a") SU_USERS+=("$b") SU_RUNAS+=("$c") SU_RTEXT+=("$d") SU_TAGS+=("$e") SU_CMD+=("$f") ;;
        esac
    done < <(sudoers_parse "${SU_FILES[@]}")
    # Rank each grant once: does its Runas list include root, and what does it run?
    M_NAME=root M_UID=0 M_GROUPS=$(id -nG root 2>/dev/null) M_GIDS=$(id -G root 2>/dev/null) M_ALIAS=R
    for (( i = 0; i < ${#SU_CMD[@]}; i++ )); do
        case ${SU_RUNAS[i]} in
            DEFAULT) SU_ROOT[i]=1 ;;
            SELF)    SU_ROOT[i]=0 ;;
            *)       if su_match "${SU_RUNAS[i]}" 0; then SU_ROOT[i]=1; else SU_ROOT[i]=0; fi ;;
        esac
        su_cmd_rank "${SU_CMD[i]}" 0; SU_RANK[i]=$CR SU_DESC[i]=$CD
    done
fi

# -- doas --
DOAS_PRESENT=0; { have doas || [[ -x /usr/bin/doas || -x /usr/local/bin/doas ]]; } && DOAS_PRESENT=1
DO_FILES=() DO_ACT=() DO_ID=() DO_TGT=() DO_CMD=() DO_OPTS=() DO_SRC=()
# doas.conf: permit|deny [options] identity [as target] [cmd command [args ...]]
# -> D <permit|deny> <identity> <target> <command> <options> <file:line>
doas_parse() {
    awk '
    BEGIN { FS_ = "\034" }
    FNR == 1 { buf = "" }
    {
        line = $0; sub(/\r$/, "", line)
        if (buf == "") start = FNR
        if (line ~ /\\$/) { buf = buf substr(line, 1, length(line) - 1) " "; next }
        line = buf line; buf = ""
        sub(/#.*/, "", line)
        n = split(line, t)
        if (n == 0 || (t[1] != "permit" && t[1] != "deny")) next
        i = 2; opts = ""
        while (i <= n) {
            if (t[i] == "setenv") {
                i++
                if (t[i] ~ /^[{]/) while (i <= n && t[i] !~ /[}]$/) i++
                i++; continue
            }
            if (t[i] ~ /^(nopass|nolog|persist|keepenv)$/) { opts = opts (opts == "" ? "" : ",") t[i]; i++; continue }
            break
        }
        ident = t[i++]; target = ""; cmd = ""
        if (t[i] == "as") { target = t[i + 1]; i += 2 }
        if (t[i] == "cmd") { cmd = t[i + 1]; for (i += 2; i <= n; i++) cmd = cmd " " t[i] }
        print "D" FS_ t[1] FS_ ident FS_ target FS_ cmd FS_ opts FS_ FILENAME ":" start
    }' "$@"
}
for f in /etc/doas.conf /usr/local/etc/doas.conf; do
    [[ -e $f ]] || continue
    if [[ -r $f ]]; then DO_FILES+=("$f"); else PC_UNREAD+=("$f"); fi
done
if (( DOAS_PRESENT && ${#DO_FILES[@]} )); then
    while IFS=$PC_FS read -r k a b c d e f; do
        DO_ACT+=("$a") DO_ID+=("$b") DO_TGT+=("$c") DO_CMD+=("$d") DO_OPTS+=("$e") DO_SRC+=("$f")
    done < <(doas_parse "${DO_FILES[@]}")
fi

# -- polkit --
PK_RULES=() PK_LA=() PK_KIND=() PK_ID=() PK_ACT=() PK_SRC=()
declare -A PK_SEEN=()
# JavaScript rules -> PA <identity> "" <file:line> for each addAdminRule identity,
# and PY <identity> <actions> <file:line> for each addRule block that returns
# YES/AUTH_SELF for a named user/group. <actions> lists the action ids it tests
# (prefix tests end in '*'); '*' = no action test at all, i.e. every action.
polkit_rules_parse() {
    awk -v q="'" '
    BEGIN { FS_ = "\034" }
    function cnt(s, ch,    n, i) { n = 0; for (i = 1; i <= length(s); i++) if (substr(s, i, 1) == ch) n++; return n }
    function qstr(m,    p) { p = index(m, "\""); m = substr(m, p + 1); return substr(m, 1, index(m, "\"") - 1) }
    function emit(kind, id, acts) { print kind FS_ id FS_ acts FS_ FILENAME ":" start }
    function flush(    s, t, m, a, acts) {
        s = blk
        if (mode == "A") {
            while (match(s, /unix-(user|group|netgroup):[-A-Za-z0-9_.@$]+/)) {
                emit("PA", substr(s, RSTART, RLENGTH), ""); s = substr(s, RSTART + RLENGTH)
            }
            return
        }
        if (s !~ /polkit\.Result\.(YES|AUTH_SELF)/) return
        acts = ""; t = s
        while (match(t, /(action\.id[ \t]*===?[ \t]*|indexOf\([ \t]*|startsWith\([ \t]*)"[^"]*"/)) {
            m = substr(t, RSTART, RLENGTH); t = substr(t, RSTART + RLENGTH)
            a = qstr(m); if (m !~ /^action/) a = a "*"
            acts = acts (acts == "" ? "" : ",") a
        }
        if (acts == "") acts = (s ~ /action\./) ? "(filtered)" : "*"
        t = s
        while (match(t, /isInGroup\([ \t]*"[^"]*"/)) {
            emit("PY", "unix-group:" qstr(substr(t, RSTART, RLENGTH)), acts); t = substr(t, RSTART + RLENGTH)
        }
        t = s
        while (match(t, /subject\.user[ \t]*===?[ \t]*"[^"]*"/)) {
            emit("PY", "unix-user:" qstr(substr(t, RSTART, RLENGTH)), acts); t = substr(t, RSTART + RLENGTH)
        }
    }
    FNR == 1 { incom = 0; mode = "" }
    {
        line = $0; sub(/\r$/, "", line); gsub(q, "\"", line)
        out = ""                       # line with /* */ and // comments removed
        while (line != "") {
            if (incom) {
                p = index(line, "*/")
                if (p == 0) line = ""; else { line = substr(line, p + 2); incom = 0 }
                continue
            }
            p = index(line, "/*"); c = index(line, "//")
            if (c > 0 && (p == 0 || c < p)) { out = out substr(line, 1, c - 1); line = ""; continue }
            if (p > 0) { out = out substr(line, 1, p - 1); line = substr(line, p + 2); incom = 1; continue }
            out = out line; line = ""
        }
        if (mode == "") {
            if (out ~ /addAdminRule[ \t]*\(/) mode = "A"
            else if (out ~ /addRule[ \t]*\(/) mode = "R"
            if (mode != "") { blk = ""; depth = 0; opened = 0; start = FNR }
        }
        if (mode != "") {
            blk = blk " " out
            o = cnt(out, "{"); depth += o - cnt(out, "}"); if (o) opened = 1
            if (opened && depth <= 0) { flush(); mode = "" }
        }
    }' "$@"
}
# Local-authority backend: AdminIdentities= in localauthority.conf.d (the last
# file wins) and .pkla sections whose Result* is yes/auth_self.
polkit_pkla_parse() {
    awk '
    BEGIN { FS_ = "\034" }
    function pflush(    n, a, i) {
        if (ids != "" && grant) {
            n = split(ids, a, ";")
            for (i = 1; i <= n; i++) if (a[i] != "") print "PY" FS_ a[i] FS_ acts FS_ src
        }
        ids = ""; acts = ""; grant = 0
    }
    { sub(/\r$/, "") }
    FNR == 1 { pflush() }
    /^[ \t]*\[/ { pflush(); src = FILENAME ":" FNR; next }
    /^[ \t]*Identity[ \t]*=/ { v = $0; sub(/^[^=]*=[ \t]*/, "", v); ids = v; next }
    /^[ \t]*Action[ \t]*=/   { v = $0; sub(/^[^=]*=[ \t]*/, "", v); gsub(/;/, ",", v); acts = v; next }
    /^[ \t]*Result(Any|Inactive|Active)[ \t]*=[ \t]*(yes|auth_self)/ { grant = 1; next }
    /^[ \t]*AdminIdentities[ \t]*=/ { v = $0; sub(/^[^=]*=[ \t]*/, "", v); admin = v; asrc = FILENAME ":" FNR }
    END {
        pflush()
        n = split(admin, a, ";")
        for (i = 1; i <= n; i++) if (a[i] != "") print "PA" FS_ a[i] FS_ "" FS_ asrc
    }' "$@"
}
# Rules dirs in polkit priority order; a same-named file earlier in the list
# overrides a later one, so only the first copy of each name is read.
for d in /etc/polkit-1/rules.d /run/polkit-1/rules.d /usr/local/share/polkit-1/rules.d /usr/share/polkit-1/rules.d; do
    [[ -d $d ]] || continue
    if [[ ! -r $d || ! -x $d ]]; then PC_UNREAD+=("$d/"); continue; fi
    for f in "$d"/*.rules; do
        [[ -f $f && -z ${PK_SEEN[${f##*/}]-} ]] || continue
        PK_SEEN[${f##*/}]=1
        if [[ -r $f ]]; then PK_RULES+=("$f"); else PC_UNREAD+=("$f"); fi
    done
done
for d in /etc/polkit-1/localauthority /var/lib/polkit-1/localauthority; do
    [[ -d $d && ! ( -r $d && -x $d ) ]] && PC_UNREAD+=("$d/")
done
for f in /etc/polkit-1/localauthority.conf.d/*.conf /etc/polkit-1/localauthority/*/*.pkla \
         /var/lib/polkit-1/localauthority/*/*.pkla; do
    [[ -f $f ]] || continue
    if [[ -r $f ]]; then PK_LA+=("$f"); else PC_UNREAD+=("$f"); fi
done
while IFS=$PC_FS read -r k a b c; do
    PK_KIND+=("$k") PK_ID+=("$a") PK_ACT+=("$b") PK_SRC+=("$c")
done < <(
    (( ${#PK_RULES[@]} )) && polkit_rules_parse "${PK_RULES[@]}"
    (( ${#PK_LA[@]} )) && polkit_pkla_parse "${PK_LA[@]}"
)

# -- pam_cap --
# capability.conf: "<caps> <user|@group|*> ..."; pam_cap applies the FIRST line
# that matches. A '^' prefix also raises the cap as AMBIENT (live in the login
# shell); plain caps are inheritable only and need a binary carrying matching
# file caps; '!' drops a cap from the bounding set.
PC_DANGER_CAPS='all cap_setuid cap_setgid cap_sys_admin cap_dac_override cap_dac_read_search cap_sys_ptrace cap_sys_module cap_chown cap_fowner cap_setfcap cap_sys_rawio'
PAMCAP_ACTIVE=0; CAP_SPEC=() CAP_WHO=() CAP_SRC=()
CAPCONF=/etc/security/capability.conf
if [[ -e $CAPCONF ]]; then
    grep -qsE '^[[:space:]]*[^#[:space:]]+[[:space:]].*pam_cap\.so' /etc/pam.d/* && PAMCAP_ACTIVE=1
    if [[ -r $CAPCONF ]]; then
        n=0
        while read -r spec who || [[ -n ${spec-} ]]; do
            n=$(( n + 1 ))
            [[ -z $spec || $spec == '#'* ]] && continue
            CAP_SPEC+=("$spec") CAP_WHO+=("${who%%#*}") CAP_SRC+=("$CAPCONF:$n")
        done < "$CAPCONF"
    else
        PC_UNREAD+=("$CAPCONF")
    fi
fi

# -- per-account evaluation: fills R_CAP (paths to root) and R_LIM (limited) --
pc_eval_sudo() {
    local i who
    for (( i = 0; i < ${#SU_CMD[@]}; i++ )); do
        (( SU_RANK[i] )) || continue
        su_match "${SU_USERS[i]}" 0 || continue
        who=${SU_USERS[i]//$PC_US/,}
        [[ $who == "$M_NAME" ]] && who="" || who=" [$who]"
        r="sudo$who ${SU_RTEXT[i]:-(root)} ${SU_DESC[i]}${SU_TAGS[i]:+ ${SU_TAGS[i]}}  @${SU_SRC[i]}"
        if (( SU_ROOT[i] && SU_RANK[i] >= 2 )); then R_CAP+=("$r"); else R_LIM+=("$r"); fi
    done
}
pc_eval_doas() {        # rules apply in order and the last match wins, so a later deny-all clears earlier grants
    local i id tgt who
    local -a cap=() lim=()
    for (( i = 0; i < ${#DO_ACT[@]}; i++ )); do
        id=${DO_ID[i]} who=""
        if [[ $id == :* ]]; then in_list "${id:1}" "$M_GROUPS $M_GIDS" || continue; who=" [$id]"
        else [[ $id == "$M_NAME" || $id == "$M_UID" ]] || continue; fi
        tgt=${DO_TGT[i]:-root}
        if [[ ${DO_ACT[i]} == deny ]]; then
            [[ -z ${DO_CMD[i]} && ( $tgt == root || $tgt == 0 ) ]] && cap=() lim=()
            continue
        fi
        CR=3 CD="any command"
        [[ -n ${DO_CMD[i]} ]] && su_cmd_rank "${DO_CMD[i]}" 0
        r="doas$who as $tgt: $CD${DO_OPTS[i]:+ ${DO_OPTS[i]}}  @${DO_SRC[i]}"
        if [[ ( $tgt == root || $tgt == 0 ) ]] && (( CR >= 2 )); then cap+=("$r"); else lim+=("$r"); fi
    done
    R_CAP+=(${cap[@]+"${cap[@]}"}) R_LIM+=(${lim[@]+"${lim[@]}"})
}
pk_id_match() {         # pk_id_match unix-user:NAME|UID / unix-group:NAME|GID
    case $1 in
        unix-user:*)  [[ ${1#unix-user:} == "$M_NAME" || ${1#unix-user:} == "$M_UID" ]] ;;
        unix-group:*) in_list "${1#unix-group:}" "$M_GROUPS $M_GIDS" ;;
        *) return 1 ;;
    esac
}
pc_eval_polkit() {
    local i a root acts
    local -a al
    for (( i = 0; i < ${#PK_KIND[@]}; i++ )); do
        pk_id_match "${PK_ID[i]}" || continue
        if [[ ${PK_KIND[i]} == PA ]]; then
            R_CAP+=("polkit admin [${PK_ID[i]}]: pkexec / auth_admin actions with own password  @${PK_SRC[i]}")
            continue
        fi
        root=0
        IFS=, read -ra al <<<"${PK_ACT[i]}"
        # Each entry is an action id or a glob ('*', 'org.freedesktop.*'): left
        # unquoted on purpose so it matches as a pattern.
        for a in ${al[@]+"${al[@]}"}; do [[ org.freedesktop.policykit.exec == $a ]] && root=1; done
        acts=${PK_ACT[i]}; [[ $acts == '*' ]] && acts="ALL actions"
        r="polkit [${PK_ID[i]}]: $acts without admin auth  @${PK_SRC[i]}"
        if (( root )); then R_CAP+=("$r"); else R_LIM+=("$r"); fi
    done
}
pc_eval_pamcap() {
    local i w c amb inh root
    local -a ws caps
    (( PAMCAP_ACTIVE )) || return
    for (( i = 0; i < ${#CAP_SPEC[@]}; i++ )); do
        read -ra ws <<<"${CAP_WHO[i]}"
        for w in ${ws[@]+"${ws[@]}"}; do
            [[ $w == '*' || $w == "$M_NAME" ]] && break
            [[ $w == @* ]] && in_list "${w:1}" "$M_GROUPS" && break
            w=""
        done
        [[ -n ${w-} ]] || continue
        amb="" inh="" root=0
        IFS=, read -ra caps <<<"${CAP_SPEC[i],,}"
        for c in ${caps[@]+"${caps[@]}"}; do
            case $c in
                ''|none|'!'*) ;;
                '^'*) amb+=" ${c:1}"; in_list "${c:1}" "$PC_DANGER_CAPS" && root=1 ;;
                *)    inh+=" $c" ;;
            esac
        done
        if (( root )); then R_CAP+=("pam_cap ambient:$amb  @${CAP_SRC[i]}")
        elif [[ -n $amb$inh ]]; then
            R_LIM+=("pam_cap${amb:+ ambient:$amb}${inh:+ inheritable:$inh} (inheritable caps need a binary with matching file caps)  @${CAP_SRC[i]}")
        fi
        return
    done
}
pc_eval_user() {        # pc_eval_user NAME UID
    local g
    M_NAME=$1 M_UID=$2 M_ALIAS=U
    M_GROUPS=$(id -nG "$1" 2>/dev/null); M_GIDS=$(id -G "$1" 2>/dev/null)
    R_CAP=() R_LIM=()
    for g in $M_GROUPS; do
        priv_group_note "$g" || continue
        if in_list "$g" "$SUDO_GROUPS"; then
            # Count the name only when sudoers itself can't be read; otherwise the
            # parsed rules decide whether the group grants anything.
            (( SUDO_PRESENT )) && [[ -e /etc/sudoers && ! -r /etc/sudoers ]] \
                && R_CAP+=("group $g ($PG_NOTE; sudoers unreadable, assumed)")
        elif in_list "$g" "$PRIV_GROUPS_ROOT"; then R_CAP+=("group $g ($PG_NOTE)")
        else R_LIM+=("group $g ($PG_NOTE)"); fi
    done
    (( SUDO_PRESENT )) && pc_eval_sudo
    (( DOAS_PRESENT )) && pc_eval_doas
    pc_eval_polkit
    pc_eval_pamcap
}

# -- coverage: what was evaluated, and what could not be read --
pcov="sudoers "
if (( ! SUDO_PRESENT )); then pcov+="(sudo not installed)"; else pcov+="${#SU_FILES[@]} file(s)/${#SU_CMD[@]} grant(s)"; fi
if (( ! DOAS_PRESENT )); then pcov+=" | doas not installed"; else pcov+=" | doas ${#DO_ACT[@]} rule(s)"; fi
pcov+=" | polkit $(( ${#PK_RULES[@]} + ${#PK_LA[@]} )) file(s)/${#PK_KIND[@]} grant(s)"
if [[ ! -e $CAPCONF ]]; then pcov+=" | pam_cap no capability.conf"
elif (( PAMCAP_ACTIVE )); then pcov+=" | pam_cap ${#CAP_SPEC[@]} entr(ies)"
else pcov+=" | pam_cap inactive (pam_cap.so not in /etc/pam.d)"; fi
dim "privilege sources: $pcov"
PC_UNREAD=(${SU_UNREAD[@]+"${SU_UNREAD[@]}"} ${PC_UNREAD[@]+"${PC_UNREAD[@]}"})
if (( ${#PC_UNREAD[@]} )); then
    pcov=""
    for (( i = 0; i < ${#PC_UNREAD[@]} && i < 6; i++ )); do pcov+="${pcov:+, }${PC_UNREAD[i]}"; done
    (( ${#PC_UNREAD[@]} > 6 )) && pcov+=" (+$(( ${#PC_UNREAD[@]} - 6 )) more)"
    info "NOTE: not readable as ${ME:-this user}, so NOT evaluated: $pcov"
    if (( SUDO_PRESENT )) && [[ -e /etc/sudoers && ! -r /etc/sudoers ]]; then
        info "NOTE: sudo rules unknown - sudo/wheel/admin membership is assumed root-capable; re-run as root for full coverage"
    fi
fi
(( ${#DO_FILES[@]} && ! DOAS_PRESENT )) && dim "doas.conf exists but doas is not installed - ignored"
grep -qsE '^[[:space:]]*sudoers:.*(sss|ldap)' /etc/nsswitch.conf \
    && info "NOTE: nsswitch.conf also serves sudoers from sss/ldap - those rules are not evaluated"
for u in ${SU_USERS[@]+"${SU_USERS[@]}"} ${SU_UA[@]+"${SU_UA[@]}"}; do
    if [[ $PC_US$u == *"$PC_US+"* || $PC_US$u == *"$PC_US%:"* || $PC_US$u == *"$PC_US!+"* || $PC_US$u == *"$PC_US!%:"* ]]; then
        dim "some sudo rules name netgroups (+x) or non-Unix groups (%:x) - those entries are not evaluated"
        break
    fi
done

if [[ -r /etc/passwd ]]; then
    while IFS=: read -r name _ uid gid _ home shell; do
        [[ $uid =~ ^[0-9]+$ ]] || continue
        tags="" regular=0 interactive=0 rogue_uid0=0
        R_CAP=() R_LIM=()
        if (( uid == 0 )); then
            tags+=" UID0"
            # Any UID 0 account other than 'root' is root-equivalent regardless
            # of its login shell (su target / tampering evidence) - always flag it.
            [[ $name != root ]] && rogue_uid0=1
        elif (( uid >= UID_MIN && uid <= UID_MAX )); then tags+=" regular"; regular=1
        else tags+=" system"; fi
        is_interactive_shell "$shell" && { tags+=" interactive-shell"; interactive=1; }
        # UID 0 already is root; every other account is checked for a path to it.
        (( uid != 0 )) && pc_eval_user "$name" "$uid"
        if (( ${#R_CAP[@]} )); then tags+=" PRIV-CAPABLE"; elif (( ${#R_LIM[@]} )); then tags+=" PRIV-LIMITED"; fi
        line="$name  uid=$uid gid=$gid  shell=$shell  home=$home  [${tags# }]"
        if (( rogue_uid0 || ${#R_CAP[@]} )); then hit "$line"
        elif (( interactive && (regular || ${#R_LIM[@]}) )); then hit "$line"
        else info "$line"; fi
        for r in ${R_CAP[@]+"${R_CAP[@]}"}; do info "    -> root via $r"; done
        for r in ${R_LIM[@]+"${R_LIM[@]}"}; do info "    -> limited: $r"; done
    done < /etc/passwd
else
    hit "/etc/passwd not readable (unusual)"
fi
dim "highlighted = a second UID 0 account, any PRIV-CAPABLE account, or a human / PRIV-LIMITED account with a login shell"
dim "PRIV-CAPABLE = a path to root (sudo/doas ALL or GTFOBins command as root, polkit admin, docker/lxd/disk...); PRIV-LIMITED = elevated rights short of root"

# ===========================================================================
# 3b. SSH LOGIN ACCESS (which local accounts can log in to THIS host, and how)
# ===========================================================================
section "SSH LOGIN ACCESS"
# Is an SSH server present / listening to accept inbound logins at all?
if have sshd || [[ -x /usr/sbin/sshd || -x /usr/bin/sshd ]]; then
    ok "sshd binary present"
else
    dim "no sshd binary found - inbound SSH may be unavailable (still analysing any config)"
fi
if have ss; then
    lst=$(ss -tlnp 2>/dev/null | grep -iE 'sshd|:22[[:space:]]')
    if [[ -n $lst ]]; then hit "an SSH server is LISTENING:"; printf '%s\n' "$lst" | indent
    else dim "no sshd socket seen in 'ss -tlnp'"; fi
fi

# Read GLOBAL-scope sshd_config (sshd_config.d/*.conf first, then the main
# file) and take the first value per keyword, mirroring sshd's first-wins rule
# with the usual 'Include .../sshd_config.d/*.conf' near the top of the file.
SSHD_SOURCES=()
for c in /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config; do
    [[ -r $c ]] && SSHD_SOURCES+=("$c")
done
if (( ${#SSHD_SOURCES[@]} == 0 )); then
    dim "no readable sshd_config (need root, or no SSH server) - cannot analyse login policy"
else
    info "config (first-wins order): ${SSHD_SOURCES[*]}"
    sshd_global=$(
        for c in "${SSHD_SOURCES[@]}"; do
            # Global scope only: stop at the first Match block in each file.
            awk 'BEGIN{IGNORECASE=1} /^[[:space:]]*match([[:space:]]|$)/{stop=1} !stop{print}' "$c" 2>/dev/null
        done
    )
    match_present=0
    for c in "${SSHD_SOURCES[@]}"; do grep -qiE '^[[:space:]]*match([[:space:]]|$)' "$c" 2>/dev/null && match_present=1; done
    sshd_get()      { awk -v k="${1,,}" 'BEGIN{IGNORECASE=1}{if(tolower($1)==k){print $2; exit}}' <<<"$sshd_global"; }
    sshd_get_list() { awk -v k="${1,,}" 'BEGIN{IGNORECASE=1}{if(tolower($1)==k){for(i=2;i<=NF;i++)print $i}}' <<<"$sshd_global"; }

    pw_auth=$(sshd_get passwordauthentication);     pw_auth=${pw_auth:-yes}
    pk_auth=$(sshd_get pubkeyauthentication);       pk_auth=${pk_auth:-yes}
    permit_root=$(sshd_get permitrootlogin);        permit_root=${permit_root:-prohibit-password}
    empty_pw=$(sshd_get permitemptypasswords);      empty_pw=${empty_pw:-no}
    auth_methods=$(sshd_get authenticationmethods); auth_methods=${auth_methods:-any}
    akf=$(sshd_get_list authorizedkeysfile | tr '\n' ' '); akf=${akf:-.ssh/authorized_keys .ssh/authorized_keys2}
    ALLOW_U=(); ALLOW_G=(); DENY_U=(); DENY_G=()
    mapfile -t ALLOW_U < <(sshd_get_list allowusers)
    mapfile -t ALLOW_G < <(sshd_get_list allowgroups)
    mapfile -t DENY_U  < <(sshd_get_list denyusers)
    mapfile -t DENY_G  < <(sshd_get_list denygroups)

    sub "effective global policy (Match blocks excluded)"
    info "PasswordAuthentication=$pw_auth   PubkeyAuthentication=$pk_auth   PermitRootLogin=$permit_root"
    info "PermitEmptyPasswords=$empty_pw   AuthenticationMethods=$auth_methods"
    (( ${#ALLOW_U[@]} )) && info "AllowUsers:  ${ALLOW_U[*]}"
    (( ${#ALLOW_G[@]} )) && info "AllowGroups: ${ALLOW_G[*]}"
    (( ${#DENY_U[@]} ))  && info "DenyUsers:   ${DENY_U[*]}"
    (( ${#DENY_G[@]} ))  && info "DenyGroups:  ${DENY_G[*]}"
    [[ ${pw_auth,,} == yes ]]     && hit "PasswordAuthentication=yes -> the server accepts password logins"
    [[ ${permit_root,,} == yes ]] && hit "PermitRootLogin=yes -> direct root SSH permitted (password or key)"
    [[ $auth_methods != any ]]    && hit "AuthenticationMethods=$auth_methods -> more than one factor may be required"
    (( match_present ))           && hit "Match blocks present -> per-user/group overrides NOT evaluated; effective policy may differ"

    # Allow/Deny evaluation helpers (OpenSSH order: DenyUsers, AllowUsers, DenyGroups, AllowGroups).
    _tok_user()   { printf '%s' "${1%%@*}"; }    # strip any @host from an Allow/Deny token
    _match_user() { local u=$1; shift; local p; for p in "$@"; do [[ $u == $(_tok_user "$p") ]] && return 0; done; return 1; }
    _match_group(){ local u=$1; shift; local p g ug; ug=$(id -nG "$u" 2>/dev/null); for p in "$@"; do for g in $ug; do [[ $g == $p ]] && return 0; done; done; return 1; }
    ssh_gate() {   # 0 = may connect, 1 = blocked by Allow/Deny
        local u=$1
        (( ${#DENY_U[@]} ))  && _match_user  "$u" "${DENY_U[@]}"   && return 1
        (( ${#ALLOW_U[@]} )) && ! _match_user  "$u" "${ALLOW_U[@]}" && return 1
        (( ${#DENY_G[@]} ))  && _match_group "$u" "${DENY_G[@]}"   && return 1
        (( ${#ALLOW_G[@]} )) && ! _match_group "$u" "${ALLOW_G[@]}" && return 1
        return 0
    }
    # Password account status (needs root to read the shadow database).
    pw_status() {  # prints: set | locked | nopw | unknown
        local u=$1 entry h
        (( AM_ROOT )) || { echo unknown; return; }
        if have getent; then entry=$(getent shadow "$u" 2>/dev/null); else entry=$(grep "^${u}:" /etc/shadow 2>/dev/null); fi
        [[ -z $entry ]] && { echo unknown; return; }
        h=${entry#*:}; h=${h%%:*}
        case $h in
            '')        echo nopw ;;
            '!'*|'*'*) echo locked ;;
            *)         echo set ;;
        esac
    }
    # Does the account have at least one authorized key we can see?
    user_has_key() {  # prints: yes | no | unknown
        local u=$1 home=$2 tok kf hk=no unk=0
        for tok in $akf; do
            tok=${tok//%%/%}; tok=${tok//%h/$home}; tok=${tok//%u/$u}
            [[ $tok == /* ]] && kf=$tok || kf="$home/$tok"
            if [[ -r $kf ]]; then
                grep -qE '^[[:space:]]*[^#[:space:]]' "$kf" 2>/dev/null && hk=yes
            elif [[ -e $kf ]]; then unk=1; fi
        done
        if [[ $hk == yes ]]; then echo yes; elif (( unk )); then echo unknown; else echo no; fi
    }

    sub "per-user login capability (accounts with a login shell)"
    printf '      %-16s %-12s %-12s %s\n' USER KEY PASSWORD NOTES
    while IFS=: read -r uname _ uid _ _ uhome ushell; do
        [[ $uid =~ ^[0-9]+$ ]] || continue
        is_interactive_shell "$ushell" || continue
        notes=""
        if [[ $uname == root ]]; then
            case ${permit_root,,} in
                no)                                 key_m=no;    pw_m=no;    notes="PermitRootLogin=no" ;;
                prohibit-password|without-password) key_m=maybe; pw_m=no;    notes="PermitRootLogin=$permit_root (key only)" ;;
                forced-commands-only)               key_m=maybe; pw_m=no;    notes="PermitRootLogin=forced-commands-only" ;;
                *)                                  key_m=maybe; pw_m=maybe ;;
            esac
        else
            key_m=maybe; pw_m=maybe
        fi
        [[ ${pk_auth,,} != yes ]] && key_m=no
        [[ ${pw_auth,,} != yes ]] && pw_m=no
        if [[ $key_m == maybe ]]; then
            case $(user_has_key "$uname" "$uhome") in
                yes) key_m=yes ;; no) key_m=no ;; unknown) key_m=unknown ;;
            esac
        fi
        if [[ $pw_m == maybe ]]; then
            case $(pw_status "$uname") in
                set)     pw_m=yes ;;
                locked)  pw_m=no ;;
                nopw)    [[ ${empty_pw,,} == yes ]] && pw_m="yes(EMPTY!)" || pw_m=no ;;
                unknown) pw_m=unknown ;;
            esac
        fi
        if ! ssh_gate "$uname"; then key_m=no; pw_m=no; notes="BLOCKED by Allow/Deny"; fi
        line=$(printf '%-16s %-12s %-12s %s' "$uname" "$key_m" "$pw_m" "$notes")
        if [[ $key_m == yes || $pw_m == yes* ]]; then hit "$line"; else info "$line"; fi
    done < <(cat /etc/passwd 2>/dev/null)
    dim "KEY/PASSWORD: yes=able, no=blocked, maybe/unknown=cannot confirm (need root for shadow, or can't read another user's keys)."
    dim "Non-root runs cannot read /etc/shadow or other users' keys, so many rows show 'unknown'. Match blocks are not evaluated."
fi

# --- Passive check: CVE-2026-123158 "sshole" (OpenSSH password-auth bypass) ---
# Affects OpenSSH built against musl libc WITHOUT PAM (Alpine's default
# openssh-server, or openssh-server-pam with UsePAM no). glibc systems
# (Debian/Ubuntu/Fedora/RHEL) are NOT affected. Fixed upstream in 10.6p2.
# PASSIVE: only inspects local libc/binary/config/account state - it never
# sends a password, probes the port, or exploits anything.
sub "CVE-2026-123158 'sshole' exposure (passive)"
is_musl=0
if [[ -e /etc/alpine-release ]] || ls /lib/ld-musl-* >/dev/null 2>&1 \
   || { have ldd && ldd --version 2>&1 | grep -qi musl; } || [[ ${OS_ID:-} == alpine ]]; then
    is_musl=1
fi
sshver=""; have ssh && sshver=$(ssh -V 2>&1 | head -n1)
[[ -n $sshver ]] && info "OpenSSH banner (info only; Alpine backports within a version string): $sshver"
if (( ! is_musl )); then
    ok "not applicable: non-musl/glibc system (Debian/Ubuntu/RHEL/Fedora are not affected by sshole)"
else
    hit "musl libc detected (Alpine/musl) -> sshole preconditions are possible; checking PAM + password auth"
    sshd_bin=$(command -v sshd 2>/dev/null); [[ -z $sshd_bin && -x /usr/sbin/sshd ]] && sshd_bin=/usr/sbin/sshd
    pam_linked=unknown
    if [[ -n $sshd_bin ]] && have ldd; then
        ldd "$sshd_bin" 2>/dev/null | grep -qi 'libpam' && pam_linked=yes || pam_linked=no
    fi
    eff_pw=""; eff_pam=""
    if (( AM_ROOT )) && [[ -n $sshd_bin ]]; then       # sshd -T = authoritative effective config (local, no network)
        eff=$("$sshd_bin" -T 2>/dev/null)
        [[ -n $eff ]] && {
            eff_pw=$(awk 'tolower($1)=="passwordauthentication"{print tolower($2);exit}' <<<"$eff")
            eff_pam=$(awk 'tolower($1)=="usepam"{print tolower($2);exit}' <<<"$eff")
        }
    fi
    if [[ -r /etc/ssh/sshd_config ]]; then
        [[ -z $eff_pw ]]  && eff_pw=$(awk  'BEGIN{IGNORECASE=1}/^[[:space:]]*match([[:space:]]|$)/{s=1}!s&&tolower($1)=="passwordauthentication"{print tolower($2);exit}' /etc/ssh/sshd_config)
        [[ -z $eff_pam ]] && eff_pam=$(awk 'BEGIN{IGNORECASE=1}/^[[:space:]]*match([[:space:]]|$)/{s=1}!s&&tolower($1)=="usepam"{print tolower($2);exit}' /etc/ssh/sshd_config)
    fi
    eff_pw=${eff_pw:-yes}          # OpenSSH default PasswordAuthentication=yes
    eff_pam=${eff_pam:-no}         # upstream default UsePAM=no; and no-PAM build cannot use PAM anyway
    pam_in_use=no; [[ $pam_linked == yes && $eff_pam == yes ]] && pam_in_use=yes
    info "sshd PAM-linked=$pam_linked  UsePAM=$eff_pam  ->  PAM in use: $pam_in_use"
    info "PasswordAuthentication (effective): $eff_pw"
    if [[ $pam_in_use == no && $eff_pw != no ]]; then
        hit "POTENTIALLY VULNERABLE to CVE-2026-123158 (sshole): musl + PAM not in use + password auth enabled"
        if (( AM_ROOT )); then
            while IFS=: read -r acct _ auid _ _ ahome ashell; do
                [[ $auid =~ ^[0-9]+$ ]] || continue
                is_interactive_shell "$ashell" || continue
                if have getent; then ent=$(getent shadow "$acct" 2>/dev/null); else ent=$(grep "^${acct}:" /etc/shadow 2>/dev/null); fi
                [[ -z $ent ]] && continue
                h=${ent#*:}; h=${h%%:*}
                case $h in
                    '')        hit "  target account: $acct ($ashell) - EMPTY password (no password set)" ;;
                    '!'*|'*'*) hit "  target account: $acct ($ashell) - locked/disabled password (key-only style)" ;;
                esac
            done < <(cat /etc/passwd 2>/dev/null)
        else
            dim "run as root to list the password-disabled accounts an attacker could land on (reads /etc/shadow)"
        fi
        hit "FIX: 'apk upgrade -U openssh' (>= fixed branch pkg / OpenSSH 10.6p2) then restart sshd; or set 'PasswordAuthentication no'"
    elif [[ $eff_pw == no ]]; then
        ok "not exposed: PasswordAuthentication=no (password logins disabled)"
    elif [[ $pam_in_use == yes ]]; then
        ok "not exposed: PAM is in use (UsePAM yes and sshd linked to libpam)"
    else
        dim "exposure undetermined; as root run: sshd -T | grep -iE 'passwordauthentication|usepam'"
    fi
    dim "Official check (as root): sshd -T | grep -iE 'passwordauthentication|usepam' - not exposed if password off or PAM on."
fi

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
# 4b. NFS EXPORTS + NETWORK MOUNTS (server exports, root squashing, fstab, live)
# ===========================================================================
section "NFS EXPORTS & NETWORK MOUNTS"
# Network filesystem types checked in /etc/fstab and /proc/self/mounts.
NETFS_RE='nfs|nfs4|cifs|smb3|smbfs|fuse\.sshfs|sshfs|glusterfs|ceph|fuse\.ceph|davfs'
declare -A NFS_SEEN=()        # "path|client" -> normalized option state (config vs live drift)
declare -A NFS_VULN_KEYS=()   # "path|client" already counted as squash-vulnerable
NFS_VULN_LIST=()

# Parse an NFS export option string into NFS_* globals. Starts from the
# exports(5) defaults (ro, root_squash, no_all_squash, secure, sec=sys); later
# options override earlier ones, so "-defaults,client-opts" merges correctly.
nfs_parse_opts() {
    local o; local -a ol=()
    NFS_RSQ=1 NFS_ASQ=0 NFS_RW=0 NFS_SECURE=1 NFS_AUID= NFS_AGID= NFS_SEC=sys
    IFS=, read -ra ol <<<"$1"
    for o in ${ol[@]+"${ol[@]}"}; do
        case $o in
            root_squash) NFS_RSQ=1 ;;  no_root_squash) NFS_RSQ=0 ;;
            all_squash)  NFS_ASQ=1 ;;  no_all_squash)  NFS_ASQ=0 ;;
            rw) NFS_RW=1 ;;            ro) NFS_RW=0 ;;
            secure) NFS_SECURE=1 ;;    insecure) NFS_SECURE=0 ;;
            anonuid=*) NFS_AUID=${o#*=} ;;
            anongid=*) NFS_AGID=${o#*=} ;;
            sec=*)     NFS_SEC=${o#*=} ;;
        esac
    done
}
# True when the export accepts AUTH_SYS (client-asserted UIDs). /proc/fs/nfsd
# shows flavours numerically (1 = sys).
nfs_sec_sys() { case ":$NFS_SEC:" in *:sys:*|*:1:*|*:none:*|*:null:*) return 0 ;; esac; return 1; }
nfs_world()   { case $1 in '*'|'<world>'|'0.0.0.0/0'|'0.0.0.0/0.0.0.0'|'::/0') return 0 ;; esac; return 1; }
# Option state that matters for the checks below, used to spot config/live drift.
nfs_state() {
    local a=0 g=0; [[ $NFS_AUID == 0 ]] && a=1; [[ $NFS_AGID == 0 ]] && g=1
    printf 'rsq=%s asq=%s rw=%s secure=%s anonuid0=%s anongid0=%s' \
        "$NFS_RSQ" "$NFS_ASQ" "$NFS_RW" "$NFS_SECURE" "$a" "$g"
}

# nfs_check_squash PATH CLIENT OPTS
# Flags an export whose root squashing is disabled or defeated:
#   no_root_squash            -> client root is UID 0 on the share
#   root_squash + anonuid=0   -> root is "squashed" straight back to root
#   all_squash  + anonuid=0   -> every client user becomes root
#   anongid=0 while squashing -> squashed users land in the root group
# Prints its findings; returns 0 (true) when the export is vulnerable.
nfs_check_squash() {
    local who="$1 -> $2" vuln=1
    nfs_parse_opts "$3"
    if (( NFS_ASQ )); then
        if [[ $NFS_AUID == 0 ]]; then
            hit "$who: all_squash maps EVERY client user to anonuid=0 (root) - squashing gives no protection"; vuln=0
        else
            ok "$who: all_squash - every client user mapped to anonuid=${NFS_AUID:-nobody}"
        fi
    elif (( ! NFS_RSQ )); then
        hit "$who: no_root_squash - root squashing DISABLED; client root is UID 0 on this share"
        (( NFS_RW )) && hit "$who: rw + no_root_squash - client root can create root-owned and setuid files here"
        vuln=0
    elif [[ $NFS_AUID == 0 ]]; then
        hit "$who: root_squash maps client root to anonuid=0 - squashing has no effect"; vuln=0
    else
        ok "$who: root_squash in effect (client root -> anonuid=${NFS_AUID:-nobody})"
        (( NFS_RW )) && nfs_sec_sys && \
            dim "  note: rw + sec=sys - root_squash protects UID 0 only; all other UIDs/GIDs are client-asserted"
    fi
    if (( NFS_ASQ || NFS_RSQ )) && [[ $NFS_AGID == 0 ]]; then
        hit "$who: anongid=0 - squashed users land in GID 0 (root group)"; vuln=0
    fi
    return $vuln
}

# nfs_check_export SOURCE PATH CLIENT OPTS
nfs_check_export() {
    local src=$1 path=$2 client=$3 opts=$4 key="$2|$3"
    info "$path  ->  $client(${opts:-defaults})   [$src]"
    nfs_parse_opts "$opts"
    if nfs_world "$client"; then
        hit "$path -> $client: exported to ANY host"
    elif [[ $client == *[*?]* ]]; then
        dim "  wildcard client pattern: $client"
    fi
    (( NFS_SECURE )) || hit "$path -> $client: insecure - accepts requests from unprivileged (>1023) source ports"
    case $path in
        /|/etc|/etc/*|/root|/root/*|/boot|/boot/*|/usr|/var|/bin|/sbin|/lib|/lib64)
            if (( NFS_RW )); then hit "$path -> $client: sensitive system path exported read-write"
            else dim "  sensitive system path exported (read-only)"; fi ;;
    esac
    NFS_SEEN[$key]=$(nfs_state)
    if nfs_check_squash "$path" "$client" "$opts"; then
        if [[ -z ${NFS_VULN_KEYS[$key]+x} ]]; then
            NFS_VULN_KEYS[$key]=1
            NFS_VULN_LIST+=("$path -> $client  [$src]")
        fi
    fi
}

# One logical /etc/exports entry: PATH [-defaults] client[(opts)] ...
nfs_parse_export_line() {
    local src=$1 entry=$2 path rest t client copts defs="" n=0
    local -a toks=()
    entry=${entry#"${entry%%[![:space:]]*}"}                       # left-trim
    if [[ $entry == \"* ]]; then                                    # "quoted path with spaces"
        path=${entry#\"}; path=${path%%\"*}; rest=${entry#\"*\"}
    else
        path=${entry%%[[:space:]]*}; rest=${entry#"$path"}
    fi
    read -ra toks <<<"$rest"
    for t in ${toks[@]+"${toks[@]}"}; do
        if [[ $t == -* ]]; then defs+=${defs:+,}${t#-}; continue; fi   # default opts for later clients
        if [[ $t == \(* ]]; then
            # "path host (rw)": the space detaches the options from the host,
            # so they apply to every host while "host" gets the defaults.
            client='*'; copts=${t#\(}; copts=${copts%\)}
            hit "$src: '$path ... ($copts)' has options with no host (space before '(') -> they apply to EVERY host"
        elif [[ $t == *\(* ]]; then
            client=${t%%\(*}; copts=${t#*\(}; copts=${copts%\)}
        else
            client=$t; copts=""
        fi
        ((n++))
        nfs_check_export "$src" "$path" "$client" "${defs}${defs:+${copts:+,}}${copts}"
    done
    if (( n == 0 )); then
        hit "$src: $path has no client list -> exported to EVERY host with default options"
        nfs_check_export "$src" "$path" '*' "$defs"
    fi
}

# Read an exports(5) file: strip comments, join "\" continuations.
nfs_parse_exports_file() {
    local f=$1 line buf="" ln=0 start=0 entries=0
    while IFS= read -r line || [[ -n $line ]]; do
        ((ln++))
        [[ -z $buf ]] && start=$ln
        line=${line%%#*}
        if [[ $line == *\\ ]]; then buf+="${line%\\} "; continue; fi
        buf+=$line
        [[ $buf =~ ^[[:space:]]*$ ]] && { buf=""; continue; }
        ((entries++))
        nfs_parse_export_line "$f:$start" "$buf"
        buf=""
    done < "$f"
    (( entries )) || dim "no active entries in $f"
}

# nfs_check_mount SOURCE SPEC MOUNTPOINT FSTYPE OPTS  (client-side mount hygiene)
nfs_check_mount() {
    local src=$1 spec=$2 mp=$3 fstype=$4 opts=$5 o cf nosuid=0 nodev=0
    local -a ol=()
    info "$spec on $mp type $fstype ($opts)   [$src]"
    IFS=, read -ra ol <<<"$opts"
    for o in ${ol[@]+"${ol[@]}"}; do
        case $o in
            nosuid) nosuid=1 ;;  suid) nosuid=0 ;;
            nodev)  nodev=1 ;;   dev)  nodev=0 ;;
            user|users|owner)    # imply nosuid,nodev unless overridden later
                nosuid=1; nodev=1
                dim "  '$o': non-root users may mount/unmount this filesystem" ;;
            credentials=*|cred=*|IdentityFile=*)
                cf=${o#*=}
                if [[ -r $cf ]]; then hit "$mp: credential file $cf is READABLE by me"
                elif [[ -e $cf ]]; then dim "  credential file $cf (exists, not readable by me)"
                else dim "  credential file $cf (not found)"; fi ;;
            password=*|pass=*|password2=*)
                hit "$mp: inline credential in $src: $o" ;;
        esac
    done
    (( nosuid )) || hit "$mp: mounted without nosuid - setuid files on the remote share are honoured on this host"
    (( nodev ))  || dim "  $mp: no nodev - device files on the share are honoured"
}

sub "NFS server status"
nfs_srv=0
ps -e -o comm= 2>/dev/null | grep -qx nfsd && nfs_srv=1
if have systemctl; then
    for u in nfs-server nfs-kernel-server; do
        systemctl is-active --quiet "$u" 2>/dev/null && nfs_srv=1
    done
fi
if (( nfs_srv )); then info "NFS server is RUNNING on this host"
else info "NFS server not running (exports below are configured but not currently served)"; fi

sub "/etc/exports"
check_perm /etc/exports 644
[[ -e /etc/exports && -w /etc/exports ]] && hit "/etc/exports is WRITABLE by me -> can add an export"
if [[ -r /etc/exports ]]; then
    nfs_parse_exports_file /etc/exports
elif [[ -e /etc/exports ]]; then
    dim "not readable"
fi

if [[ -d /etc/exports.d ]]; then
    sub "/etc/exports.d/*.exports"
    [[ -w /etc/exports.d ]] && hit "/etc/exports.d is WRITABLE by me -> can drop in an export"
    nfs_dropins=0
    for f in /etc/exports.d/*.exports; do
        [[ -e $f ]] || continue
        ((nfs_dropins++))
        check_perm "$f" 644
        [[ -w $f ]] && hit "$f is WRITABLE by me"
        if [[ -r $f ]]; then nfs_parse_exports_file "$f"; else dim "not readable"; fi
    done
    (( nfs_dropins )) || dim "no *.exports files"
fi

sub "active export table (what is being served now)"
nfs_live="" nfs_live_src=""
for f in /var/lib/nfs/etab /proc/fs/nfsd/exports; do
    [[ -r $f ]] || continue
    nfs_live=$(grep -vE '^[[:space:]]*(#|$)' "$f" 2>/dev/null)   # /proc files report size 0; read, don't -s
    [[ -n $nfs_live ]] && { nfs_live_src=$f; break; }
done
if [[ -n $nfs_live ]]; then
    dim "source: $nfs_live_src (effective options, defaults expanded)"
    while IFS= read -r l; do
        l_path=${l%%[[:space:]]*}
        read -ra l_toks <<<"${l#"$l_path"}"
        for t in ${l_toks[@]+"${l_toks[@]}"}; do
            [[ $t == *\(* ]] || continue
            l_client=${t%%\(*}; l_opts=${t#*\(}; l_opts=${l_opts%\)}
            [[ -z $l_client ]] && l_client='*'
            l_key="$l_path|$l_client"
            nfs_parse_opts "$l_opts"; l_state=$(nfs_state)
            if [[ -z ${NFS_SEEN[$l_key]+x} ]]; then
                hit "$l_path -> $l_client: served but not in the config files (added at runtime via exportfs?)"
                nfs_check_export "$nfs_live_src" "$l_path" "$l_client" "$l_opts"
            elif [[ ${NFS_SEEN[$l_key]} != "$l_state" ]]; then
                hit "$l_path -> $l_client: live options differ from config (edited without 'exportfs -ra'?)"
                nfs_check_export "$nfs_live_src" "$l_path" "$l_client" "$l_opts"
            else
                ok "$l_path -> $l_client: live options match config (findings above apply)"
            fi
        done
    done <<<"$nfs_live"
else
    dim "nothing exported (empty or unreadable /var/lib/nfs/etab and /proc/fs/nfsd/exports)"
fi

if have showmount; then
    sub "showmount -e localhost (loopback query to the local mountd)"
    if have timeout; then o=$(timeout 5 showmount -e localhost 2>/dev/null)
    else o=$(showmount -e localhost 2>/dev/null); fi
    [[ -n $o ]] && printf '%s\n' "$o" | cap | indent || dim "no answer (mountd not running, NFSv4-only server, or filtered)"
else
    missing showmount
fi

sub "root-squash summary"
if (( ${#NFS_VULN_LIST[@]} )); then
    hit "${#NFS_VULN_LIST[@]} export(s) with root squashing disabled or defeated:"
    printf '%s\n' "${NFS_VULN_LIST[@]}" | sed 's/^/        /'
else
    ok "no exports with root squashing disabled or defeated"
fi

sub "/etc/fstab - network filesystems (this host as client)"
check_perm /etc/fstab 644
[[ -w /etc/fstab ]] && hit "/etc/fstab is WRITABLE by me -> can add mounts (e.g. without nosuid)"
if [[ -r /etc/fstab ]]; then
    nfs_fs=0
    while read -r spec mp fstype mopts _; do
        [[ -z ${spec:-} || $spec == \#* ]] && continue
        [[ $fstype =~ ^($NETFS_RE)$ || ( $fstype == fuse && $spec == sshfs\#* ) ]] || continue
        ((nfs_fs++))
        nfs_check_mount /etc/fstab "$spec" "$mp" "$fstype" "${mopts:-defaults}"
    done < /etc/fstab
    (( nfs_fs )) || dim "no network filesystems in /etc/fstab"
else
    dim "not readable"
fi

sub "network filesystems mounted now (/proc/self/mounts)"
if [[ -r /proc/self/mounts ]]; then
    nfs_mnt=0
    while read -r spec mp fstype mopts _; do
        [[ $fstype =~ ^($NETFS_RE)$ || ( $fstype == fuse && $spec == sshfs\#* ) ]] || continue
        ((nfs_mnt++))
        nfs_check_mount /proc/mounts "$spec" "$mp" "$fstype" "$mopts"
        mpd=$(printf '%b' "$mp")                     # decode \040-style escapes
        [[ -w $mpd ]] && dim "  mount point $mpd is WRITABLE by me"
    done < /proc/self/mounts
    (( nfs_mnt )) || dim "no network filesystems currently mounted"
else
    dim "/proc/self/mounts not readable"
fi

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
shopt -s nocasematch                 # match $SENSITIVE_RE case-insensitively
for hf in "$MY_HOME/.bash_history" "$MY_HOME/.zsh_history" "$MY_HOME/.sh_history" \
          "$MY_HOME/.ash_history" "$MY_HOME/.local/share/fish/fish_history" \
          "$MY_HOME/.python_history" "$MY_HOME/.mysql_history" "$MY_HOME/.psql_history" \
          "$MY_HOME/.rediscli_history" "$MY_HOME/.lesshst"; do
    [[ -r $hf ]] || continue
    found=1
    sub "$hf"
    # Print the whole file; tag EVERY line that looks credential-bearing, and
    # mark later identical occurrences as duplicates (first occurrence wins).
    # Read in the current shell (not a subshell) so the seen-map persists.
    declare -A _seen=()
    ln=0
    while IFS= read -r line || [[ -n $line ]]; do
        ((ln++))
        if [[ $line =~ $SENSITIVE_RE ]]; then
            if [[ -n ${_seen[$line]:-} ]]; then
                printf '      %s[sensitive][duplicate of line %s]%s %s\n' "$C_HIT" "${_seen[$line]}" "$C_RST" "$line"
            else
                _seen[$line]=$ln
                printf '      %s[sensitive]%s %s\n' "$C_HIT" "$C_RST" "$line"
            fi
        else
            printf '      %s\n' "$line"
        fi
    done < "$hf"
    unset _seen
done
shopt -u nocasematch
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

# --- Installed-package inventory to CSV (the only file this script writes) ---
# Emits one row per package across every package source present, with proper
# RFC-4180 quoting, into ./sysrecon-packages-<host>-<timestamp>.csv. Opt out
# with --no-csv to keep the run strictly read-only.
if (( WRITE_CSV )); then
    sub "CSV export (installed applications + versions)"
    csv_host=$(hostname 2>/dev/null); csv_host=${csv_host:-host}; csv_host=${csv_host//[^A-Za-z0-9_.-]/_}
    csv_ts=$(date +%Y%m%d-%H%M%S 2>/dev/null); csv_ts=${csv_ts:-output}
    csv_path="./sysrecon-packages-${csv_host}-${csv_ts}.csv"
    if : > "$csv_path" 2>/dev/null; then
        {
            printf 'source,name,version\n'
            if is_debian && have dpkg-query; then
                dpkg-query -W -f='${Package}\t${Version}\n' 2>/dev/null \
                  | while IFS=$'\t' read -r n v; do printf '%s,%s,%s\n' dpkg "$(csv_escape "$n")" "$(csv_escape "$v")"; done
            elif is_redhat && have rpm; then
                rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' 2>/dev/null \
                  | while IFS=$'\t' read -r n v; do printf '%s,%s,%s\n' rpm "$(csv_escape "$n")" "$(csv_escape "$v")"; done
            fi
            have snap    && snap list 2>/dev/null | awk 'NR>1 && NF>=2 {print $1"\t"$2}' \
                  | while IFS=$'\t' read -r n v; do printf '%s,%s,%s\n' snap "$(csv_escape "$n")" "$(csv_escape "$v")"; done
            have flatpak && flatpak list --columns=application,version 2>/dev/null \
                  | while IFS=$'\t' read -r n v; do [[ -n $n ]] && printf '%s,%s,%s\n' flatpak "$(csv_escape "$n")" "$(csv_escape "$v")"; done
            have pip3    && pip3 list --format=freeze 2>/dev/null \
                  | while IFS= read -r line; do n=${line%%==*}; v=${line#*==}; [[ -n $n && $n != "$line" ]] && printf '%s,%s,%s\n' pip3 "$(csv_escape "$n")" "$(csv_escape "$v")"; done
        } >> "$csv_path" 2>/dev/null
        rows=$(( $(wc -l < "$csv_path" 2>/dev/null) - 1 )); (( rows < 0 )) && rows=0
        ok "installed-package inventory written: $csv_path  ($rows rows)"
        dim "columns: source,name,version (RFC-4180 quoted). This is the only file sysrecon writes; suppress with --no-csv."
    else
        hit "cannot write CSV to the current directory ($(pwd 2>/dev/null)) - skipping (cd to a writable dir, or pass --no-csv)"
    fi
fi

# ===========================================================================
# 15. RUNNING APPLICATIONS + PORT CORRELATION
# ===========================================================================
section "RUNNING APPS & LISTENING PORTS"
if have ss; then
    sub "listening sockets with owning process (ss -tulnp)"
    ss -tulnp 2>/dev/null | indent
    sub "port -> service/process map"
    printf '      %-5s %-22s %-20s %s\n' PROTO LOCAL SERVICE PROCESS
    ss -tulnp 2>/dev/null | awk 'NR>1 {
        proto=$1; local=$5; line=$0;
        # Parse each ("name",pid=NNN,fd=..) entry out of the users:((...)) blob,
        # grouping pids under their process name so multi-worker daemons
        # (httpd, nginx) show as name(pid1,pid2,...) once instead of repeating.
        # Scanning $0 (not $NF) also survives process names that contain spaces.
        # split("",arr) clears per-record and stays POSIX-portable (mawk/busybox).
        split("", pids); split("", order); n=0;
        while (match(line, /"[^"]+",(pid=)?[0-9]+/)) {
            tok=substr(line, RSTART, RLENGTH); line=substr(line, RSTART+RLENGTH);
            name=substr(tok, 2); name=substr(name, 1, index(name, "\"")-1);
            pid=tok; sub(/^"[^"]+",/, "", pid); sub(/^pid=/, "", pid);
            if (name in pids) pids[name]=pids[name] "," pid;
            else { order[++n]=name; pids[name]=pid; }
        }
        out="";
        for (i=1; i<=n; i++) out=(out=="" ? "" : out ",") order[i] "(" pids[order[i]] ")";
        if (out=="") out="-";   # no privilege to see owner, or kernel socket
        print proto "\t" local "\t" out
    }' | while IFS=$'\t' read -r proto local proc; do
        port=${local##*:}
        svc=$(service_name "$port" "$proto"); [[ -n $svc ]] || svc="-"
        printf '      %-5s %-22s %-20s %s\n' "$proto" "$local" "$svc" "$proc"
    done
    dim "SERVICE = typical assignment for that port (static snapshot), not a check of what is actually bound."
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
# Keep only the leading digits of each component so rc/custom version strings
# (e.g. 5.15.0rc1) don't abort the base-10 arithmetic below with an empty knum.
kmaj=${kmaj%%[!0-9]*}; kmin=${kmin%%[!0-9]*}; kpatch=${kpatch%%[!0-9]*}
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
# 20. SYSTEMD SERVICES - STATE / BOOT / RUN-AS / EXEC PATH
#     For every discovered service unit: its current state, whether it starts
#     on boot, the user it actually runs under (correlated to the live MainPID
#     via ps, else the configured identity), whether it sets an explicit
#     User=/Group= and DynamicUser, and the ExecStart command grepped straight
#     from the unit file. Non-absolute (relative/specifier) ExecStart paths and
#     user-writable ExecStart binaries are highlighted as hijack/tamper vectors.
# ===========================================================================
section "SYSTEMD SERVICES - STATE / BOOT / RUN-AS / EXEC"
if have systemctl; then
    # Union of units that have a unit file (incl. enabled-but-stopped) and units
    # currently loaded, so nothing bootable or transient is missed.
    mapfile -t SVC_UNITS < <(
        { systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null | awk '{print $1}'
          systemctl list-units      --type=service --all --no-legend --no-pager 2>/dev/null | awk '{print $1}'
        } | grep -E '\.service$' | sort -u
    )
    if (( ${#SVC_UNITS[@]} == 0 )); then
        dim "no service units enumerated"
    else
        sub "per-service inventory (state / boot / run-as / identity / ExecStart)"
        printf '      %-30s %-16s %-9s %-14s %-6s %s\n' UNIT STATE BOOT RUN-AS ID EXEC
        RELATIVE_EXEC=(); ROOT_NOISO=(); WRITABLE_EXEC=()
        svc_count=0
        for svc in "${SVC_UNITS[@]}"; do
            [[ -n $svc ]] || continue
            (( FULL )) || { (( svc_count >= FIND_CAP )) && { dim "... (capped at $FIND_CAP services; --full for all)"; break; }; }
            ((svc_count++))

            # One show call per unit, parsed Key=Value into an assoc array.
            declare -A S=()
            while IFS= read -r kv; do
                [[ $kv == *=* ]] || continue
                S[${kv%%=*}]=${kv#*=}
            done < <(systemctl show "$svc" --no-pager \
                        -p Id -p LoadState -p ActiveState -p SubState -p UnitFileState \
                        -p User -p Group -p DynamicUser -p MainPID -p FragmentPath \
                        -p DropInPaths -p ExecStart 2>/dev/null)

            state="${S[ActiveState]:-?}/${S[SubState]:-?}"
            boot=${S[UnitFileState]:-?}
            cfg_user=${S[User]:-}; cfg_group=${S[Group]:-}
            dynuser=${S[DynamicUser]:-no}; dynuser=${dynuser,,}
            mainpid=${S[MainPID]:-0}; [[ $mainpid =~ ^[0-9]+$ ]] || mainpid=0

            # Identity posture (the explicit-User/Group + DynamicUser check),
            # compacted into one cell: U+G = both set, U / G = one set,
            # dyn = DynamicUser=yes, root = none set and DynamicUser=no.
            if [[ $dynuser == yes ]]; then
                idset="dyn"
            else
                idset=""
                [[ -n $cfg_user ]]  && idset="U"
                [[ -n $cfg_group ]] && idset="${idset:+$idset+}G"
                [[ -z $idset ]]     && idset="root"
            fi

            # Run-as user: prefer the live process; fall back to the configured
            # User= / DynamicUser / systemd default (root). A trailing '*' marks
            # a value taken from config rather than observed on a running PID.
            runas=""
            if (( mainpid > 0 )); then
                runas=$(ps -o user= -p "$mainpid" 2>/dev/null | awk 'NR==1{print $1}')
                [[ -z $runas && -r /proc/$mainpid/status ]] && {
                    ruid=$(awk '/^Uid:/{print $2; exit}' "/proc/$mainpid/status" 2>/dev/null)
                    [[ -n $ruid ]] && runas=$(id -nu "$ruid" 2>/dev/null || printf 'uid=%s' "$ruid")
                }
            fi
            if [[ -z $runas ]]; then
                if   [[ -n $cfg_user ]];    then runas="${cfg_user}*"
                elif [[ $dynuser == yes ]]; then runas="dynamic*"
                else                             runas="root*"; fi
            fi

            # ExecStart tokens grepped straight from the unit file + drop-ins
            # (strip the leading special prefixes @ - + ! : systemd allows).
            execfiles=()
            [[ -n ${S[FragmentPath]:-} ]] && execfiles+=("${S[FragmentPath]}")
            if [[ -n ${S[DropInPaths]:-} ]]; then read -ra _di <<<"${S[DropInPaths]}"; execfiles+=("${_di[@]}"); fi
            raw_tokens=()
            if (( ${#execfiles[@]} )); then
                mapfile -t raw_tokens < <(
                    grep -hE '^[[:space:]]*ExecStart[[:space:]]*=' "${execfiles[@]}" 2>/dev/null \
                      | sed -E 's/^[[:space:]]*ExecStart[[:space:]]*=[[:space:]]*//; s/^[-@+!:]+//' \
                      | awk '{print $1}' | sed '/^$/d'
                )
            fi
            # Resolved binary path as systemd parsed it (for the writable check).
            execresolved=$(sed -n 's/.*[ {]path=\([^ ;]*\).*/\1/p' <<<"${S[ExecStart]:-}" | head -n1)
            first_exec=${raw_tokens[0]:-$execresolved}
            exec_disp=${first_exec:--}
            (( ${#raw_tokens[@]} > 1 )) && exec_disp+=" (+$((${#raw_tokens[@]}-1)))"

            row_hit=0
            # Non-absolute ExecStart token -> PATH-resolution / tamper risk.
            for tok in ${raw_tokens[@]+"${raw_tokens[@]}"}; do
                case $tok in
                    /*) ;;
                    %*) RELATIVE_EXEC+=("$svc  ExecStart uses a systemd specifier path: $tok"); row_hit=1 ;;
                    *)  RELATIVE_EXEC+=("$svc  ExecStart uses a NON-absolute path: $tok");      row_hit=1 ;;
                esac
            done
            # Resolved ExecStart binary writable by me -> direct code-exec vector.
            [[ -z $execresolved && $first_exec == /* ]] && execresolved=$first_exec
            if [[ -n $execresolved && $execresolved == /* && -w $execresolved ]]; then
                WRITABLE_EXEC+=("$svc  ExecStart binary WRITABLE by me: $execresolved (runs as ${runas%\*})"); row_hit=1
            fi
            # Active/enabled service with no explicit User= and DynamicUser=no
            # -> runs as unconfined root (the specific posture asked about).
            if [[ -z $cfg_user && $dynuser != yes ]] \
               && { [[ ${S[ActiveState]:-} == active ]] || [[ $boot == enabled ]]; }; then
                grp_note=""; [[ -n $cfg_group ]] && grp_note=" Group=$cfg_group"
                ROOT_NOISO+=("$svc  no User=, DynamicUser=no${grp_note}  (state=$state boot=$boot exec=${first_exec:-?})")
            fi

            line=$(printf '%-30.30s %-16.16s %-9.9s %-14.14s %-6.6s %s' \
                   "$svc" "$state" "$boot" "$runas" "$idset" "$exec_disp")
            if (( row_hit )); then hit "$line"; else info "$line"; fi
            unset S
        done
        dim "RUN-AS '*' = from unit config (service not live); no '*' = observed on the running MainPID. STATE=ActiveState/SubState, BOOT=UnitFileState."
        dim "ID (identity posture): U+G=explicit User and Group, U/G=only one set, dyn=DynamicUser=yes, root=no User/Group and DynamicUser=no (unconfined root)."

        sub "ExecStart commands with NON-absolute paths (relative / specifier)"
        if (( ${#RELATIVE_EXEC[@]} )); then
            printf '%s\n' "${RELATIVE_EXEC[@]}" | sort -u | while IFS= read -r l; do hit "$l"; done
            dim "A relative or bare-name ExecStart is resolved via systemd's own PATH - a hijack vector if any PATH dir is writable."
        else
            ok "every ExecStart in the scanned units uses an absolute path"
        fi

        sub "ExecStart executables writable by current user"
        if (( ${#WRITABLE_EXEC[@]} )); then
            printf '%s\n' "${WRITABLE_EXEC[@]}" | sort -u | while IFS= read -r l; do hit "$l"; done
        else
            dim "none of the scanned ExecStart binaries are writable by ${ME:-this user}"
        fi

        sub "services effectively running as root (no explicit User=, DynamicUser=no)"
        if (( ${#ROOT_NOISO[@]} )); then
            printf '%s\n' "${ROOT_NOISO[@]}" | sort -u | cap | while IFS= read -r l; do info "$l"; done
            dim "Expected for many core daemons; listed so the root-privileged attack surface is explicit. An explicit User=/Group= or DynamicUser=yes shrinks it."
        else
            ok "no active/enabled service runs as unconfined root (all set User= or DynamicUser=yes)"
        fi
    fi
else
    missing systemctl
    [[ -d /etc/init.d ]] && { sub "SysV init scripts (no systemd)"; ls -la /etc/init.d 2>/dev/null | indent; }
fi

# ===========================================================================
# 21. SYSTEM DAEMONS - sensitive information
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
            grep -oiE "(${SENSITIVE_RE})[^ ]*" <<<"$env" | sed 's/^/        /'
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
