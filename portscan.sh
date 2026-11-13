#!/usr/bin/env bash
#
# portscan.sh - Nmap-style TCP connect / UDP scanner with banner grabbing.
#
# TCP is built on nc. It works with every netcat that Debian, Ubuntu and RHEL-family systems ship:
# netcat-openbsd, netcat-traditional and Nmap's ncat. They disagree on flags and
# on what happens at stdin EOF, so this script sticks to what they share:
#   * -n and -w are common to all of them.
#   * The connect test uses -z, or --send-only on old ncat (RHEL 7) without -z.
#   * Banner reads send the payload and then close stdin. Every flavour keeps
#     reading after that (ncat only with --no-shutdown, which is used when it
#     is available). timeout(1) ends every read, because -w means "idle
#     timeout" on some flavours and "connect timeout" on others.
#
# Requires bash 4.0+, coreutils, awk, xargs and getent. A static `nc` binary
# placed in the directory the script is called from is preferred over any nc on
# PATH (handy on locked-down targets with no netcat, or an incompatible libc).
# If no netcat is found at all, it falls back to bash's built-in /dev/tcp.
#
# UDP (-sU) does not use nc. Each probe uses a connected socket from bash's
# /dev/udp, sends the request with dd and reads one reply with dd. A connected
# socket turns an ICMP port-unreachable into ECONNREFUSED on the next send or
# receive, so closed ports can be told apart from silent ones. The nc flavours
# report that ICMP differently (or not at all), so going through nc would lose it.
# Ports whose services only answer a well-formed request get one (see
# udp_payloads); every other port gets a short generic datagram.

# Runs before anything bash-4-specific, and is plain POSIX sh so the message
# still comes out under sh or an old bash. Every helper process (xargs workers,
# the /dev/tcp and /dev/udp probes) is started as "$BASH", this same bash.
if [ -z "${BASH_VERSION:-}" ] || [ "${BASH_VERSINFO:-0}" -lt 4 ]; then
    echo "${0##*/}: requires bash 4.0 or newer (running: ${BASH_VERSION:-not bash})" >&2
    exit 2
fi

PROG=${0##*/}
# Directory the script was invoked from. A static nc dropped here is preferred
# over system netcat; captured once up front since the script never chdir's.
CALLDIR=$PWD
TIMEOUT=2           # seconds allowed for a connect, and for each banner read
JOBS=50             # concurrent probes
MAX_HOSTS=65536     # largest target list accepted (a /16)
BANNER_MAX=120      # banner characters shown
HTTP_PROBE='HEAD / HTTP/1.0\r\n\r\n'
PROTO=tcp           # tcp, or udp with -sU (passed to getopts as -u)
SHOW_REASON=0       # 1 with --reason (passed to getopts as -r)
UDP_LIST_MAX=25     # per host, list at most this many open|filtered (or filtered)
                    # UDP ports individually; above it they are only counted

IPV4='[0-9]{1,3}(\.[0-9]{1,3}){3}'

declare -A seen_ips
host_ips=()
host_labels=()
targets=()

usage() {
    cat <<EOF
Usage: $PROG -p <port[s]> [-sU] [--reason] [-t seconds] [-j jobs] <target> [target...]

Ports (-p):
  22                  single port
  22,80,443           list
  1-1024              range
  22,80,8000-8100     any mix
  -                   all ports (1-65535)

Targets:
  192.168.1.10                  IPv4 address
  scanme.example.com            hostname (first IPv4 address is used)
  192.168.1.0/24                CIDR block
  192.168.1.1-50                octet range; lists also work: 10.0.1-3.1,5,9
  192.168.1.250-192.168.2.10    full address range
  10.0.0.1,10.0.0.9,host.lan    comma-separated mix of the above

Options:
  -sU           scan UDP instead of TCP
  --reason      show why each port is in its state (as nmap --reason does):
                a REASON column, and the reasons behind ports not shown
  -t seconds    connect and banner timeout; for UDP, how long to wait for a
                reply (default: $TIMEOUT)
  -j jobs       concurrent probes (default: $JOBS)
  -h            show this help

While scanning, a progress line (probes done, open so far, elapsed, time
left) is shown on stderr when stderr is a terminal.

UDP states (-sU):
  open            the port sent a reply
  open|filtered   no reply: the port may be open but ignored the probe, or
                  a firewall dropped it
  filtered        the kernel reported an ICMP error on the socket other than
                  port-unreachable: admin-prohibited (codes 9, 10, 13, e.g.
                  firewalld's default REJECT) or protocol-unreachable. Plain
                  host/net-unreachable (codes 0, 1) are not reported for UDP
                  on Linux, so those ports show as open|filtered.
  closed          ICMP port-unreachable came back (not listed, only counted)
  Probes this machine could not send (no route, a broadcast address, a local
  firewall) are not a port state: they are counted as local errors.
  Linux sends a scanner only about one port-unreachable per second after a
  short burst, and other systems rate-limit them too. On a large UDP scan many
  closed ports therefore show as open|filtered. For accurate closed vs
  open|filtered results, scan fewer ports or use a low -j.

Examples:
  $PROG -p 22,80,443 192.168.1.10
  $PROG -p 1-1024 -t 1 -j 100 192.168.1.0/24 web01.lan
  $PROG -sU -p 53,123,161,500,1900 192.168.1.0/24
EOF
}

# First argument is the message; any further arguments are printed as indented
# continuation lines rather than being mashed onto one line.
warn() {
    printf '%s: %s\n' "$PROG" "$1" >&2
    shift
    (($#)) && printf '  %s\n' "$@" >&2
    return 0
}
die()  { warn "$@"; exit 2; }
have() { command -v "$1" >/dev/null 2>&1; }

# Typical service for a port number (STATIC SNAPSHOT, mirrors IANA / nmap-services
# common assignments). This is only the conventional occupant of the port - a hint,
# not a check of what is actually answering; trust the banner for that. Call as
# `service_name <port> [tcp|udp]`; prints a short name, or nothing if unknown.
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

# Print each number in a spec such as "1,3,7-9", rejecting anything outside
# min..max. Shared by port lists and IP octets.
expand_list() {
    local spec=$1 min=$2 max=$3 item lo hi i
    local IFS=,

    [[ -n $spec ]] || return 1
    for item in $spec; do
        [[ $item =~ ^([0-9]{1,5})(-([0-9]{1,5}))?$ ]] || return 1
        lo=$((10#${BASH_REMATCH[1]}))
        hi=$((10#${BASH_REMATCH[3]:-$lo}))
        ((lo >= min && hi <= max && lo <= hi)) || return 1
        for ((i = lo; i <= hi; i++)); do
            echo "$i"
        done
    done
}

add_host() {
    local ip=$1 label=${2:-$1}

    [[ -z ${seen_ips[$ip]} ]] || return 0
    ((${#host_ips[@]} < MAX_HOSTS)) ||
        die "too many targets (limit is $MAX_HOSTS addresses, a /16)"
    seen_ips[$ip]=1
    host_ips+=("$ip")
    host_labels+=("$label")
}

# Convert a dotted quad to an integer, or fail if an octet is over 255.
ip_to_int() {
    local a b c d
    IFS=. read -r a b c d <<<"$1"
    ((10#$a <= 255 && 10#$b <= 255 && 10#$c <= 255 && 10#$d <= 255)) || return 1
    echo $(((10#$a << 24) | (10#$b << 16) | (10#$c << 8) | 10#$d))
}

add_int_range() {
    local first=$1 last=$2 i

    # Reject an over-broad block up front instead of enumerating tens of
    # thousands of addresses only to abort partway through add_host.
    (( last - first + 1 <= MAX_HOSTS )) ||
        die "target range covers $((last - first + 1)) addresses (limit is $MAX_HOSTS, a /16)"
    for ((i = first; i <= last; i++)); do
        add_host "$((i >> 24 & 255)).$((i >> 16 & 255)).$((i >> 8 & 255)).$((i & 255))"
    done
}

add_cidr() {
    local base prefix=$2 mask size

    base=$(ip_to_int "$1") && ((prefix <= 32)) || die "invalid target: '$1/$2'"
    size=$((1 << (32 - prefix)))
    mask=$((0xFFFFFFFF ^ (size - 1)))
    add_int_range "$((base & mask))" "$(((base & mask) + size - 1))"
}

add_octets() {
    local spec=$1 a b c d w x y z

    IFS=. read -r a b c d <<<"$spec"
    a=$(expand_list "$a" 0 255) && b=$(expand_list "$b" 0 255) &&
        c=$(expand_list "$c" 0 255) && d=$(expand_list "$d" 0 255) ||
        die "invalid target: '$spec'"
    for w in $a; do
        for x in $b; do
            for y in $c; do
                for z in $d; do
                    add_host "$w.$x.$y.$z"
                done
            done
        done
    done
}

# Resolve a hostname to its first IPv4 address. Tries several tools so this
# works beyond glibc/getent (e.g. musl/Alpine, where 'getent ahostsv4' may be
# absent or empty): getent, then python3, host, dig.
resolve_ipv4() {
    local name=$1 ip=
    # 'getent hosts' may answer with IPv6 only (glibc asks for IPv6 first), so
    # every step keeps IPv4 results only; an IPv6 answer must not stop the
    # fallbacks below from running.
    local first_v4='$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { print $1; exit }'

    if have getent; then
        ip=$(getent ahostsv4 "$name" 2>/dev/null | awk "$first_v4")
        [[ -n $ip ]] || ip=$(getent hosts "$name" 2>/dev/null | awk "$first_v4")
    fi
    [[ -z $ip ]] && have python3 && ip=$(python3 -c \
        'import socket,sys
try: print(socket.getaddrinfo(sys.argv[1],None,socket.AF_INET)[0][4][0])
except Exception: pass' "$name" 2>/dev/null)
    [[ -z $ip ]] && have host && ip=$(host -t A "$name" 2>/dev/null |
        awk '/has address/ { print $NF; exit }')
    [[ -z $ip ]] && have dig && ip=$(dig +short A "$name" 2>/dev/null |
        awk '/^[0-9.]+$/ { print; exit }')

    [[ $ip =~ ^$IPV4$ ]] && printf '%s\n' "$ip"
}

add_hostname() {
    local name=$1 ip

    ip=$(resolve_ipv4 "$name")
    if [[ -z $ip ]]; then
        warn "could not resolve '$name', skipping"
        return 0
    fi
    add_host "$ip" "$name ($ip)"
}

add_target() {
    local target=$1 first last item
    local -a items

    if [[ $target =~ ^($IPV4)/([0-9]{1,2})$ ]]; then
        add_cidr "${BASH_REMATCH[1]}" "$((10#${BASH_REMATCH[3]}))"
    elif [[ $target =~ ^($IPV4)-($IPV4)$ ]]; then
        first=$(ip_to_int "${BASH_REMATCH[1]}") &&
            last=$(ip_to_int "${BASH_REMATCH[3]}") && ((first <= last)) ||
            die "invalid target: '$target'"
        add_int_range "$first" "$last"
    elif [[ $target =~ ^[0-9,-]+(\.[0-9,-]+){3}$ ]]; then
        add_octets "$target"
    elif [[ $target == *,* ]]; then
        IFS=, read -ra items <<<"$target"
        for item in "${items[@]}"; do
            add_target "$item"
        done
    elif [[ $target =~ ^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9.])?$ && $target == *[A-Za-z]* ]]; then
        add_hostname "$target"
    else
        die "invalid target: '$target' (expected IPv4 address, range, CIDR or hostname)"
    fi
}

find_nc() {
    # Prefer a static nc in the directory the script was called from ($CALLDIR,
    # an absolute path, so the xargs worker shells resolve it wherever they run).
    # Typical use: a netcat 1.10 build from github.com/H74N/netcat-binaries
    # dropped in the working directory and renamed to 'nc'. Note that whatever
    # 'nc' is there gets executed, so don't run this from a shared directory
    # such as /tmp.
    local local_nc="$CALLDIR/nc" probe help
    if [[ -x $local_nc ]]; then
        # Confirm it actually executes as netcat. A wrong-arch binary (the repo
        # ships both nc32 and nc64) keeps its +x bit but fails to exec, which
        # would otherwise be mistaken for a flavour without -z and silently make
        # every port read "closed". Its usage/help text identifies a real nc.
        probe=$("$local_nc" -h </dev/null 2>&1)
        if grep -qiE 'listen|zero-i/o|\[-options\]|usage' <<<"$probe"; then
            NC=$local_nc
            warn "using static nc from working directory: $NC"
        else
            warn "found $local_nc but it did not run as netcat" \
                 "(wrong architecture? the repo ships separate nc32/nc64); ignoring it"
        fi
    elif [[ -e $local_nc ]]; then
        warn "found $local_nc but it is not executable; run 'chmod +x nc' to use it"
    fi
    [[ -n $NC ]] || NC=$(command -v nc || command -v ncat || command -v netcat)
    if [[ -z $NC ]]; then
        warn "nc not found, falling back to bash /dev/tcp" \
            "(install with: apt-get install netcat-openbsd, or dnf install nmap-ncat)"
        return 0
    fi
    # netcat 1.10, OpenBSD nc and ncat 7+ advertise -z (zero-I/O scan); old
    # ncat (RHEL 7) has --send-only instead. A netcat with neither (e.g. a
    # minimal BusyBox build) would fail every probe and report every port
    # closed, so it is not used.
    if [[ $NC == "$local_nc" ]]; then
        help=$probe
    else
        help=$("$NC" -h </dev/null 2>&1)
    fi
    if grep -q -- '-z' <<<"$help"; then
        NC_CONNECT_FLAG=-z
    elif grep -q -- '--send-only' <<<"$help"; then
        NC_CONNECT_FLAG=--send-only
    else
        warn "$NC offers neither -z nor --send-only; falling back to bash /dev/tcp"
        NC= NC_CONNECT_FLAG=
        return 0
    fi
    # Help text can mislead, so confirm this netcat takes the flags as used.
    if ! nc_flags_work -v "$NC_CONNECT_FLAG"; then
        warn "$NC rejected '-v $NC_CONNECT_FLAG -n -w'; falling back to bash /dev/tcp"
        NC= NC_CONNECT_FLAG=
        return 0
    fi
    # Banner reads close stdin once the payload is sent. ncat answers that by
    # half-closing the socket (FIN), and a server that holds back its greeting
    # may hang up on it. --no-shutdown (newer ncat) keeps the connection fully
    # open, as the other flavours do by default.
    if grep -q -- '--no-shutdown' <<<"$help" && nc_flags_work --no-shutdown; then
        NC_READ_FLAG=--no-shutdown
    fi
}

# True if "$NC <flags> -n -w" runs as a connection. Aimed at a local port it
# must succeed or fail as a connection (open, refused or timed out, all fine),
# not with a usage error, unknown option or failure to execute.
nc_flags_work() {
    local out status

    # C locale: the patterns below are English, and getopt translates them.
    out=$(LC_ALL=C timeout 3 "$NC" "$@" -n -w 1 127.0.0.1 9 </dev/null 2>&1)
    status=$?
    ((status < 124)) &&
        ! grep -qiE 'usage|invalid option|unrecognized option|unknown option|illegal option' <<<"$out"
}

# Test whether ip:port accepts a TCP connection; the status says so. Prints
# what nc (-v, which every flavour has) or bash said about the attempt, such as
# "Connection refused" or "timed out", for port_reason to read. The C locale
# keeps that text in English: nc and bash print strerror(), which glibc
# translates under a non-English LANG.
port_is_open() {
    local ip=$1 port=$2

    if [[ -n $NC ]]; then
        LC_ALL=C timeout "$((TIMEOUT + 1))" "$NC" -v "$NC_CONNECT_FLAG" -n -w "$TIMEOUT" \
            "$ip" "$port" </dev/null 2>&1
    else
        LC_ALL=C timeout "$TIMEOUT" "$BASH" -c 'exec 3<>"/dev/tcp/$0/$1"' "$ip" "$port" 2>&1
    fi
}

# Why a port is in its state, as one token in the style of nmap --reason.
# Call as `port_reason <tcp|udp> <state> <exit status> [error text]`, where the
# error text is what nc, bash or dd reported for the probe. Prints one of:
#   syn-ack           TCP connection completed
#   conn-refused      TCP connection refused: a RST, or ICMP port unreachable
#   reset             TCP connection reset while connecting (not seen on
#                     Linux, where a RST during connect reads as refused)
#   udp-response      UDP reply received
#   port-unreach      ICMP port unreachable
#   admin-prohibited  ICMP administratively prohibited (UDP; see below)
#   host-unreach      ICMP host unreachable; over TCP also host-prohibited
#                     (e.g. firewalld's default REJECT), so not proof the
#                     host is down
#   net-unreach       network unreachable or prohibited
#   proto-unreach     ICMP protocol unreachable
#   no-response       nothing came back before the timeout
#   local-error       this machine could not send the probe
#   unknown           anything else
# The kernel only passes an errno, not the ICMP code, so codes sharing an errno
# share a token. A Linux TCP connect aborts on any ICMP unreachable, so code 1
# (host unreachable) and codes 10/13 (prohibited) all arrive as EHOSTUNREACH.
# A connected Linux UDP socket never reports code 1, so there EHOSTUNREACH can
# only mean codes 10, 13, 14 or 15: hence admin-prohibited.
port_reason() {
    local proto=$1 state=$2 status=$3 text=${4,,}

    case $proto:$state in
        tcp:open)            echo syn-ack;      return ;;
        udp:open)            echo udp-response; return ;;
        udp:closed)          echo port-unreach; return ;;
        'udp:open|filtered') echo no-response;  return ;;
        udp:error)           echo local-error;  return ;;
    esac
    # tcp:closed and udp:filtered: what was reported decides.
    if ((status == 124)); then
        echo no-response
        return
    fi
    case $text in
        *refused*)                               echo conn-refused ;;
        *reset*)                                 echo reset ;;
        *'timed out'*|*timeout*)                 echo no-response ;;
        *'no route to host'*)
            [[ $proto == udp ]] && echo admin-prohibited || echo host-unreach ;;
        *'host is down'*|*'not on the network'*) echo host-unreach ;;
        *'network is unreachable'*)              echo net-unreach ;;
        *'protocol not available'*)              echo proto-unreach ;;
        *'permission denied'*|*'not permitted'*) echo local-error ;;
        *)                                       echo unknown ;;
    esac
}

# Connect, optionally send a payload, and print what the service returns.
# bash's printf flushes at each newline, so the payload goes through cat to reach
# the socket as one write rather than in fragments.
read_service() {
    local ip=$1 port=$2 payload=$3 read_to=${4:-$TIMEOUT}

    # stdin hits EOF right after the payload. nc keeps reading the socket after
    # that (ncat thanks to $NC_READ_FLAG), so no background 'sleep' is needed to
    # hold stdin open; that only left a process lingering until the timeout.
    # timeout(1) ends the read whether or not the service closes first.
    if [[ -n $NC ]]; then
        timeout "$read_to" "$NC" ${NC_READ_FLAG:+"$NC_READ_FLAG"} -n -w "$read_to" "$ip" "$port" \
            < <(printf '%b' "$payload" | cat) 2>/dev/null
    else
        timeout "$read_to" "$BASH" -c \
            'exec 3<>"/dev/tcp/$0/$1"; printf "%b" "$2" | cat >&3; cat <&3' \
            "$ip" "$port" "$payload" 2>/dev/null
    fi
}

# Reduce raw service output to one safe line. Dropping control characters keeps
# binary protocols readable and stops a hostile service sending terminal escapes.
# Lines under 4 characters are skipped when a longer one exists, because binary
# greetings (such as MySQL's) often lead with a stray byte or two.
clean_banner() {
    LC_ALL=C tr -d '\000-\010\013-\037\177-\377' | tr '\t' ' ' | awk -v max="$BANNER_MAX" '
        NF && short == ""                  { short = $0 }
        NF && long == "" && length($0) >= 4 { long = $0 }
        tolower($0) ~ /^server:/           { server = $0 }
        END {
            line = (long != "") ? long : short
            if (line ~ /^HTTP\// && server != "") line = line " | " server
            print substr(line, 1, max)
        }'
}

# Probe one TCP port and print "index<TAB>port<TAB>state<TAB>reason<TAB>banner",
# where state is open or closed and reason comes from port_reason (never
# empty, so tab-splitting cannot shift the fields). Every probe prints exactly
# one line, which is what track_progress counts.
scan_port() {
    local index=$1 ip=$2 port=$3 banner greet_to said status

    said=$(port_is_open "$ip" "$port")
    status=$?
    if ((status != 0)); then
        printf '%s\t%s\tclosed\t%s\t\n' "$index" "$port" \
            "$(port_reason tcp closed "$status" "$said")"
        return 0
    fi

    # Most services that announce themselves do so on connect, within a round
    # trip. Give that connect-banner read only a short wait (capped at the
    # configured timeout, so a low -t is honoured and the default 2s is
    # unchanged); only ports that stay quiet pay the full timeout on the HTTP
    # probe, which covers HTTP servers on any port.
    greet_to=$(( TIMEOUT < 2 ? TIMEOUT : 2 ))
    banner=$(read_service "$ip" "$port" '' "$greet_to" | clean_banner)
    [[ -n $banner ]] || banner=$(read_service "$ip" "$port" "$HTTP_PROBE" | clean_banner)

    printf '%s\t%s\t%s\t%s\t%s\n' "$index" "$port" open "$(port_reason tcp open 0)" "$banner"
}

# Request datagrams for UDP services that stay silent unless asked something
# they understand. Call as `udp_payloads <port> <ip>`; prints one payload per
# line in printf %b form, and each one is sent as its own datagram. IDs are
# non-printable bytes so they are not mistaken for banner text in the reply.
# TFTP (69) and DHCP (67) are left out on purpose: their servers reply from or
# to a different port, which a connected socket never receives.
udp_payloads() {
    local port=$1 ip=$2

    case $port in
        53)    # DNS: "version.bind" TXT CHAOS. Even a refusal counts as a reply.
               printf '%s\n' '\xa5\x5a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03' ;;
        111)   # ONC RPC NULL call to the portmapper (program 100000, v2).
               printf '%s\n' '\x8a\x3d\x51\x07\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa0\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' ;;
        123)   # NTPv4 client request: mode 3, rest zero (48 bytes).
               printf '\\xe3'; printf '\\x00%.0s' {1..47}; echo ;;
        137)   # NetBIOS node-status (NBSTAT) query for "*"; the reply lists names.
               printf '%s\n' '\xa2\x48\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01' ;;
        161)   # SNMPv1 GET sysDescr.0 with community "public", then an SNMPv3
               # engine-discovery request, which v3 agents answer without credentials.
               printf '%s\n' \
                   '\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00' \
                   '\x30\x3a\x02\x01\x03\x30\x0f\x02\x02\x5c\x71\x02\x03\x00\xff\xe3\x04\x01\x04\x02\x01\x03\x04\x10\x30\x0e\x04\x00\x02\x01\x00\x02\x01\x00\x04\x00\x04\x00\x04\x00\x30\x12\x04\x00\x04\x00\xa0\x0c\x02\x02\x1f\x4b\x02\x01\x00\x02\x01\x00\x30\x00' ;;
        623)   # IPMI over RMCP: Get Channel Authentication Capabilities.
               printf '%s\n' '\x06\x00\xff\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x20\x18\xc8\x81\x00\x38\x8e\x04\xb5' ;;
        1194)  # OpenVPN P_CONTROL_HARD_RESET_CLIENT_V2 (ignored if tls-auth is on).
               printf '%s\n' '\x38\x5c\x1e\x7a\x93\x04\xd2\x6b\xf1\x00\x00\x00\x00\x00' ;;
        1434)  # SQL Server Browser: list instances.
               printf '%s\n' '\x02' ;;
        1900)  # SSDP unicast M-SEARCH.
               printf '%s\n' "M-SEARCH * HTTP/1.1\r\nHOST: $ip:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n" ;;
        5060)  # SIP OPTIONS; "rport" asks for the reply to come back to our port.
               printf '%s\n' "OPTIONS sip:$ip SIP/2.0\r\nVia: SIP/2.0/UDP portscan.invalid;branch=z9hG4bK-portscan;rport\r\nMax-Forwards: 70\r\nFrom: <sip:portscan@portscan.invalid>;tag=portscan\r\nTo: <sip:$ip>\r\nCall-ID: portscan@portscan.invalid\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n" ;;
        5353)  # mDNS legacy-unicast query: PTR _services._dns-sd._udp.local.
               printf '%s\n' '\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01' ;;
        5683)  # CoAP: GET /.well-known/core.
               printf '%s\n' '\x40\x01\x7a\x5c\xbb.well-known\x04core' ;;
        11211) # memcached UDP frame header + "version".
               printf '%s\n' '\x00\x01\x00\x00\x00\x01\x00\x00version\r\n' ;;
        *)     # Generic: enough for echo/daytime-style and line-based services.
               printf '%s\n' '\r\n\r\n' ;;
    esac
}

# Exit from udp_exchange based on an error message from dd or bash (its first
# line ends in strerror; the C locale is forced so the text is in English).
# Call as `udp_error <message> [status]`: port unreachable always exits 3;
# anything else prints the reason and exits with status (default 4).
udp_error() {
    local reason=${1%%$'\n'*} status=${2:-4}

    reason=${reason##*: }
    case $reason in
        # ECONNREFUSED (Linux) / ECONNRESET (Cygwin): ICMP port unreachable.
        *[Rr]efused*|*[Rr]eset*) exit 3 ;;
        # EPERM / EACCES come from this machine (an OUTPUT firewall rule, a
        # broadcast address), never from an ICMP reply.
        *'not permitted'*|*'Permission denied'*) status=5 ;;
    esac
    printf '%s\n' "${reason:-unknown error}"
    exit "$status"
}

# One UDP exchange: send each payload argument as its own datagram, then wait up
# to $TIMEOUT for a single reply. Must run in a subshell (e.g. as a pipeline
# element) since it opens fd 3 and exits. Exit status:
#   0    reply received (raw bytes on stdout)
#   3    ICMP port unreachable (closed)
#   4    another ICMP error reported on the socket (reason on stdout)
#   5    local error: no probe left this machine (reason on stdout)
#   124  no reply within the timeout
udp_exchange() {
    local ip=$1 port=$2 payload err status send_fail=5
    shift 2

    # Opening the socket only binds and connects it; nothing is sent. A failure
    # here is local (no route, a broadcast address) and says nothing about the
    # target. Repeat the open in a subshell to capture bash's message.
    if ! { exec 3<>"/dev/udp/$ip/$port"; } 2>/dev/null; then
        udp_error "$(LC_ALL=C; { exec 3<>"/dev/udp/$ip/$port"; } 2>&1)" 5
    fi
    for payload; do
        # printf flushes at every newline. dd with differing ibs/obs gathers
        # those pieces into one write, so each payload goes out as one datagram.
        # Before the first datagram is out no ICMP reply can exist, so an error
        # on it is local; on later ones it may be an ICMP error from the first.
        err=$(printf '%b' "$payload" | LC_ALL=C dd ibs=4096 obs=65536 2>&1 >&3) ||
            udp_error "$err" "$send_fail"
        send_fail=4
    done
    # A single read() (count=1) on a datagram socket returns exactly one reply.
    # timeout wraps dd itself, the only step that can block, so the signal goes
    # straight to it. Wrapping a parent shell instead relies on the process-group
    # kill reaching dd; where it does not, dd lingers and keeps the
    # caller's pipe open.
    { err=$(LC_ALL=C timeout "$TIMEOUT" dd bs=65536 count=1 <&3 2>&1 >&4); } 4>&1
    status=$?
    ((status == 0 || status == 124)) && exit "$status"
    udp_error "$err"
}

# Turn a UDP reply, given as od's decimal byte listing, into one safe line.
# Binary protocols carry their useful text (version strings, host names,
# sysDescr) as runs of printable bytes between length and flag bytes, so keep
# runs of 4+ printable characters, at least 3 of them letters or digits (ASN.1
# headers such as 30 28 30 26 read as "0(0&"), and drop the rest. Repeated
# runs are dropped, and so is the encoded "*" that NetBIOS echoes back. A reply
# that starts with an HTTP/SIP status line shows that line plus its Server (or
# User-Agent) header.
udp_banner() {
    awk -v max="$BANNER_MAX" '
        function cut(   t) {
            sub(/^ +/, "", run); sub(/ +$/, "", run)
            t = run
            if (length(run) >= 4 && gsub(/[A-Za-z0-9]/, "", t) >= 3 &&
                !(run in seen) && run !~ /^CKA+$/) {
                seen[run] = 1
                line = line (line == "" ? "" : " ") run
            }
            run = ""
        }
        function endline() { cut(); if (line != "") lines[++nl] = line; line = "" }
        {
            for (i = 1; i <= NF; i++) {
                n++; c = $i + 0
                if (c >= 32 && c < 127) run = run sprintf("%c", c)
                else if (c == 10)       endline()
                else                    cut()
            }
        }
        END {
            endline()
            if (n == 0)  { print "(empty reply)"; exit }
            if (nl == 0) { printf "(%d-byte binary reply)\n", n; exit }
            out = lines[1]
            if (out ~ /^(HTTP|SIP)\//) {
                for (i = 2; i <= nl; i++)
                    if (tolower(lines[i]) ~ /^(server|user-agent):/) { out = out " | " lines[i]; break }
            } else {
                for (i = 2; i <= nl; i++) out = out " " lines[i]
            }
            gsub(/  +/, " ", out)
            print substr(out, 1, max)
        }'
}

# Probe one UDP port and print "index<TAB>port<TAB>state<TAB>reason<TAB>banner",
# where state is open, open|filtered, filtered or closed, or error when the
# probe could not be sent and the banner holds the reason (exactly one line per
# probe, as with scan_port).
scan_port_udp() {
    local index=$1 ip=$2 port=$3 bytes status state banner=
    local -a payloads

    mapfile -t payloads < <(udp_payloads "$port" "$ip")
    # od makes the reply safe to hold in a variable (bash drops NUL bytes).
    bytes=$(udp_exchange "$ip" "$port" "${payloads[@]}" 2>/dev/null | od -An -v -tu1
            exit "${PIPESTATUS[0]}")
    status=$?
    case $status in
        0)   state=open ;;
        3)   state=closed ;;
        4)   state=filtered ;;
        5)   state=error ;;
        124) state='open|filtered' ;;
        *)   state=error; bytes= ;;     # dd or timeout itself failed
    esac
    [[ $state == open || -n $bytes ]] && banner=$(udp_banner <<<"$bytes")
    [[ $state == error && -z $banner ]] && banner="probe failed (exit status $status)"

    # For filtered ports the banner is the error text that names the ICMP error.
    printf '%s\t%s\t%s\t%s\t%s\n' "$index" "$port" "$state" \
        "$(port_reason udp "$state" "$status" "$banner")" "$banner"
}

list_probes() {
    local i port

    for i in "${!host_ips[@]}"; do
        for port in $ports; do
            echo "$i ${host_ips[i]} $port"
        done
    done
}

# Seconds as m:ss, or h:mm:ss from an hour up, into the variable named by $1.
fmt_duration() {
    local s=$2

    if ((s >= 3600)); then
        printf -v "$1" '%d:%02d:%02d' "$((s / 3600))" "$((s % 3600 / 60))" "$((s % 60))"
    else
        printf -v "$1" '%d:%02d' "$((s / 60))" "$((s % 60))"
    fi
}

# Sits between the workers and sort. Every probe prints exactly one line, so
# the lines read so far are the probes finished, counted as they complete
# rather than as they are handed out. Passes every row except "closed" on to the
# report. With SHOW_PROGRESS set, it redraws one status line on stderr at most
# once a second (only when a probe finishes) and erases it at the end, so the
# report that follows prints on a clean line.
track_progress() {
    local total=$1 finished=0 open=0 start=$SECONDS last=-1
    local line rest state reason key elapsed eta_text elapsed_text
    local -A closed_why=()   # "host index<TAB>reason" -> closed ports

    ((SHOW_PROGRESS)) && trap 'printf "\r\033[K" >&2; exit 130' INT TERM
    while IFS= read -r line; do
        ((finished += 1))
        rest=${line#*$'\t'}; rest=${rest#*$'\t'}; state=${rest%%$'\t'*}
        [[ $state == open ]] && ((open += 1))
        if [[ $state != closed ]]; then
            printf '%s\n' "$line"
        elif ((SHOW_REASON)); then
            # Closed rows are dropped, but --reason reports why they were
            # closed, so keep a count per host and reason.
            reason=${rest#*$'\t'}; reason=${reason%%$'\t'*}
            key=${line%%$'\t'*}$'\t'$reason
            closed_why[$key]=$(( ${closed_why[$key]:-0} + 1 ))
        fi

        ((SHOW_PROGRESS)) || continue
        ((SECONDS != last || finished == total)) || continue
        last=$SECONDS
        elapsed=$((SECONDS - start))
        fmt_duration elapsed_text "$elapsed"
        # Until one full batch of -j probes has finished, the rate is
        # dominated by the startup delay and the estimate is wildly high.
        if ((elapsed > 0 && finished >= JOBS)); then
            fmt_duration eta_text "$(((total - finished) * elapsed / finished))"
            eta_text="~$eta_text left"
        else
            eta_text='estimating'
        fi
        printf '\r\033[K[%*d/%d %3d%%] %d open, %s elapsed, %s' \
            "${#total}" "$finished" "$total" "$((finished * 100 / total))" \
            "$open" "$elapsed_text" "$eta_text" >&2
    done
    ((SHOW_PROGRESS)) && printf '\r\033[K' >&2
    # One "closed-why" row per host and reason: "index 0 closed-why reason count".
    # Port 0 sorts them ahead of the host's own rows.
    for key in "${!closed_why[@]}"; do
        printf '%s\t0\tclosed-why\t%s\t%s\n' \
            "${key%%$'\t'*}" "${key#*$'\t'}" "${closed_why[$key]}"
    done
    # Workers stopped early (xargs gives up if one is killed). print_report
    # reads missing rows as closed ports, so pass it a marker row; host index
    # -1 sorts first.
    ((finished == total)) || printf -- '-1\t0\tincomplete\t-\t%s\n' "$finished"
    return 0
}

# Print one host's block. Arguments after the host index are its result rows,
# "port<TAB>state<TAB>reason<TAB>banner". track_progress has already dropped
# closed rows, so the closed count is the number of ports scanned minus the
# number of rows, and a host with no rows at all had no port answer. With
# --reason, $host_why (set by print_report) says why its closed ports were
# closed, e.g. "998 conn-refused, 2 no-response".
report_host() {
    local index=$1 row port state reason banner svc closed joined err_reason=
    local n_open=0 n_of=0 n_filt=0 n_err=0 width=7 why=
    local -a notes=()
    shift
    ((SHOW_REASON)) && [[ -n $host_why ]] && why=" ($host_why)"

    for row; do
        case $row in
            *$'\t'open$'\t'*)            ((n_open += 1)) ;;
            *$'\t''open|filtered'$'\t'*) ((n_of += 1)) ;;
            *$'\t'error$'\t'*)           ((n_err += 1))
                                         [[ -n $err_reason ]] || err_reason=${row##*$'\t'} ;;
            *)                           ((n_filt += 1)) ;;
        esac
    done
    closed=$((port_count - $#))

    if (($# == 0)); then
        # Over UDP every port answered with ICMP port-unreachable, so the host
        # is up: give it a one-line block. Over TCP no open port cannot be told
        # apart from filtered ports or a host that is down, so only count it.
        if [[ $PROTO == udp ]]; then
            ((hosts_reported++)) && echo
            printf 'Scan report for %s\n' "${host_labels[index]}"
            printf 'All %d scanned UDP port(s) are closed (ICMP port unreachable)\n' "$port_count"
        elif [[ $host_why == *conn-refused* ]]; then
            # --reason knows more: a refused connection means the host sent a
            # RST, so it is up even though no port is open.
            ((hosts_reported++)) && echo
            printf 'Scan report for %s\n' "${host_labels[index]}"
            printf 'All %d scanned TCP port(s) are closed%s\n' "$port_count" "$why"
        else
            ((no_open_hosts += 1))
        fi
        return 0
    fi

    # No probe left this machine (no route, a broadcast address, a local
    # firewall), so nothing is known about the target. Collect it for a warning
    # instead of listing ports whose state was never tested.
    if ((n_err == port_count)); then
        unsent_hosts[$err_reason]+=" ${host_ips[index]}"
        return 0
    fi

    if [[ $PROTO == udp ]]; then
        width=15
        # No reply of any kind (not even ICMP) can also mean the host is down.
        # Count such hosts instead of printing a block of open|filtered ports.
        if ((n_open + n_filt + n_err + closed == 0)); then
            ((silent_hosts += 1, openfilt_count += n_of))
            return 0
        fi
    fi

    ((hosts_reported++)) && echo
    printf 'Scan report for %s\n' "${host_labels[index]}"
    if ((SHOW_REASON)); then
        printf '%-12s%-*s%-20s%-18s%s\n' PORT "$width" STATE SERVICE REASON BANNER
    else
        printf '%-12s%-*s%-20s%s\n' PORT "$width" STATE SERVICE BANNER
    fi
    for row; do
        IFS=$'\t' read -r port state reason banner <<<"$row"
        case $state in
            open)            ((open_count += 1)) ;;
            'open|filtered') ((openfilt_count += 1)); ((n_of > UDP_LIST_MAX)) && continue ;;
            filtered)        ((n_filt > UDP_LIST_MAX)) && continue ;;
            error)           continue ;;
        esac
        svc=$(service_name "$port" "$PROTO"); [[ -n $svc ]] || svc=unknown
        if ((SHOW_REASON)); then
            printf '%-12s%-*s%-20s%-18s%s\n' "$port/$PROTO" "$width" "$state" "$svc" "$reason" "$banner"
        else
            printf '%-12s%-*s%-20s%s\n' "$port/$PROTO" "$width" "$state" "$svc" "$banner"
        fi
    done

    if [[ $PROTO == tcp ]]; then
        ((closed > 0 && SHOW_REASON)) && printf 'Not shown: %d closed%s\n' "$closed" "$why"
        return 0
    fi
    ((n_of > UDP_LIST_MAX)) && notes+=("$n_of open|filtered (no reply)")
    ((n_filt > UDP_LIST_MAX)) && notes+=("$n_filt filtered (ICMP unreachable)")
    ((closed > 0)) && notes+=("$closed closed (ICMP port unreachable)")
    ((n_err > 0)) && notes+=("$n_err not probed (local error: $err_reason)")
    if ((${#notes[@]})); then
        joined=$(printf '%s, ' "${notes[@]}")
        printf 'Not shown: %s\n' "${joined%, }"
    fi
}

print_report() {
    local index port state reason banner current=-1 i list finished= host_why=
    local -a rows=() ips

    while IFS=$'\t' read -r index port state reason banner; do
        # track_progress's marker for a pipeline that ended early.
        if ((index < 0)); then
            finished=$banner
            continue
        fi
        if ((index != current)); then
            ((current >= 0)) && report_host "$current" "${rows[@]}"
            # Hosts between the previous index and this one sent no rows, so
            # no port on them answered. report_host still accounts for them.
            host_why=
            for ((i = current + 1; i < index; i++)); do report_host "$i"; done
            current=$index
            rows=()
        fi
        # With --reason: "count reason" for this host's dropped closed ports.
        if [[ $state == closed-why ]]; then
            host_why+="${host_why:+, }$banner $reason"
            continue
        fi
        rows+=("$port"$'\t'"$state"$'\t'"$reason"$'\t'"$banner")
    done
    ((current >= 0)) && report_host "$current" "${rows[@]}"
    host_why=
    for ((i = current + 1; i < ${#host_ips[@]}; i++)); do report_host "$i"; done

    if ((no_open_hosts > 0 && hosts_reported > 0)); then
        echo
        printf '%s other host(s) had no open TCP port (closed, filtered, or host down).\n' \
            "$no_open_hosts"
    fi

    if ((silent_hosts > 0)); then
        ((hosts_reported > 0)) && echo
        printf '%s host(s) sent no reply on any port (down, or a firewall drops the probes);\n' \
            "$silent_hosts"
        printf 'all %s scanned UDP port(s) on them are open|filtered.\n' "$((port_count))"
    fi
    ((open_count > 0)) || echo 'No open ports found.'

    for reason in "${!unsent_hosts[@]}"; do
        read -ra ips <<<"${unsent_hosts[$reason]}"
        list=${ips[*]:0:8}
        ((${#ips[@]} > 8)) && list+=" ..."
        warn "${#ips[@]} host(s) not scanned: no probe could be sent ($reason)" "$list"
    done
    # A host's missing rows are read as "no port answered", which is only true
    # if every probe reported. Say so when the pipeline stopped short.
    [[ -z $finished ]] ||
        warn "scan incomplete: only $finished of $((${#host_ips[@]} * port_count)) probes finished;" \
             "ports with no result were counted as closed"
}

port_spec=
# Honour an explicit "--": everything after it is a target, even if it begins
# with "-". Split those off here so getopts never tries to parse them.
post_dd_targets=()
seen_dd=0
pre_args=()
for arg in "$@"; do
    if ((seen_dd)); then post_dd_targets+=("$arg")
    elif [[ $arg == -- ]]; then seen_dd=1
    # The UDP flag is spelled -sU on the command line (as in nmap) and
    # translated here into the -u that getopts handles below. -u itself, alone
    # or in a cluster such as -uh, is not accepted from the user.
    elif [[ $arg == -sU ]]; then pre_args+=(-u)
    # Long option; getopts only knows single letters, so it becomes -r.
    elif [[ $arg == --reason ]]; then pre_args+=(-r)
    elif [[ $arg == -[!-]* && $arg == *u* ]]; then die "unknown option -u (use -sU for a UDP scan)"
    else pre_args+=("$arg"); fi
done
set -- "${pre_args[@]}"

while (($#)); do
    OPTIND=1
    while getopts ':p:t:j:urh' opt; do
        case $opt in
            p) port_spec=$OPTARG ;;
            u) PROTO=udp ;;
            r) SHOW_REASON=1 ;;
            t) TIMEOUT=$OPTARG ;;
            j) JOBS=$OPTARG ;;
            h) usage; exit 0 ;;
            :) die "option -$OPTARG requires a value (see -h)" ;;
            *) die "unknown option -$OPTARG (see -h)" ;;
        esac
    done
    shift $((OPTIND - 1))
    if (($#)); then
        targets+=("$1")
        shift
    fi
done
targets+=("${post_dd_targets[@]}")

if [[ -z $port_spec || ${#targets[@]} -eq 0 ]]; then
    usage >&2
    exit 2
fi
[[ $TIMEOUT =~ ^[1-9][0-9]{0,3}$ ]] || die "-t must be a whole number of seconds (1-9999)"
[[ $JOBS =~ ^[1-9][0-9]{0,3}$ ]] || die "-j must be a whole number (1-9999)"

[[ $port_spec == - ]] && port_spec=1-65535
ports=$(expand_list "$port_spec" 1 65535) || die "invalid port specification: '$port_spec'"
ports=$(sort -nu <<<"$ports")
port_count=$(wc -l <<<"$ports")

for target in "${targets[@]}"; do
    add_target "$target"
done
((${#host_ips[@]} > 0)) || die "no targets to scan"

# timeout(1) bounds every probe in both the nc and /dev/tcp paths; without it
# each probe would fail before touching the socket and every port would read as
# closed. Fail loudly rather than silently reporting nothing.
have timeout || die "'timeout' (from coreutils) is required but was not found in PATH"

NC=
NC_CONNECT_FLAG=
NC_READ_FLAG=
if [[ $PROTO == udp ]]; then
    have dd && have od || die "UDP scanning needs 'dd' and 'od' (from coreutils) in PATH"
    # Workers run as "$BASH", so check that one. Opening a UDP socket sends
    # nothing, so this works offline; it fails only if bash was built without
    # /dev/udp support, in which case every probe would fail.
    "$BASH" -c 'exec 3<>/dev/udp/127.0.0.1/9' 2>/dev/null ||
        die "UDP scanning needs bash's /dev/udp support, which this bash lacks"
    scanner=scan_port_udp
    via='bash /dev/udp'
else
    find_nc
    scanner=scan_port
    via=${NC:-/dev/tcp}
fi

export NC NC_CONNECT_FLAG NC_READ_FLAG TIMEOUT BANNER_MAX HTTP_PROBE
export -f scan_port port_is_open read_service clean_banner port_reason
export -f scan_port_udp udp_payloads udp_exchange udp_error udp_banner

warn "scanning ${#host_ips[@]} host(s), $((port_count)) ${PROTO^^} port(s) per host, using $via"

# The progress line is for a person watching: skip it when stderr is redirected
# to a file or pipe, so logs do not fill with carriage-return redraws.
[[ -t 2 ]] && SHOW_PROGRESS=1 || SHOW_PROGRESS=0

open_count=0
openfilt_count=0
hosts_reported=0
silent_hosts=0
no_open_hosts=0         # TCP hosts on which no port was open
declare -A unsent_hosts # UDP: local error reason -> " ip ip ..." never probed
print_report < <(list_probes |
    xargs -n 3 -P "$JOBS" "$BASH" -c "$scanner"' "$@"' _ |
    track_progress "$((${#host_ips[@]} * port_count))" |
    sort -t "$(printf '\t')" -k1,1n -k2,2n)

if [[ $PROTO == udp ]]; then
    warn "done: $open_count open, $openfilt_count open|filtered port(s) in ${SECONDS}s"
else
    warn "done: $open_count open port(s) in ${SECONDS}s"
fi
