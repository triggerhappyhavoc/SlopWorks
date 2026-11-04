#!/usr/bin/env bash
#
# portscan.sh - Nmap-style TCP connect scanner with banner grabbing, built on nc.
#
# Works with every netcat that Debian, Ubuntu and RHEL-family systems ship:
# netcat-openbsd, netcat-traditional and Nmap's ncat. They disagree on flags and
# on what happens at stdin EOF, so this script sticks to what they share:
#   * -n and -w are common to all of them.
#   * The connect test uses -z, or --send-only on old ncat (RHEL 7) without -z.
#   * Banner reads keep stdin open and rely on timeout(1) to end the session,
#     because -w means "idle timeout" on some flavours and "connect timeout"
#     on others.
#
# Requires bash 4.0+, coreutils, awk, xargs and getent. If no netcat is
# installed, it falls back to bash's built-in /dev/tcp.

PROG=${0##*/}
TIMEOUT=2           # seconds allowed for a connect, and for each banner read
JOBS=50             # concurrent probes
MAX_HOSTS=65536     # largest target list accepted (a /16)
BANNER_MAX=120      # banner characters shown
HTTP_PROBE='HEAD / HTTP/1.0\r\n\r\n'

IPV4='[0-9]{1,3}(\.[0-9]{1,3}){3}'

declare -A seen_ips
host_ips=()
host_labels=()
targets=()

usage() {
    cat <<EOF
Usage: $PROG -p <port[s]> [-t seconds] [-j jobs] <target> [target...]

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
  -t seconds    connect and banner timeout (default: $TIMEOUT)
  -j jobs       concurrent probes (default: $JOBS)
  -h            show this help

Examples:
  $PROG -p 22,80,443 192.168.1.10
  $PROG -p 1-1024 -t 1 -j 100 192.168.1.0/24 web01.lan
EOF
}

warn() { printf '%s: %s\n' "$PROG" "$*" >&2; }
die()  { warn "$*"; exit 2; }

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

add_hostname() {
    local name=$1 ip

    ip=$(getent ahostsv4 "$name" 2>/dev/null | awk 'NR == 1 { print $1 }')
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
    NC=$(command -v nc || command -v ncat || command -v netcat)
    if [[ -z $NC ]]; then
        warn "nc not found, falling back to bash /dev/tcp" \
            "(install with: apt-get install netcat-openbsd, or dnf install nmap-ncat)"
        return 0
    fi
    if "$NC" -h </dev/null 2>&1 | grep -q -- '-z'; then
        NC_CONNECT_FLAG=-z
    else
        NC_CONNECT_FLAG=--send-only
    fi
}

port_is_open() {
    local ip=$1 port=$2

    if [[ -n $NC ]]; then
        timeout "$((TIMEOUT + 1))" "$NC" "$NC_CONNECT_FLAG" -n -w "$TIMEOUT" \
            "$ip" "$port" </dev/null >/dev/null 2>&1
    else
        timeout "$TIMEOUT" bash -c 'exec 3<>"/dev/tcp/$0/$1"' "$ip" "$port" 2>/dev/null
    fi
}

# Connect, optionally send a payload, and print what the service returns.
# bash's printf flushes at each newline, so the payload goes through cat to reach
# the socket as one write rather than in fragments.
read_service() {
    local ip=$1 port=$2 payload=$3

    if [[ -n $NC ]]; then
        timeout "$TIMEOUT" "$NC" -n -w "$TIMEOUT" "$ip" "$port" \
            < <(printf '%b' "$payload" | cat; sleep "$TIMEOUT") 2>/dev/null
    else
        timeout "$TIMEOUT" bash -c \
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

# Probe one port. Silent when closed; prints "index<TAB>port<TAB>banner" when open.
scan_port() {
    local index=$1 ip=$2 port=$3 banner

    port_is_open "$ip" "$port" || return 0

    # Most services that announce themselves do so on connect. Only send a probe
    # to the ones that stay quiet, which covers HTTP servers on any port.
    banner=$(read_service "$ip" "$port" '' | clean_banner)
    [[ -n $banner ]] || banner=$(read_service "$ip" "$port" "$HTTP_PROBE" | clean_banner)

    printf '%s\t%s\t%s\n' "$index" "$port" "$banner"
}

list_probes() {
    local i port

    for i in "${!host_ips[@]}"; do
        for port in $ports; do
            echo "$i ${host_ips[i]} $port"
        done
    done
}

print_report() {
    local index port banner current=-1

    while IFS=$'\t' read -r index port banner; do
        if ((index != current)); then
            ((current >= 0)) && echo
            current=$index
            printf 'Scan report for %s\n' "${host_labels[index]}"
            printf '%-12s%-7s%s\n' PORT STATE BANNER
        fi
        printf '%-12s%-7s%s\n' "$port/tcp" open "$banner"
        ((open_count += 1))
    done
    ((open_count > 0)) || echo 'No open ports found.'
}

port_spec=
while (($#)); do
    OPTIND=1
    while getopts ':p:t:j:h' opt; do
        case $opt in
            p) port_spec=$OPTARG ;;
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

NC=
NC_CONNECT_FLAG=
find_nc

export NC NC_CONNECT_FLAG TIMEOUT BANNER_MAX HTTP_PROBE
export -f scan_port port_is_open read_service clean_banner

warn "scanning ${#host_ips[@]} host(s), $((port_count)) port(s) per host, using ${NC:-/dev/tcp}"

open_count=0
print_report < <(list_probes |
    xargs -n 3 -P "$JOBS" bash -c 'scan_port "$@"' _ |
    sort -t "$(printf '\t')" -k1,1n -k2,2n)

warn "done: $open_count open port(s) in ${SECONDS}s"
