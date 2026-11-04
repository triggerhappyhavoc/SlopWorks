#!/usr/bin/env bash
#
# enum.sh - Local Linux enumeration for authorized security assessments.
#
# A lightweight, dependency-light alternative to LinPEAS. It only READS system
# state (files, process/socket/service/cron listings) and reports what it finds;
# it never writes to, modifies, or exploits anything. Intended for use on hosts
# you are authorized to assess (pentest engagements, CTFs, your own machines).
#
# Usage:
#   ./enum.sh            # normal run (includes full-filesystem find scans)
#   ./enum.sh --fast     # skip the slow full-'/' find scans (SUID, caps, world-writable)
#   ./enum.sh --full     # same as default, but remove the output caps on find scans
#   ./enum.sh | tee out  # keep a copy; colour auto-disables when piped
#   NO_COLOR=1 ./enum.sh # force plain output
#
# Exits 0 always. Missing tools are reported and skipped, never fatal.

# No `set -e`: on a stripped-down target half the tools may be absent, and we
# want to run every check regardless of individual failures.
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
missing() { dim "($1 not installed, skipping)"; }

# ---------------------------------------------------------------------------
# Scan mode: gate the slow full-filesystem find passes.
#   FAST=1  -> skip the full-'/' scans (SUID/SGID, getcap -r /, world-writable)
#   FULL=1  -> run them with no output cap (otherwise capped, see FIND_CAP)
# ---------------------------------------------------------------------------
FAST=0
FULL=0
FIND_CAP=200            # max lines kept from each capped find pass in normal mode
for arg in "$@"; do
    case $arg in
        --fast)    FAST=1 ;;
        --full)    FULL=1 ;;
        -h|--help)
            sed -n '3,17p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) printf 'enum.sh: unknown option %q (try --help)\n' "$arg" >&2; exit 2 ;;
    esac
done
(( FAST && FULL )) && { printf 'enum.sh: --fast and --full are mutually exclusive\n' >&2; exit 2; }

# cap_find reads stdin and, unless --full, trims to FIND_CAP lines with a notice.
cap_find() {
    if (( FULL )); then cat
    else awk -v n="$FIND_CAP" 'NR<=n; NR==n+1{print "      ... (capped at "n"; re-run with --full for all)"}'
    fi
}
# skipped_fullscan prints a uniform note when --fast is active.
skipped_fullscan() { dim "skipped in --fast mode (full-filesystem scan); re-run without --fast to include"; }

# ---------------------------------------------------------------------------
# 1. Current user / identity
# ---------------------------------------------------------------------------
section "CURRENT USER"
sub "whoami / id"
info "user:   $(id -un 2>/dev/null) (uid $(id -u 2>/dev/null))"
info "groups: $(id -Gn 2>/dev/null)"
info "id:     $(id 2>/dev/null)"
# String compare: if `id` is missing, $(id -u) is empty and must NOT look like 0.
[[ $(id -u 2>/dev/null) == 0 ]] && hit "running as root"

sub "logged-in users"
have who && who 2>/dev/null | sed 's/^/      /' || missing who
sub "last logins"
have last && last -n 10 2>/dev/null | sed 's/^/      /' || missing last

sub "sudo rights (sudo -l, non-interactive)"
if have sudo; then
    # -n never prompts; if a password is required it just errors out harmlessly.
    out=$(sudo -n -l 2>/dev/null)
    if [[ -n $out ]]; then
        printf '%s\n' "$out" | sed 's/^/      /'
        grep -qE 'NOPASSWD|ALL' <<<"$out" && hit "sudo entries allow NOPASSWD or ALL - review above"
    else
        dim "no passwordless sudo, or a password is required"
    fi
else
    missing sudo
fi

# ---------------------------------------------------------------------------
# 2. /etc/passwd - accounts with a real shell
# ---------------------------------------------------------------------------
section "ACCOUNTS WITH A LOGIN SHELL (/etc/passwd)"
if [[ -r /etc/passwd ]]; then
    valid_shells=$( [[ -r /etc/shells ]] && grep -v '^#' /etc/shells 2>/dev/null )
    while IFS=: read -r name _ uid gid _ home shell; do
        case $shell in
            */nologin|*/false|/bin/sync|"") continue ;;
        esac
        line="$name  uid=$uid gid=$gid  home=$home  shell=$shell"
        if [[ $uid -eq 0 ]]; then
            hit "UID 0 account -> $line"
        else
            info "$line"
        fi
    done < /etc/passwd
    [[ -n $valid_shells ]] && dim "shells listed in /etc/shells: $(tr '\n' ' ' <<<"$valid_shells")"
else
    hit "/etc/passwd is not readable (unusual)"
fi

# ---------------------------------------------------------------------------
# 3. Permissions on sensitive files
# ---------------------------------------------------------------------------
section "SENSITIVE FILE PERMISSIONS"
check_perm() {
    local f=$1 expect=$2 perm owner
    if [[ -e $f ]]; then
        perm=$(stat -c '%a' "$f" 2>/dev/null)
        owner=$(stat -c '%U:%G' "$f" 2>/dev/null)
        printf '      %-18s mode=%-5s owner=%s' "$f" "$perm" "$owner"
        if [[ -r $f ]]; then printf '  %s[readable by me]%s' "$C_HIT" "$C_RST"; fi
        if [[ -w $f ]]; then printf '  %s[WRITABLE by me]%s' "$C_HIT" "$C_RST"; fi
        printf '\n'
        [[ -n $expect && $perm != "$expect" ]] &&
            hit "$f mode $perm differs from the usual $expect"
    else
        dim "$f does not exist"
    fi
}
check_perm /etc/shadow 640
check_perm /etc/gshadow 640
check_perm /etc/passwd 644
check_perm /etc/group  644
check_perm /etc/sudoers 440
if [[ -d /etc/sudoers.d ]]; then
    sub "/etc/sudoers.d"
    ls -la /etc/sudoers.d 2>/dev/null | sed 's/^/      /'
fi
[[ -w /etc/passwd ]] && hit "/etc/passwd is writable -> can add a UID 0 account"
[[ -r /etc/shadow ]] && hit "/etc/shadow is readable -> offline hash cracking possible"

# ---------------------------------------------------------------------------
# 4. SUID / SGID binaries
# ---------------------------------------------------------------------------
section "SUID / SGID BINARIES"
# Known-abusable names (GTFOBins-style). Presence as SUID is worth flagging.
GTFO='aa-exec|ab|agetty|alpine|ar|arj|arp|as|ascii-xfr|ash|aspell|atobm|awk|base32|base64|basenc|bash|bridge|busybox|bzip2|cabal|capsh|cat|chmod|chown|chroot|cmp|column|comm|cp|cpio|cpulimit|csh|csplit|csvtool|cupsfilter|curl|cut|dash|date|dd|dialog|diff|dig|dmesg|dmsetup|dnf|docker|dosbox|ed|efax|emacs|env|eqn|expand|expect|file|find|flock|fmt|fold|gawk|gcore|gdb|genie|gimp|git|grep|gtester|gzip|hd|head|hexdump|highlight|hping3|iconv|install|ionice|ip|ispell|jjs|join|journalctl|jq|jrunscript|ksh|ksshell|ld.so|less|logsave|look|lua|make|mawk|more|mosquitto|msgattrib|msgcat|msgconv|msgfilter|msgmerge|msguniq|multitime|mv|nano|nawk|nc|ncftp|nft|nice|nl|nmap|node|nohup|od|openssl|openvpn|paste|perl|pg|php|pic|pico|pr|python|python2|python3|readelf|restic|rev|rlwrap|rsync|rtorrent|run-parts|rview|rvim|scp|screen|script|sed|service|setarch|shuf|smbclient|socat|soelim|sort|sqlite3|ss|ssh|ssh-keygen|start-stop-daemon|stdbuf|strace|strings|su|sysdig|systemctl|tac|tail|tar|taskset|tbl|tclsh|tcpdump|tee|tftp|tic|time|timeout|tmux|troff|ul|unexpand|uniq|unshare|unzip|update-alternatives|uudecode|uuencode|vi|view|vigr|vim|vipw|watch|wc|wget|xargs|xdotool|xmodmap|xxd|xz|yarn|yash|zip|zsh|zypper'
if (( FAST )); then
    skipped_fullscan
else
    sub "scanning / (this can take a moment)"
    # Prune pseudo-filesystems but DO cross real mount points: separate /usr,
    # /var, /home, /opt commonly hold SUID/SGID binaries we must not miss.
    suid_list=$(find / \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o -perm -4000 -type f -print 2>/dev/null | cap_find)
    sgid_list=$(find / \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o -perm -2000 -type f -print 2>/dev/null | cap_find)
    if [[ -n $suid_list ]]; then
        while read -r f; do
            [[ $f == *'(capped at'* ]] && { dim "$f"; continue; }
            base=${f##*/}
            if [[ $base =~ ^($GTFO)$ ]]; then
                hit "SUID $f  (abusable per GTFOBins - spawns/reads as owner)"
            else
                info "SUID $f"
            fi
        done <<<"$suid_list"
    else
        dim "no SUID files found (or find unavailable)"
    fi
    sub "SGID binaries"
    if [[ -n $sgid_list ]]; then
        while read -r f; do
            [[ $f == *'(capped at'* ]] && { dim "$f"; continue; }
            info "SGID $f"
        done <<<"$sgid_list"
    else
        dim "none found"
    fi
fi

# ---------------------------------------------------------------------------
# 5. gcore
# ---------------------------------------------------------------------------
section "gcore (process memory dumping)"
if have gcore; then
    hit "gcore present at $(command -v gcore) - can dump memory of readable processes"
else
    missing gcore
fi
have gdb && info "gdb present at $(command -v gdb)"

# ---------------------------------------------------------------------------
# 6. Linux capabilities
# ---------------------------------------------------------------------------
section "FILE CAPABILITIES"
if (( FAST )); then
    skipped_fullscan
elif have getcap; then
    caps=$(getcap -r / 2>/dev/null | cap_find)
    if [[ -n $caps ]]; then
        while read -r line; do
            [[ $line == *'(capped at'* ]] && { dim "$line"; continue; }
            # cap_setuid, cap_setgid, cap_dac_*, cap_sys_admin etc. are the dangerous ones
            if grep -qiE 'cap_setuid|cap_setgid|cap_dac_override|cap_dac_read_search|cap_sys_admin|cap_sys_ptrace|cap_sys_module|cap_chown|cap_fowner' <<<"$line"; then
                hit "$line"
            else
                info "$line"
            fi
        done <<<"$caps"
    else
        dim "no file capabilities found"
    fi
else
    missing getcap
fi

# ---------------------------------------------------------------------------
# 7. $PATH inspection
# ---------------------------------------------------------------------------
section "PATH"
info "PATH=$PATH"
IFS=: read -ra path_parts <<<"$PATH"
for p in "${path_parts[@]}"; do
    case $p in
        /usr/local/sbin|/usr/local/bin|/usr/sbin|/usr/bin|/sbin|/bin|/usr/games|/usr/local/games) ;;
        "") hit "empty PATH element -> treated as current directory (.)" ;;
        .)  hit "'.' (current directory) is in PATH" ;;
        *)
            flag=""
            [[ -w $p ]] && flag=" (WRITABLE by me)"
            [[ ! -d $p ]] && flag="$flag (does not exist)"
            if [[ -n $flag ]]; then hit "non-standard PATH entry: $p$flag"
            else info "non-standard PATH entry: $p"; fi
            ;;
    esac
done

# ---------------------------------------------------------------------------
# 8. Shell history
# ---------------------------------------------------------------------------
section "SHELL HISTORY (current user)"
found_hist=0
for hf in "$HOME/.bash_history" "$HOME/.zsh_history" "$HOME/.sh_history" \
          "$HOME/.ash_history" "$HOME/.local/share/fish/fish_history" \
          "$HOME/.python_history" "$HOME/.mysql_history" "$HOME/.psql_history"; do
    if [[ -r $hf ]]; then
        found_hist=1
        sub "$hf (last 25 lines)"
        tail -n 25 "$hf" 2>/dev/null | sed 's/^/      /'
        grep -niE 'pass|pwd=|secret|token|key|ssh|curl|wget|export ' "$hf" 2>/dev/null |
            tail -n 10 | sed "s/^/      ${C_HIT}[credlike]${C_RST} /"
    fi
done
[[ $found_hist -eq 0 ]] && dim "no readable history files for $(id -un)"

# ---------------------------------------------------------------------------
# 9. Network sockets
# ---------------------------------------------------------------------------
section "NETWORK SOCKETS"
if have ss; then
    sub "listening TCP/UDP (ss -tulnp)"
    ss -tulnp 2>/dev/null | sed 's/^/      /'
    sub "established TCP (ss -tnp state established)"
    ss -tnp state established 2>/dev/null | sed 's/^/      /'
elif have netstat; then
    sub "listening (netstat -tulnp)"
    netstat -tulnp 2>/dev/null | sed 's/^/      /'
    sub "established (netstat -tnp)"
    netstat -tnp 2>/dev/null | grep ESTABLISHED | sed 's/^/      /'
else
    missing "ss/netstat"
fi

# ---------------------------------------------------------------------------
# 10. Cron
# ---------------------------------------------------------------------------
section "CRON JOBS"
sub "current user's crontab"
crontab -l 2>/dev/null | sed 's/^/      /' || dim "none / not permitted"
sub "/etc/crontab"
[[ -r /etc/crontab ]] && grep -v '^\s*#' /etc/crontab 2>/dev/null | grep -v '^\s*$' | sed 's/^/      /' || dim "not readable"
for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    if [[ -d $d ]]; then
        sub "$d"
        ls -la "$d" 2>/dev/null | sed 's/^/      /'
        # A cron file/dir writable by us is a classic escalation path
        [[ -w $d ]] && hit "$d is WRITABLE by me"
        # Portable writable-child check (busybox find has no -writable predicate).
        for entry in "$d"/*; do
            [[ -e $entry ]] || continue
            [[ -w $entry ]] && printf '      %s[WRITABLE]%s %s\n' "$C_HIT" "$C_RST" "$entry"
        done
    fi
done
sub "per-user spools (/var/spool/cron)"
ls -la /var/spool/cron/crontabs 2>/dev/null /var/spool/cron 2>/dev/null | sed 's/^/      /' || dim "not readable"

# ---------------------------------------------------------------------------
# 11. systemd
# ---------------------------------------------------------------------------
section "SYSTEMD"
if have systemctl; then
    sub "running services"
    systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null |
        sed 's/^/      /'
    sub "enabled services (start at boot)"
    systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend 2>/dev/null |
        sed 's/^/      /'
    sub "timers"
    systemctl list-timers --all --no-pager --no-legend 2>/dev/null | sed 's/^/      /'
    sub "unit files writable by me (escalation if the service runs as root)"
    # Check the common unit directories for anything we can write.
    for ud in /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system \
              "${HOME:-}/.config/systemd/user"; do
        [[ -d $ud ]] || continue
        # Portable writable check to depth 2 (busybox find lacks -writable).
        for entry in "$ud" "$ud"/* "$ud"/*/*; do
            [[ -e $entry ]] || continue
            [[ -w $entry ]] && printf '      %s[WRITABLE]%s %s\n' "$C_HIT" "$C_RST" "$entry"
        done
    done
else
    missing systemctl
    [[ -d /etc/init.d ]] && { sub "SysV init scripts"; ls /etc/init.d 2>/dev/null | sed 's/^/      /'; }
fi

# ---------------------------------------------------------------------------
# 12. Containers
# ---------------------------------------------------------------------------
section "CONTAINERS (docker / lxc)"
if have docker; then
    hit "docker client present at $(command -v docker)"
    # Membership of the docker group == effectively root on the host.
    id -Gn 2>/dev/null | tr ' ' '\n' | grep -qx docker &&
        hit "current user is in the 'docker' group -> root-equivalent via docker run"
    docker ps 2>/dev/null | sed 's/^/      /' | head -n 20
else
    dim "docker client not installed"
fi
[[ -S /var/run/docker.sock ]] && {
    hit "/var/run/docker.sock exists"
    [[ -w /var/run/docker.sock ]] && hit "docker.sock is WRITABLE by me -> container breakout to host root"
}
for c in lxc lxc-start lxc-attach lxd; do
    have "$c" && hit "$c present at $(command -v "$c")"
done
id -Gn 2>/dev/null | tr ' ' '\n' | grep -qx lxd &&
    hit "current user is in the 'lxd' group -> root-equivalent via lxd"

# ---------------------------------------------------------------------------
# 13. NFS exports (no_root_squash)
# ---------------------------------------------------------------------------
section "NFS EXPORTS"
nfs_found=0
for ef in /etc/exports /etc/exports.d/*.exports; do
    [[ -r $ef ]] || continue
    nfs_found=1
    sub "$ef"
    # Skip blank lines and comments; show the rest.
    grep -vE '^\s*(#|$)' "$ef" 2>/dev/null | while read -r line; do
        if grep -qE '\bno_root_squash\b' <<<"$line"; then
            hit "$line  (no_root_squash -> a mountable share where root stays root = host root)"
        else
            info "$line"
        fi
    done
done
# Also ask the running server what it actually exports, if we can.
if have exportfs; then
    out=$(exportfs -v 2>/dev/null)
    if [[ -n $out ]]; then
        sub "exportfs -v (live exports)"
        printf '%s\n' "$out" | while read -r line; do
            if grep -qE 'no_root_squash' <<<"$line"; then
                hit "$line"
            else
                info "$line"
            fi
        done
    fi
fi
[[ $nfs_found -eq 0 ]] && ! have exportfs && dim "no readable /etc/exports and no exportfs"

# ---------------------------------------------------------------------------
# 14. World-writable files and directories
# ---------------------------------------------------------------------------
section "WORLD-WRITABLE FILES & DIRECTORIES"
if (( FAST )); then
    skipped_fullscan
else
    sub "world-writable DIRECTORIES without the sticky bit (anyone can delete/replace contents)"
    # Sticky-bit dirs like /tmp are expected and filtered out (-perm -1000 excluded).
    find / \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o \
        -type d -perm -0002 ! -perm -1000 -print 2>/dev/null |
        cap_find | while read -r d; do
            [[ $d == *'(capped at'* ]] && { dim "$d"; continue; }
            printf '      %s[ww-dir]%s %s\n' "$C_HIT" "$C_RST" "$d"
        done

    sub "world-writable FILES (excludes /proc, /sys)"
    # These can be tampered with by any user; a world-writable script run by root is
    # a direct escalation path.
    find / \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o \
        -type f -perm -0002 -print 2>/dev/null |
        cap_find | while read -r f; do
            [[ $f == *'(capped at'* ]] && { dim "$f"; continue; }
            owner=$(stat -c '%U' "$f" 2>/dev/null)
            if [[ $owner == root ]]; then
                hit "$f  (world-writable, owned by root)"
            else
                info "$f  (owner $owner)"
            fi
        done
fi

# ---------------------------------------------------------------------------
# 15. Interesting dotfiles / secret-bearing files
# ---------------------------------------------------------------------------
section "INTERESTING DOTFILES & SECRET FILES"
# Search the current user's home plus other home dirs and a few system spots.
# For each hit, report whether WE can read and/or write it.
dot_targets=(
    "$HOME/.ssh/id_rsa" "$HOME/.ssh/id_dsa" "$HOME/.ssh/id_ecdsa"
    "$HOME/.ssh/id_ed25519" "$HOME/.ssh/authorized_keys"
    "$HOME/.ssh/config" "$HOME/.ssh/known_hosts"
    "$HOME/.aws/credentials" "$HOME/.aws/config"
    "$HOME/.git-credentials" "$HOME/.netrc" "$HOME/.npmrc" "$HOME/.pypirc"
    "$HOME/.docker/config.json" "$HOME/.kube/config"
    "$HOME/.gnupg" "$HOME/.password-store"
    "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile" "$HOME/.zshrc"
    "$HOME/.my.cnf" "$HOME/.pgpass" "$HOME/.env"
)

report_dotfile() {
    local f=$1 flags=""
    [[ -e $f ]] || return 0
    [[ -r $f ]] && flags="${flags} ${C_HIT}[readable]${C_RST}"
    [[ -w $f ]] && flags="${flags} ${C_HIT}[WRITABLE]${C_RST}"
    local owner; owner=$(stat -c '%U:%G %a' "$f" 2>/dev/null)
    printf '      %-45s %s%s\n' "$f" "($owner)" "$flags"
}

sub "current user ($HOME)"
for f in "${dot_targets[@]}"; do report_dotfile "$f"; done

# Other users' homes and system config: only interesting when WE can read/write
# something we shouldn't. Scan broadly but only print accessible hits.
sub "other homes & system (showing only files readable/writable by me)"
if (( FAST )); then
    skipped_fullscan
else
scan_roots=(/root /home)
for base in "${scan_roots[@]}"; do
    [[ -d $base ]] || continue
    find "$base" -xdev -type f 2>/dev/null \
        \( -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ecdsa' \
           -o -name 'id_ed25519' -o -name 'authorized_keys' -o -name '.netrc' \
           -o -name 'credentials' -o -name '.git-credentials' -o -name '.pgpass' \
           -o -name '.my.cnf' -o -name '*.pem' -o -name '*.key' -o -name '.env' \
           -o -name 'config.json' -o -name '.npmrc' \) 2>/dev/null |
    while read -r f; do
        # Skip our own home (already covered above).
        [[ $f == "$HOME"/* ]] && continue
        if [[ -w $f ]]; then hit "$f  (WRITABLE by me)"
        elif [[ -r $f ]]; then hit "$f  (readable by me)"
        fi
    done
done
fi

# ---------------------------------------------------------------------------
# 16. Kernel version & well-known escalation CVEs
# ---------------------------------------------------------------------------
section "KERNEL VERSION & KNOWN ESCALATION CVEs"
krel=$(uname -r 2>/dev/null)                 # e.g. 5.4.0-91-generic
kver=${krel%%-*}                             # 5.4.0
info "release: $krel"
info "version: $(uname -v 2>/dev/null)"
info "arch:    $(uname -m 2>/dev/null)"

# Parse major.minor.patch into comparable integers. Missing parts default to 0.
IFS=. read -r kmaj kmin kpatch _ <<<"$kver"
kmaj=${kmaj:-0}; kmin=${kmin:-0}; kpatch=${kpatch:-0}
# 10#... forces base-10 so leading zeros don't trigger octal errors.
knum=$(( 10#$kmaj * 1000000 + 10#$kmin * 1000 + 10#$kpatch ))

# ver_lt A_MAJ A_MIN A_PATCH  -> true if the running kernel is OLDER than A.
ver_lt() { (( knum < $1 * 1000000 + $2 * 1000 + $3 )); }
# ver_between LO_MAJ LO_MIN LO_PATCH HI_MAJ HI_MIN HI_PATCH -> [lo, hi) inclusive of lo.
ver_in() {
    local lo=$(( $1*1000000 + $2*1000 + $3 )) hi=$(( $4*1000000 + $5*1000 + $6 ))
    (( knum >= lo && knum < hi ))
}

sub "possible exploits (linux-exploit-suggester-style; VERIFY before trusting)"

# Collect candidates, then print ranked by confidence - like linux-exploit-suggester.
# Each row: WEIGHT \t MARK \t CVE \t NAME \t EXPOSURE \t TAGS \t COMMENT \t URL
#   WEIGHT 3/2/1 = highly probable / probable / less probable (sort key only)
#   MARK  "+"   = an environment check passed (binary present, distro matched)
#         " "   = matched on kernel version range alone (more false positives)
is_ubuntu() { [[ -r /etc/os-release ]] && grep -qi ubuntu /etc/os-release 2>/dev/null; }
CVE_ROWS=()
add_cve() { CVE_ROWS+=("$1	$2	$3	$4	$5	$6	$7	$8"); }

# --- Dirty COW: fixed 4.8.3; affects essentially everything older ------------
ver_lt 4 8 3 &&
    add_cve 3 " " CVE-2016-5195 "Dirty COW" "highly probable" \
        "kernel<4.8.3" "race in COW handling; reliable on most pre-4.8.3 builds" \
        "https://dirtycow.ninja/"

# --- overlayfs Ubuntu local root (very old Ubuntu 3.13/3.16/3.19) ------------
if ver_lt 3 19 1; then
    if is_ubuntu; then m="+"; exp="probable"; else m=" "; exp="less probable"; fi
    add_cve 2 "$m" CVE-2015-1328 "overlayfs (Ubuntu)" "$exp" \
        "ubuntu,kernel<3.19.1" "Ubuntu-specific overlayfs permission bug" \
        "https://www.exploit-db.com/exploits/37292"
fi

# --- Dirty Pipe: introduced 5.8, fixed upstream in 5.16.11 with stable
#     backports in 5.15.25 and 5.10.102. Exclude kernels at/after the fix on
#     those stable lines to cut obvious false positives; distro kernels that
#     backport the fix WITHOUT bumping the version still need manual confirmation.
dirty_pipe_vuln() {
    ver_in 5 8 0 5 16 11 || return 1
    (( kmaj == 5 && kmin == 15 )) && ! ver_lt 5 15 25 && return 1
    (( kmaj == 5 && kmin == 10 )) && ! ver_lt 5 10 102 && return 1
    return 0
}
dirty_pipe_vuln &&
    add_cve 3 " " CVE-2022-0847 "Dirty Pipe" "highly probable" \
        "kernel=5.8-5.16.11" "excludes 5.15.25+/5.10.102+ stable fixes; distro backports still need a manual patch-level check" \
        "https://dirtypipe.cm4all.com/"

# --- PwnKit: pkexec, not the kernel - flagged when the binary is present -----
if have pkexec; then
    pkver=$(pkexec --version 2>/dev/null | awk '{print $NF}')
    add_cve 3 "+" CVE-2021-4034 "PwnKit (pkexec)" "highly probable" \
        "pkexec=${pkver:-unknown}" "exploitable unless pkexec/polkit is patched; near-universal pre-2022" \
        "https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt"
fi

# --- netfilter / nf_tables family across 5.x-6.3 -----------------------------
ver_in 5 10 0 6 4 0 &&
    add_cve 1 " " CVE-2022-32250 "netfilter/nf_tables LPE family" "less probable" \
        "kernel=5.10-6.3" "several distinct nf_tables CVEs in this span (also CVE-2023-32233) - match exact patch" \
        "https://github.com/search?q=nf_tables+LPE&type=repositories"

# --- GameOver(lay): Ubuntu overlayfs, 2023 -----------------------------------
if ver_in 5 4 0 6 2 0 && is_ubuntu; then
    add_cve 2 "+" CVE-2023-2640 "GameOver(lay) (Ubuntu overlayfs)" "probable" \
        "ubuntu,kernel=5.4-6.1" "pairs with CVE-2023-32629; confirm it is an Ubuntu kernel build" \
        "https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629"
fi

if (( ${#CVE_ROWS[@]} == 0 )); then
    ok "no matches from the built-in candidate list"
else
    # Sort by weight (col 1) descending, then print each as an LES-style block.
    printf '%s\n' "${CVE_ROWS[@]}" | sort -t'	' -k1,1nr | while IFS=$'\t' read -r w mark cve name exp tags comment url; do
        case $w in 3) col=$C_HIT ;; 2) col=$C_HIT ;; *) col=$C_DIM ;; esac
        printf '%s  [%s] [%s] %s%s\n' "$col" "$mark" "$cve" "$name" "$C_RST"
        printf '        Exposure: %s\n' "$exp"
        printf '        Tags:     %s\n' "$tags"
        printf '        Comments: %s\n' "$comment"
        printf '        Details:  %s\n' "$url"
    done
fi
dim "Candidate list, not proof: [+] passed an environment check, [ ] matched on"
dim "version range alone. Distros backport fixes WITHOUT bumping the version"
dim "string, so confirm against the exact build. For a maintained database use"
dim "the standalone linux-exploit-suggester / linux-exploit-suggester-2."

# ---------------------------------------------------------------------------
# Context (free, and useful when reading the rest)
# ---------------------------------------------------------------------------
section "HOST CONTEXT"
info "hostname: $(hostname 2>/dev/null)"
info "kernel:   $(uname -a 2>/dev/null)"
[[ -r /etc/os-release ]] && info "os:       $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"

printf '\n%sdone.%s\n' "$C_OK" "$C_RST"
