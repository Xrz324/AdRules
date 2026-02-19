#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/utils.sh"

ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TMP_DIR="${ROOT_DIR}/tmp"
TOOLS_DIR="${TMP_DIR}/tools"
MIHOMO_RULE_FILE="${TMP_DIR}/mihomo_classical.txt"
DNS_REGEX_FILE="${TMP_DIR}/dns_regex_rules.txt"
SINGBOX_VERSION="${SINGBOX_VERSION:-1.11.11}"
MIHOMO_CHANNEL="${MIHOMO_CHANNEL:-Prerelease-Alpha}"
MIHOMO_VERSION="${MIHOMO_VERSION:-}"
STRICT_DNS_CONVERTER="${STRICT_DNS_CONVERTER:-false}"

# 检查依赖
check_deps awk cat chmod curl grep gzip perl python sed sort tar tr wc

match_domains_by_patterns() {
    local mode="$1"
    local pattern_file="$2"
    local domain_file="$3"
    local output_file="$4"

    perl - "$mode" "$pattern_file" "$domain_file" <<'PERL' | sort -u > "$output_file"
use strict;
use warnings;

my ($mode, $pattern_file, $domain_file) = @ARGV;
open my $pf, "<", $pattern_file or die "failed to open pattern file: $pattern_file\n";
open my $df, "<", $domain_file or die "failed to open domain file: $domain_file\n";

my @compiled;
my $invalid = 0;
my $loaded = 0;

sub domain_matches_denyallow {
    my ($domain, $allow_rule) = @_;
    return 0 if !defined $allow_rule || $allow_rule eq "";

    my $d = lc($domain);
    my $a = lc($allow_rule);
    $a =~ s/^\s+|\s+$//g;
    return 0 if $a eq "";
    $a =~ s/^~//;
    return 0 if $a eq "";

    if ($a =~ /\*/) {
        my $expr = $a;
        $expr =~ s/([\\.^\$+?(){}\[\]|])/\\$1/g;
        $expr =~ s/\*/.*/g;
        return ($d =~ /^$expr$/i) ? 1 : 0;
    }

    return 1 if $d eq $a;
    return ($d =~ /\.\Q$a\E$/i) ? 1 : 0;
}

while (my $line = <$pf>) {
    chomp $line;
    $line =~ s/\r$//;
    next if $line eq "";
    $loaded++;

    my $re;
    my @denyallow;
    if ($mode eq "wildcard") {
        my $expr = $line;
        $expr =~ s/([\\.^\$+?(){}\[\]|])/\\$1/g;
        $expr =~ s/\*/.*/g;
        $re = eval { qr/^$expr$/i };
    } else {
        my ($pattern, $denyallow_raw) = split(/\t/, $line, 2);
        $pattern = "" if !defined $pattern;
        $re = eval { qr/$pattern/i };

        if (defined $denyallow_raw && $denyallow_raw ne "") {
            @denyallow = grep { $_ ne "" } map {
                my $v = $_;
                $v =~ s/^\s+|\s+$//g;
                $v;
            } split(/\|/, $denyallow_raw);
        }
    }

    if ($@ || !defined $re) {
        $invalid++;
        next;
    }
    push @compiled, { re => $re, denyallow => \@denyallow };
}

if ($invalid > 0) {
    print STDERR "[WARN] 跳过 $invalid 条无法编译的${mode}覆盖模式\n";
}

if ($loaded == 0 || scalar(@compiled) == 0) {
    exit 0;
}

while (my $domain = <$df>) {
    chomp $domain;
    $domain =~ s/\r$//;
    next if $domain eq "";
    for my $entry (@compiled) {
        if ($domain =~ $entry->{re}) {
            my $skip = 0;
            if ($mode eq "regex" && scalar(@{$entry->{denyallow}}) > 0) {
                for my $allow_rule (@{$entry->{denyallow}}) {
                    if (domain_matches_denyallow($domain, $allow_rule)) {
                        $skip = 1;
                        last;
                    }
                }
            }
            if ($skip) {
                next;
            }
            print "$domain\n";
            last;
        }
    }
}
PERL
}

prune_covered_domain_rules() {
    local dns_file="$1"
    local plain_domain_file="${TMP_DIR}/dns_plain_domains.txt"
    local wildcard_suffix_file="${TMP_DIR}/dns_wildcard_suffixes.txt"
    local wildcard_suffix_match_file="${TMP_DIR}/dns_wildcard_suffix_covered_domains.txt"
    local wildcard_glob_file="${TMP_DIR}/dns_wildcard_globs.txt"
    local wildcard_glob_match_file="${TMP_DIR}/dns_wildcard_glob_covered_domains.txt"
    local regex_pattern_file="${TMP_DIR}/dns_cover_regex_patterns.txt"
    local regex_match_file="${TMP_DIR}/dns_regex_covered_domains.txt"
    local covered_domain_file="${TMP_DIR}/dns_covered_domains.txt"
    local covered_rule_file="${TMP_DIR}/dns_covered_rules.txt"
    local tmp_output="${dns_file}.tmp"
    local before_count=0
    local after_count=0
    local wildcard_suffix_removed=0
    local wildcard_glob_removed=0
    local regex_removed=0
    local total_removed=0

    : > "$plain_domain_file"
    : > "$wildcard_suffix_file"
    : > "$wildcard_suffix_match_file"
    : > "$wildcard_glob_file"
    : > "$wildcard_glob_match_file"
    : > "$regex_pattern_file"
    : > "$regex_match_file"
    : > "$covered_domain_file"
    : > "$covered_rule_file"

    # 仅处理标准域名规则：||example.com^
    awk '
        {
            line = tolower($0)
            sub(/\r$/, "", line)
            if (line ~ /^\|\|[a-z0-9.-]+\^$/) {
                print substr(line, 3, length(line) - 3)
            }
        }
    ' "$dns_file" > "$plain_domain_file"

    if [[ ! -s "$plain_domain_file" ]]; then
        log_info "未找到可用于覆盖清理的标准域名规则"
        return 0
    fi

    before_count=$(wc -l < "$dns_file")

    # 1) 用通配符规则覆盖清理：||*.example.com^ 覆盖 ||a.example.com^
    awk '
        {
            line = tolower($0)
            sub(/\r$/, "", line)
            if (line ~ /^\|\|\*\.[a-z0-9.-]+\^$/) {
                print substr(line, 5, length(line) - 5)
            }
        }
    ' "$dns_file" | sort -u > "$wildcard_suffix_file"

    if [[ -s "$wildcard_suffix_file" ]]; then
        awk '
            NR == FNR {
                suffixes[$0] = 1
                next
            }
            {
                domain = $0
                n = split(domain, parts, ".")
                for (i = 2; i <= n; i++) {
                    parent = parts[i]
                    for (j = i + 1; j <= n; j++) {
                        parent = parent "." parts[j]
                    }
                    if (parent in suffixes) {
                        print domain
                        break
                    }
                }
            }
        ' "$wildcard_suffix_file" "$plain_domain_file" | sort -u > "$wildcard_suffix_match_file"
        wildcard_suffix_removed=$(wc -l < "$wildcard_suffix_match_file")
    fi

    # 1.1) 用模糊通配符规则覆盖清理：||*foo*bar.com^ 覆盖 ||afoo1bar.com^
    awk '
        {
            line = tolower($0)
            sub(/\r$/, "", line)
            if (line ~ /^\|\|[a-z0-9.*-]+\^$/ && line ~ /\*/) {
                pattern = substr(line, 3, length(line) - 3)
                if (pattern !~ /^\*\.[a-z0-9.-]+$/) {
                    print pattern
                }
            }
        }
    ' "$dns_file" | sort -u > "$wildcard_glob_file"

    if [[ -s "$wildcard_glob_file" ]]; then
        match_domains_by_patterns "wildcard" "$wildcard_glob_file" "$plain_domain_file" "$wildcard_glob_match_file"
        wildcard_glob_removed=$(wc -l < "$wildcard_glob_match_file")
    fi

    # 2) 用 regex 规则覆盖清理（仅限无 modifier 或仅 important，跳过 badfilter/denyallow 等）
    awk '
        function trim(s) {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", s)
            return s
        }

        function parse_regex_rule(line,    mods, core, mod_sep, search_from, rel_pos) {
            p_core = ""
            p_mods = ""

            if (line !~ /^\/.*\/(\$[^[:space:]]+)?$/) {
                return 0
            }

            mods = ""
            core = line
            mod_sep = 0
            search_from = 1
            while (1) {
                rel_pos = index(substr(line, search_from), "/$")
                if (rel_pos == 0) {
                    break
                }
                mod_sep = search_from + rel_pos - 1
                search_from = mod_sep + 2
            }
            if (mod_sep > 0) {
                core = substr(line, 1, mod_sep)
                mods = substr(line, mod_sep + 1)
            }

            if (substr(core, 1, 1) != "/" || substr(core, length(core), 1) != "/") {
                return 0
            }

            p_core = core
            p_mods = mods
            return 1
        }

        function analyze_modifiers(mods,    raw, tokens, n, i, token, name, value) {
            m_supported = 1
            m_badfilter = 0
            m_denyallow = ""

            mods = trim(mods)
            if (mods == "" || mods == "$") {
                return
            }
            if (substr(mods, 1, 1) != "$") {
                m_supported = 0
                return
            }

            raw = substr(mods, 2)
            if (raw == "") {
                m_supported = 0
                return
            }

            n = split(raw, tokens, /,/)
            for (i = 1; i <= n; i++) {
                token = trim(tokens[i])
                if (token == "") {
                    continue
                }

                name = token
                sub(/=.*/, "", name)
                if (substr(name, 1, 1) == "~") {
                    name = substr(name, 2)
                }

                if (name == "important") {
                    continue
                }
                if (name == "badfilter") {
                    m_badfilter = 1
                    continue
                }
                if (name == "denyallow") {
                    value = token
                    sub(/^[^=]*=/, "", value)
                    value = trim(value)
                    if (value == "") {
                        m_supported = 0
                        continue
                    }
                    if (m_denyallow == "") {
                        m_denyallow = value
                    } else {
                        m_denyallow = m_denyallow "|" value
                    }
                    continue
                }

                m_supported = 0
            }
        }

        {
            line = trim($0)
            sub(/\r$/, "", line)
            if (line == "" || line ~ /^!/) {
                next
            }
            if (!parse_regex_rule(line)) {
                next
            }

            analyze_modifiers(p_mods)
            idx++
            cores[idx] = p_core
            supported[idx] = m_supported
            badfilter[idx] = m_badfilter
            denyallow[idx] = m_denyallow

            if (m_badfilter == 1) {
                disabled[p_core] = 1
            }
        }

        END {
            for (i = 1; i <= idx; i++) {
                core = cores[i]
                if (badfilter[i] == 1) {
                    continue
                }
                if (supported[i] != 1) {
                    continue
                }
                if (disabled[core] == 1) {
                    continue
                }

                pattern = substr(core, 2, length(core) - 2)
                if (pattern != "") {
                    printf "%s\t%s\n", pattern, denyallow[i]
                }
            }
        }
    ' "$dns_file" | sort -u > "$regex_pattern_file"

    if [[ -s "$regex_pattern_file" ]]; then
        match_domains_by_patterns "regex" "$regex_pattern_file" "$plain_domain_file" "$regex_match_file"
        regex_removed=$(wc -l < "$regex_match_file")
    fi

    cat "$wildcard_suffix_match_file" "$wildcard_glob_match_file" "$regex_match_file" | sort -u > "$covered_domain_file"
    if [[ ! -s "$covered_domain_file" ]]; then
        log_info "未发现可清理的覆盖重复域名规则"
        return 0
    fi

    sed 's/^/||/; s/$/^/' "$covered_domain_file" | sort -u > "$covered_rule_file"
    LC_ALL=C grep -vxFf "$covered_rule_file" "$dns_file" > "$tmp_output" || true
    mv "$tmp_output" "$dns_file"

    after_count=$(wc -l < "$dns_file")
    total_removed=$((before_count - after_count))
    log_info "覆盖清理完成: wildcard-suffix 命中 ${wildcard_suffix_removed} 条, wildcard-glob 命中 ${wildcard_glob_removed} 条, regex 命中 ${regex_removed} 条, 实际移除 ${total_removed} 条"
}

# 准备目录
mkdir -p "$TOOLS_DIR"
cd "$ROOT_DIR"

log_info "开始处理 DNS 规则..."

dns_raw="${TMP_DIR}/dns_pre.txt"
> "$dns_raw"

if [[ -f "./mod/rules/dns-rules.txt" ]]; then
    cat "./mod/rules/dns-rules.txt" >> "$dns_raw"
fi

shopt -s nullglob
dns_files=(./tmp/dns/*.txt)
shopt -u nullglob
for file in "${dns_files[@]}"; do
    cat "$file" >> "$dns_raw"
done

# 1. 预处理 DNS 规则
awk '
    {
        line = $0
        sub(/\r$/, "", line)

        # hosts 风格行先裁剪行尾注释，避免 "0.0.0.0 domain #comment" 被误丢弃
        if (line ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}[[:space:]]+/ ||
            line ~ /^[0-9a-fA-F:]+[[:space:]]+/) {
            sub(/[[:space:]]+#.*$/, "", line)
            gsub(/[[:space:]]+/, " ", line)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
        }

        print line
    }
' "$dns_raw" | \
    grep -P "^(?:\|\|([a-z0-9.*-]+)\^?|(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)\s+((?:\*|(?:\*\.)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)|((?:\*|(?:\*\.)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+))$" | \
    awk '
        BEGIN {
            filtered_hosts = 0
        }

        function is_blocking_hosts_ip(ip) {
            return (ip == "0.0.0.0" || ip ~ /^127\./)
        }

        {
            line = tolower($0)
            if (line ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}[[:space:]]+/) {
                split(line, parts, /[[:space:]]+/)
                if (!is_blocking_hosts_ip(parts[1])) {
                    filtered_hosts++
                    next
                }
            }
            print $0
        }

        END {
            if (filtered_hosts > 0) {
                print "[INFO] 过滤 " filtered_hosts " 条 hosts 重定向规则(非拦截IP)" > "/dev/stderr"
            }
        }
    ' | \
    grep -vE '@|:|\?|\$|#|!|/' | \
    sort -u > dns.txt || true

# 2. 压缩、白名单过滤
log_info "正在压缩和去重 DNS 规则..."
python "${SCRIPT_DIR}/compressor.py" dns.txt -i --include-wildcards
log_info "正在应用白名单..."
python "${SCRIPT_DIR}/remove.py" --blacklist dns.txt --whitelist mod/rules/dns-allowlist.txt

# 3. 回补上游高级规则（regex / 带 modifier 的域名规则）+ 添加首要规则并再次去重
awk '
    function trim(s) {
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", s)
        return s
    }

    function modifiers_supported(mods,    raw, parts, n, i, token, name) {
        mods = trim(mods)
        if (mods == "") {
            return 1
        }
        if (substr(mods, 1, 1) != "$") {
            return 0
        }

        raw = substr(mods, 2)
        if (raw == "") {
            return 0
        }

        n = split(raw, parts, /,/)
        for (i = 1; i <= n; i++) {
            token = trim(parts[i])
            if (token == "") {
                continue
            }

            name = token
            sub(/=.*/, "", name)
            if (substr(name, 1, 1) == "~") {
                name = substr(name, 2)
            }

            if (name == "important" || name == "badfilter") {
                continue
            }
            if (name == "denyallow") {
                if (token !~ /^[^=]+=.+$/) {
                    return 0
                }
                continue
            }
            return 0
        }
        return 1
    }

    {
        line = trim($0)
        if (line == "" || line ~ /^!/) {
            next
        }

        if (line ~ /^\/.*\/(\$[^[:space:]]+)?$/) {
            mods = ""
            mod_sep = 0
            search_from = 1
            while (1) {
                rel_pos = index(substr(line, search_from), "/$")
                if (rel_pos == 0) {
                    break
                }
                mod_sep = search_from + rel_pos - 1
                search_from = mod_sep + 2
            }
            if (mod_sep > 0) {
                mods = substr(line, mod_sep + 1)
            }

            if (modifiers_supported(mods)) {
                print line
            }
            next
        }

        if (line ~ /^\|\|.+\^(\$[^[:space:]]+)?$/) {
            caret_pos = index(line, "^")
            if (caret_pos <= 3) {
                next
            }

            domain = substr(line, 3, caret_pos - 3)
            if (domain !~ /^[A-Za-z0-9.*-]+$/) {
                next
            }

            mods = ""
            suffix = substr(line, caret_pos + 1)
            if (substr(suffix, 1, 1) == "$") {
                mods = suffix
            }

            if (mods != "" && modifiers_supported(mods)) {
                print line
            }
        }
    }
' "$dns_raw" | sort -u > "$DNS_REGEX_FILE"

if [[ -s "$DNS_REGEX_FILE" ]]; then
    cat "$DNS_REGEX_FILE" >> dns.txt
fi

if [[ -f "./mod/rules/first-dns-rules.txt" ]]; then
    cat ./mod/rules/first-dns-rules.txt >> dns.txt
fi
sort -u dns.txt -o dns.txt
prune_covered_domain_rules dns.txt

# 4. 生成最终 dns.txt (AdGuard Home / ABP)
count=$(wc -l < dns.txt)
{
    [[ -f "./mod/title/dns-title.txt" ]] && cat ./mod/title/dns-title.txt
    echo "! Total count: $count"
    echo "! Update: $(get_timestamp)(GMT+8)"
    cat dns.txt
} | sed '/^$/d' > dns.txt.tmp && mv dns.txt.tmp dns.txt

# 5. 转换 sing-box / mihomo
generate_mihomo_classical_rules() {
    awk '
        function trim(s) {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", s)
            return s
        }

        function base_rule_for_target(target,    rule, regex, mask, split_pos) {
            if (target ~ /\*/) {
                if (target ~ /^\*\.[[:alnum:]_-]+([.-][[:alnum:]_-]+)+$/) {
                    rule = "DOMAIN-WILDCARD," target
                } else {
                    regex = target
                    gsub(/\./, "\\.", regex)
                    gsub(/\*/, ".*", regex)
                    rule = "DOMAIN-REGEX,^" regex "$"
                }
            } else if (target ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$/ ||
                       target ~ /^[0-9a-fA-F:]+(\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))?$/) {
                if (target ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$/) {
                    split_pos = index(target, "/")
                    if (split_pos > 0) {
                        mask = substr(target, split_pos + 1)
                    } else {
                        mask = "32"
                    }
                    rule = "IP-CIDR," target
                    if (split_pos == 0) {
                        rule = rule "/" mask
                    }
                } else {
                    split_pos = index(target, "/")
                    if (split_pos > 0) {
                        mask = substr(target, split_pos + 1)
                    } else {
                        mask = "128"
                    }
                    rule = "IP-CIDR6," target
                    if (split_pos == 0) {
                        rule = rule "/" mask
                    }
                }
            } else {
                rule = "DOMAIN-SUFFIX," target
            }
            return rule
        }

        function clear_array(arr,    k) {
            for (k in arr) {
                delete arr[k]
            }
        }

        function ipv4_to_int(a, b, c, d) {
            return a * 16777216 + b * 65536 + c * 256 + d
        }

        function int_to_ipv4(v,    a, b, c, d, r) {
            a = int(v / 16777216)
            r = v - a * 16777216
            b = int(r / 65536)
            r = r - b * 65536
            c = int(r / 256)
            d = r - c * 256
            return a "." b "." c "." d
        }

        function append_cidr_rule(rule) {
            if (!(rule in cidr_seen)) {
                cidr_seen[rule] = 1
                cidr_rules[++cidr_count] = rule
            }
        }

        function append_port_rule(rule) {
            if (!(rule in port_seen)) {
                port_seen[rule] = 1
                port_rules[++port_count] = rule
            }
        }

        function emit_port_range(start_port, end_port) {
            if (start_port <= 0 || end_port > 65535 || start_port > end_port) {
                return
            }
            if (start_port == end_port) {
                append_port_rule("DST-PORT," start_port)
            } else {
                append_port_rule("DST-PORT," start_port "-" end_port)
            }
        }

        function range_to_cidr_rules(start_ip, end_ip,    block, remain, p2, prefix) {
            while (start_ip <= end_ip) {
                block = 1
                while ((start_ip % (block * 2) == 0) && (block * 2 > 0)) {
                    block *= 2
                }

                remain = end_ip - start_ip + 1
                while (block > remain) {
                    block /= 2
                }

                prefix = 32
                p2 = block
                while (p2 > 1) {
                    p2 /= 2
                    prefix--
                }

                append_cidr_rule("IP-CIDR," int_to_ipv4(start_ip) "/" prefix)
                start_ip += block
            }
        }

        function collect_octet_values(token, out_values,    v, expr, cnt) {
            clear_array(out_values)
            token = trim(token)
            if (token == "") {
                return 0
            }

            if (token ~ /^[0-9]{1,3}$/) {
                v = token + 0
                if (v < 0 || v > 255) {
                    return 0
                }
                out_values[v] = 1
                return 1
            }

            if (token == "\\d{1,3}" || token == "\\d{3}" || token == "\\d+" ||
                token == "[0-9]{1,3}" || token == "[0-9]{3}" || token == "[0-9]+") {
                for (v = 0; v <= 255; v++) {
                    out_values[v] = 1
                }
                return 1
            }

            expr = token
            gsub(/\\d/, "[0-9]", expr)
            if (expr ~ /\\[A-CE-Za-ce-z]/) {
                return 0
            }

            cnt = 0
            for (v = 0; v <= 255; v++) {
                if (sprintf("%d", v) ~ ("^(" expr ")$")) {
                    out_values[v] = 1
                    cnt++
                }
            }
            return cnt > 0
        }

        function collect_port_values(token, out_values,    v, expr, cnt) {
            clear_array(out_values)
            token = trim(token)
            if (token == "") {
                return 0
            }

            if (substr(token, 1, 1) == "(" && substr(token, length(token), 1) == ")") {
                token = trim(substr(token, 2, length(token) - 2))
            }
            if (token == "") {
                return 0
            }

            if (token ~ /^[0-9]{1,5}$/) {
                v = token + 0
                if (v <= 0 || v > 65535) {
                    return 0
                }
                out_values[v] = 1
                return 1
            }

            if (token == "\\d{1,5}" || token == "\\d+" ||
                token == "[0-9]{1,5}" || token == "[0-9]+") {
                for (v = 1; v <= 65535; v++) {
                    out_values[v] = 1
                }
                return 1
            }

            expr = token
            gsub(/\\d/, "[0-9]", expr)
            if (expr ~ /\\[A-CE-Za-ce-z]/) {
                return 0
            }

            cnt = 0
            for (v = 1; v <= 65535; v++) {
                if (sprintf("%d", v) ~ ("^(" expr ")$")) {
                    out_values[v] = 1
                    cnt++
                }
            }
            return cnt > 0
        }

        function port_values_to_rules(values,    v, in_range, start_v) {
            in_range = 0

            for (v = 1; v <= 65535; v++) {
                if (v in values) {
                    if (!in_range) {
                        in_range = 1
                        start_v = v
                    }
                } else if (in_range) {
                    emit_port_range(start_v, v - 1)
                    in_range = 0
                }
            }

            if (in_range) {
                emit_port_range(start_v, 65535)
            }
        }

        function values_to_ranges(values, out_starts, out_ends,    v, in_range, start_v, n) {
            clear_array(out_starts)
            clear_array(out_ends)
            in_range = 0
            n = 0

            for (v = 0; v <= 255; v++) {
                if (v in values) {
                    if (!in_range) {
                        in_range = 1
                        start_v = v
                    }
                } else if (in_range) {
                    n++
                    out_starts[n] = start_v
                    out_ends[n] = v - 1
                    in_range = 0
                }
            }

            if (in_range) {
                n++
                out_starts[n] = start_v
                out_ends[n] = 255
            }
            return n
        }

        function regex_to_precise_ip_rule(regex,    normalized, parts, n, suffix, port_expr, colon_pos, a, b, c, d, i1, i2, i3, i4, n1, n2, n3, n4, start_ip, end_ip) {
            cidr_count = 0
            clear_array(cidr_rules)
            clear_array(cidr_seen)
            port_count = 0
            clear_array(port_rules)
            clear_array(port_seen)

            if (regex == "") {
                return 0
            }
            if (substr(regex, 1, 1) != "^") {
                return 0
            }

            normalized = substr(regex, 2)
            if (substr(normalized, length(normalized), 1) == "$") {
                normalized = substr(normalized, 1, length(normalized) - 1)
            }
            gsub(/\\\./, ".", normalized)

            if (normalized ~ /^[0-9A-Fa-f:]+$/ && normalized ~ /:/) {
                if (normalized !~ /:::/) {
                    append_cidr_rule("IP-CIDR6," normalized "/128")
                    return 1
                }
                return 0
            }

            n = split(normalized, parts, ".")
            if (n != 4) {
                return 0
            }

            suffix = ""
            colon_pos = index(parts[4], ":")
            if (colon_pos > 0) {
                suffix = substr(parts[4], colon_pos)
                parts[4] = substr(parts[4], 1, colon_pos - 1)
            }
            if (parts[4] == "") {
                return 0
            }
            if (suffix != "") {
                if (suffix == ":") {
                    # 仅匹配 host:，不附加端口条件
                } else {
                    if (substr(suffix, 1, 1) != ":") {
                        return 0
                    }
                    port_expr = substr(suffix, 2)
                    if (!collect_port_values(port_expr, port_values)) {
                        return 0
                    }
                    port_values_to_rules(port_values)
                    if (port_count == 0) {
                        return 0
                    }
                }
            }

            if (!collect_octet_values(parts[1], octet_values_1) ||
                !collect_octet_values(parts[2], octet_values_2) ||
                !collect_octet_values(parts[3], octet_values_3) ||
                !collect_octet_values(parts[4], octet_values_4)) {
                return 0
            }

            n1 = values_to_ranges(octet_values_1, octet_start_1, octet_end_1)
            n2 = values_to_ranges(octet_values_2, octet_start_2, octet_end_2)
            n3 = values_to_ranges(octet_values_3, octet_start_3, octet_end_3)
            n4 = values_to_ranges(octet_values_4, octet_start_4, octet_end_4)
            if (n1 == 0 || n2 == 0 || n3 == 0 || n4 == 0) {
                return 0
            }

            for (i1 = 1; i1 <= n1; i1++) {
                for (i2 = 1; i2 <= n2; i2++) {
                    for (i3 = 1; i3 <= n3; i3++) {
                        for (i4 = 1; i4 <= n4; i4++) {
                            a = octet_start_1[i1]
                            b = octet_start_2[i2]
                            c = octet_start_3[i3]
                            d = octet_start_4[i4]
                            start_ip = ipv4_to_int(a, b, c, d)

                            a = octet_end_1[i1]
                            b = octet_end_2[i2]
                            c = octet_end_3[i3]
                            d = octet_end_4[i4]
                            end_ip = ipv4_to_int(a, b, c, d)

                            if (start_ip > end_ip) {
                                return 0
                            }
                            range_to_cidr_rules(start_ip, end_ip)
                        }
                    }
                }
            }

            if (cidr_count == 0) {
                return 0
            }
            return 1
        }

        function is_valid_ipv4_octet(value,    num) {
            if (value !~ /^[0-9]{1,3}$/) {
                return 0
            }
            num = value + 0
            return (num >= 0 && num <= 255)
        }

        function regex_to_ipv4_prefix_rule(regex,    normalized, leading_group, prefix_text, n) {
            cidr_count = 0
            clear_array(cidr_rules)
            clear_array(cidr_seen)
            port_count = 0
            clear_array(port_rules)
            clear_array(port_seen)

            if (regex == "") {
                return 0
            }
            # 放宽 IP regex 转换仅用于“URL 前缀 + 转义点分 IP”场景，避免误转普通 regex
            if (regex !~ /\\\./) {
                return 0
            }

            normalized = trim(regex)
            gsub(/\\\./, ".", normalized)
            gsub(/\\\//, "/", normalized)

            sub(/^\^/, "", normalized)
            while (match(normalized, /^\([^)]*\)/)) {
                leading_group = substr(normalized, RSTART, RLENGTH)
                if (leading_group ~ /:\/\//) {
                    normalized = substr(normalized, RLENGTH + 1)
                    continue
                }
                break
            }
            sub(/^(https\?:\/\/|https?:\/\/|http:\/\/|ftp:\/\/|wss:\/\/)/, "", normalized)

            if (match(normalized, /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}([^0-9]|$)/)) {
                prefix_text = substr(normalized, RSTART, RLENGTH)
                sub(/[^0-9.].*$/, "", prefix_text)
                n = split(prefix_text, ip_parts, ".")
                if (n == 4 &&
                    is_valid_ipv4_octet(ip_parts[1]) &&
                    is_valid_ipv4_octet(ip_parts[2]) &&
                    is_valid_ipv4_octet(ip_parts[3]) &&
                    is_valid_ipv4_octet(ip_parts[4])) {
                    append_cidr_rule("IP-CIDR," ip_parts[1] "." ip_parts[2] "." ip_parts[3] "." ip_parts[4] "/32")
                    return 1
                }
            }

            if (match(normalized, /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\./)) {
                prefix_text = substr(normalized, RSTART, RLENGTH - 1)
                n = split(prefix_text, ip_parts, ".")
                if (n == 3 &&
                    is_valid_ipv4_octet(ip_parts[1]) &&
                    is_valid_ipv4_octet(ip_parts[2]) &&
                    is_valid_ipv4_octet(ip_parts[3])) {
                    append_cidr_rule("IP-CIDR," ip_parts[1] "." ip_parts[2] "." ip_parts[3] ".0/24")
                    return 1
                }
            }

            if (match(normalized, /^[0-9]{1,3}\.[0-9]{1,3}\./)) {
                prefix_text = substr(normalized, RSTART, RLENGTH - 1)
                n = split(prefix_text, ip_parts, ".")
                if (n == 2 &&
                    is_valid_ipv4_octet(ip_parts[1]) &&
                    is_valid_ipv4_octet(ip_parts[2])) {
                    append_cidr_rule("IP-CIDR," ip_parts[1] "." ip_parts[2] ".0.0/16")
                    return 1
                }
            }

            return 0
        }

        function regex_looks_domain_related(regex, normalized, probe) {
            if (regex == "") {
                return 0
            }
            normalized = regex
            gsub(/\\\//, "/", normalized)

            if (normalized ~ /\//) {
                return 0
            }
            if (normalized ~ /\$[[:alnum:]_-]+([=,]|$)/) {
                return 0
            }
            if (normalized ~ /,replace=/) {
                return 0
            }
            if (normalized ~ /(https?|ftp|wss?):\/\//) {
                return 0
            }
            if (normalized ~ /:/) {
                return 0
            }
            if (normalized ~ /\\x[0-9a-fA-F]{2}/) {
                return 0
            }

            probe = normalized
            gsub(/\\[dDsSwWbB]/, "", probe)

            if (probe !~ /[A-Za-z]/) {
                return 0
            }
            return 1
        }

        function parse_line(line,    mods, core, caret_pos, suffix, mod_sep, search_from, rel_pos) {
            p_type = ""
            p_core = ""
            p_mods = ""
            p_regex = ""
            p_domain = ""

            line = trim(line)
            if (line == "" || line ~ /^(!|\[)/) {
                return 0
            }

            if (line ~ /^\/.*\/(\$.*)?$/) {
                mods = ""
                core = line
                mod_sep = 0
                search_from = 1
                while (1) {
                    rel_pos = index(substr(line, search_from), "/$")
                    if (rel_pos == 0) {
                        break
                    }
                    mod_sep = search_from + rel_pos - 1
                    search_from = mod_sep + 2
                }
                if (mod_sep > 0) {
                    core = substr(line, 1, mod_sep)
                    mods = substr(line, mod_sep + 1)
                }

                if (substr(core, 1, 1) != "/" || substr(core, length(core), 1) != "/") {
                    return 0
                }
                p_type = "regex"
                p_core = core
                p_mods = mods
                p_regex = substr(core, 2, length(core) - 2)
                return 1
            }

            if (line ~ /^\|\|.+\^(\$.*)?$/) {
                mods = ""
                caret_pos = index(line, "^")
                if (caret_pos <= 3) {
                    return 0
                }

                p_domain = trim(substr(line, 3, caret_pos - 3))
                suffix = substr(line, caret_pos + 1)
                if (substr(suffix, 1, 1) == "$") {
                    mods = suffix
                }
                if (p_domain == "" || p_domain ~ /[[:space:]]/) {
                    return 0
                }

                p_type = "domain"
                p_core = substr(line, 1, caret_pos)
                p_mods = mods
                return 1
            }

            if (line ~ /^[[:alnum:]_-]+([.-][[:alnum:]_-]+)+$/) {
                p_type = "plain"
                p_core = line
                p_domain = line
                return 1
            }

            return 0
        }

        function analyze_modifiers(mods,    raw, tokens, n, i, token, name, value) {
            m_badfilter = 0
            m_unsupported = 0
            m_denyallow = ""

            if (mods == "" || mods == "$") {
                return
            }

            raw = substr(mods, 2)
            n = split(raw, tokens, /,/)

            for (i = 1; i <= n; i++) {
                token = trim(tokens[i])
                if (token == "") {
                    continue
                }

                name = token
                sub(/=.*/, "", name)
                if (substr(name, 1, 1) == "~") {
                    name = substr(name, 2)
                }

                if (name == "badfilter") {
                    m_badfilter = 1
                    continue
                }

                if (name == "important") {
                    continue
                }

                if (name == "denyallow") {
                    if (token !~ /^[^=]+=.+$/) {
                        m_unsupported = 1
                        continue
                    }
                    value = token
                    sub(/^[^=]*=/, "", value)
                    if (value == "") {
                        m_unsupported = 1
                        continue
                    }
                    m_denyallow = value
                    continue
                }

                if (name == "client" || name == "ctag" || name == "dnstype" || name == "dnsrewrite") {
                    m_unsupported = 1
                    continue
                }

                m_unsupported = 1
            }
        }

        function denyallow_expr_from_value(deny_raw,    parts, i, item, piece, allow_expr, count) {
            count = split(deny_raw, parts, /\|/)
            allow_expr = ""

            for (i = 1; i <= count; i++) {
                item = trim(parts[i])
                if (item == "" || item ~ /^~/) {
                    continue
                }
                piece = base_rule_for_target(item)
                if (piece == "") {
                    continue
                }
                if (allow_expr != "") {
                    allow_expr = allow_expr ","
                }
                allow_expr = allow_expr "(" piece ")"
            }

            if (allow_expr == "") {
                return ""
            }
            return "NOT,(" allow_expr ")"
        }

        function join_logic_expr(op, terms, term_count,    expr, i) {
            if (term_count <= 0) {
                return ""
            }
            expr = terms[1]
            for (i = 2; i <= term_count; i++) {
                expr = op ",((" expr "),(" terms[i] "))"
            }
            return expr
        }

        function build_port_expr(    terms, i) {
            if (port_count <= 0) {
                return ""
            }
            clear_array(terms)
            for (i = 1; i <= port_count; i++) {
                terms[i] = port_rules[i]
            }
            return join_logic_expr("OR", terms, port_count)
        }

        function combine_with_and(base_expr, extra_expr, deny_expr,    terms, count) {
            clear_array(terms)
            count = 0
            if (base_expr != "") {
                terms[++count] = base_expr
            }
            if (extra_expr != "") {
                terms[++count] = extra_expr
            }
            if (deny_expr != "") {
                terms[++count] = deny_expr
            }
            if (count == 0) {
                return ""
            }
            if (count == 1) {
                return terms[1]
            }
            return join_logic_expr("AND", terms, count)
        }

        {
            lines[++total] = $0
        }

        END {
            for (i = 1; i <= total; i++) {
                if (!parse_line(lines[i])) {
                    continue
                }
                analyze_modifiers(p_mods)
                if (m_badfilter == 1) {
                    disabled[p_core] = 1
                }
            }

            for (i = 1; i <= total; i++) {
                if (!parse_line(lines[i])) {
                    continue
                }
                analyze_modifiers(p_mods)

                if (m_badfilter == 1) {
                    skipped_badfilter++
                    continue
                }
                if (disabled[p_core] == 1) {
                    skipped_badfilter++
                    continue
                }
                if (m_unsupported == 1) {
                    skipped_unsupported++
                    continue
                }

                if (p_type == "regex") {
                    if (p_regex == "") {
                        continue
                    }
                    ip_rule_mode = ""
                    if (regex_to_precise_ip_rule(p_regex)) {
                        ip_rule_mode = "precise"
                    } else if (regex_to_ipv4_prefix_rule(p_regex)) {
                        ip_rule_mode = "prefix"
                    }

                    if (ip_rule_mode != "") {
                        if (ip_rule_mode == "precise") {
                            converted_ip_regex++
                        } else {
                            converted_ip_prefix_regex++
                        }
                        deny_expr = ""
                        if (m_denyallow != "") {
                            deny_expr = denyallow_expr_from_value(m_denyallow)
                            if (deny_expr == "") {
                                skipped_unsupported++
                                continue
                            }
                        }
                        port_expr = ""
                        if (ip_rule_mode == "precise" && port_count > 0) {
                            port_expr = build_port_expr()
                            if (port_expr == "") {
                                skipped_unsupported++
                                continue
                            }
                            converted_ip_port_regex++
                        }

                        for (r = 1; r <= cidr_count; r++) {
                            final_rule = combine_with_and(cidr_rules[r], port_expr, deny_expr)
                            if (final_rule == "") {
                                skipped_unsupported++
                                continue
                            }
                            print final_rule
                        }
                        continue
                    } else {
                        if (!regex_looks_domain_related(p_regex)) {
                            skipped_non_domain_regex++
                            continue
                        }
                        base_rule = "DOMAIN-REGEX," p_regex
                    }
                } else if (p_type == "domain" || p_type == "plain") {
                    base_rule = base_rule_for_target(p_domain)
                    if (base_rule == "") {
                        skipped_unsupported++
                        continue
                    }
                } else {
                    continue
                }

                if (m_denyallow != "") {
                    deny_expr = denyallow_expr_from_value(m_denyallow)
                    if (deny_expr == "") {
                        skipped_unsupported++
                        continue
                    }
                    print combine_with_and(base_rule, "", deny_expr)
                } else {
                    print base_rule
                }
            }

            if (skipped_unsupported > 0) {
                print "[WARN] 跳过 " skipped_unsupported " 条含不受支持 modifier 的 mihomo 规则" > "/dev/stderr"
                if (ENVIRON["STRICT_MIHOMO_MODIFIERS"] == "true") {
                    print "[ERROR] STRICT_MIHOMO_MODIFIERS=true，检测到不受支持 modifier，终止 mihomo 转换" > "/dev/stderr"
                    exit 2
                }
            }
            if (skipped_badfilter > 0) {
                print "[WARN] 跳过 " skipped_badfilter " 条 badfilter 相关 mihomo 规则" > "/dev/stderr"
            }
            if (skipped_non_domain_regex > 0) {
                print "[WARN] 跳过 " skipped_non_domain_regex " 条与域名匹配无关的 regex 规则" > "/dev/stderr"
            }
            if (converted_ip_regex > 0) {
                print "[INFO] 将 " converted_ip_regex " 条可精确识别的 IP regex 转换为 IP-CIDR 规则" > "/dev/stderr"
            }
            if (converted_ip_port_regex > 0) {
                print "[INFO] 将 " converted_ip_port_regex " 条含端口约束的 IP regex 转换为 IP-CIDR + DST-PORT 规则" > "/dev/stderr"
            }
            if (converted_ip_prefix_regex > 0) {
                print "[INFO] 将 " converted_ip_prefix_regex " 条 URL/IP 前缀 regex 转换为近似 IP-CIDR 规则" > "/dev/stderr"
            }
        }
    ' dns.txt | sort -u > "$MIHOMO_RULE_FILE"
}

download_tool() {
    local name=$1
    local url=$2
    local archive=$3
    local bin_in_archive=$4
    local bin_path=$5

    [[ -f "$bin_path" ]] && return 0
    log_info "下载 $name..."

    if download_file "$url" "$TOOLS_DIR/$archive"; then
        if [[ "$archive" == *.tar.gz ]]; then
            tar -zxf "$TOOLS_DIR/$archive" -C "$TOOLS_DIR"
            mv "$TOOLS_DIR/$bin_in_archive" "$bin_path"
            rm -rf "$TOOLS_DIR/${bin_in_archive%%/*}"
        elif [[ "$archive" == *.gz ]]; then
            gzip -d -c "$TOOLS_DIR/$archive" > "$bin_path"
        fi
        chmod +x "$bin_path"
        rm -rf "$TOOLS_DIR/$archive"
    else
        log_error "下载 $name 失败"
        return 1
    fi
}

process_with_singbox() {
    local version="$SINGBOX_VERSION"
    local bin="$TOOLS_DIR/sing-box"
    local url="https://github.com/SagerNet/sing-box/releases/download/v${version}/sing-box-${version}-linux-amd64.tar.gz"

    download_tool "sing-box" "$url" "sb.tar.gz" "sing-box-${version}-linux-amd64/sing-box" "$bin" || return 1

    if "$bin" rule-set convert dns.txt -t adguard --output adrules-singbox.srs; then
        log_info "sing-box 转换完成"
    else
        log_warn "sing-box 转换失败"
        return 1
    fi
}

process_with_mihomo() {
    local bin="$TOOLS_DIR/mihomo"
    local archive="$TOOLS_DIR/mihomo.gz"
    local version_file="$TOOLS_DIR/version.txt"
    local domain_file="$TMP_DIR/mihomo_domain.txt"
    local yaml_raw_file="$TMP_DIR/mihomo_yaml_payload.txt"
    local yaml_file="$ROOT_DIR/adrules-mihomo.yaml"
    local main_mrs_file="$ROOT_DIR/adrules-mihomo.mrs"
    local invalid_file="$TMP_DIR/mihomo_invalid_rules.txt"
    local channel="$MIHOMO_CHANNEL"

    generate_mihomo_classical_rules
    if [[ ! -s "$MIHOMO_RULE_FILE" ]]; then
        log_warn "mihomo classical 规则为空，跳过 mihomo 转换"
        return 0
    fi

    if grep -nEv '^((DOMAIN(-SUFFIX|-WILDCARD|-REGEX)?|IP-CIDR6?|DST-PORT|AND|OR|NOT),)' "$MIHOMO_RULE_FILE" > "$invalid_file"; then
        log_error "检测到非 mihomo classical 语法规则，示例:"
        head -n 10 "$invalid_file" >&2
        rm -f "$invalid_file"
        return 1
    fi
    rm -f "$invalid_file"

    : > "$domain_file"
    : > "$yaml_raw_file"

    awk -F',' -v domain_file="$domain_file" -v yaml_raw_file="$yaml_raw_file" '
        function trim(s) {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", s)
            return s
        }

        {
            line = trim($0)
            if (line == "") {
                next
            }

            if (line ~ /^DOMAIN-SUFFIX,/) {
                value = trim(substr(line, length("DOMAIN-SUFFIX,") + 1))
                if (value != "") {
                    print "+." value >> domain_file
                }
                next
            }

            if (line ~ /^DOMAIN,/) {
                value = trim(substr(line, length("DOMAIN,") + 1))
                if (value != "") {
                    print value >> domain_file
                }
                next
            }

            print line >> yaml_raw_file
        }
    ' "$MIHOMO_RULE_FILE"

    sort -u "$domain_file" -o "$domain_file"
    sort -u "$yaml_raw_file" -o "$yaml_raw_file"

    if [[ -s "$yaml_raw_file" ]]; then
        {
            echo "payload:"
            while IFS= read -r line; do
                escaped=${line//\'/\'\'}
                printf "  - '%s'\n" "$escaped"
            done < "$yaml_raw_file"
        } > "$yaml_file"
    else
        echo "payload: []" > "$yaml_file"
    fi

    if [[ ! -x "$bin" ]]; then
        local version
        if [[ -n "$MIHOMO_VERSION" ]]; then
            version="$MIHOMO_VERSION"
        else
            if ! download_file "https://github.com/MetaCubeX/mihomo/releases/download/${channel}/version.txt" "$version_file"; then
                log_error "mihomo 版本信息下载失败"
                return 1
            fi
            version=$(tr -d '\r\n' < "$version_file")
        fi
        if [[ -z "$version" ]]; then
            log_error "mihomo 版本号为空"
            return 1
        fi

        local url="https://github.com/MetaCubeX/mihomo/releases/download/${channel}/mihomo-linux-amd64-${version}.gz"

        log_info "下载并配置 mihomo ($url)..."
        if ! download_file "$url" "$archive"; then
            log_error "mihomo 下载失败"
            return 1
        fi

        if gzip -d -c "$archive" > "$bin"; then
            chmod +x "$bin"
            rm -f "$archive"
        else
            rm -f "$archive"
            log_error "mihomo 解压失败"
            return 1
        fi
    else
        log_info "检测到本地 mihomo 二进制，跳过下载"
    fi

    if [[ ! -s "$domain_file" ]]; then
        log_warn "未生成可转换为 mihomo domain mrs 的规则"
        return 1
    fi

    if "$bin" convert-ruleset domain text "$domain_file" "$main_mrs_file"; then
        log_info "mihomo domain mrs 转换完成"
    else
        log_warn "mihomo domain mrs 转换失败"
        return 1
    fi

    log_info "mihomo 转换完成（domain mrs + yaml）"
}

if ! process_with_singbox; then
    log_warn "sing-box 产物生成失败，将保留仓库中的历史产物（如果存在）"
    conversion_failed=1
fi

if ! process_with_mihomo; then
    log_warn "mihomo 产物生成失败，将保留仓库中的历史产物（如果存在）"
    conversion_failed=1
fi

if [[ "${conversion_failed:-0}" -eq 1 ]]; then
    if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
        echo "::warning::DNS binary conversion failed (sing-box or mihomo)"
    fi
    if [[ "${STRICT_DNS_CONVERTER}" == "true" ]]; then
        log_error "STRICT_DNS_CONVERTER=true，DNS 二进制转换失败，终止流程"
        exit 1
    fi
fi

rm -f "$MIHOMO_RULE_FILE" "$TMP_DIR/mihomo_domain.txt" "$TMP_DIR/mihomo_yaml_payload.txt"

log_info "DNS 规则更新完成。"
