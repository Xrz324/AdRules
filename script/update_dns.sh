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
check_deps awk cat chmod curl grep gzip python sed sort tar tr wc

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
grep -P "^(?:\|\|([a-z0-9.*-]+)\^?|(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)\s+((?:\*|(?:\*\.)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)|((?:\*|(?:\*\.)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+))$" "$dns_raw" | \
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

        function base_rule_for_target(target,    rule, regex) {
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
                rule = ""
            } else {
                rule = "DOMAIN-SUFFIX," target
            }
            return rule
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
                    base_rule = "DOMAIN-REGEX," p_regex
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
                    print "AND,((" base_rule "),(" deny_expr "))"
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

    if grep -nEv '^((DOMAIN(-SUFFIX|-WILDCARD|-REGEX)?|AND|OR|NOT),)' "$MIHOMO_RULE_FILE" > "$invalid_file"; then
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
