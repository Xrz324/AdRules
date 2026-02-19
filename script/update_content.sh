#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/utils.sh"

ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TMP_DIR="${ROOT_DIR}/tmp"
MOD_DIR="${ROOT_DIR}/mod"
CONTENT_DIR="${TMP_DIR}/content"

# 检查依赖
check_deps awk grep sort wc cat

prune_covered_content_domains() {
    local content_file="$1"
    local domain_file="${TMP_DIR}/content_plain_domains.txt"
    local covered_file="${TMP_DIR}/content_covered_domains.txt"
    local tmp_output="${content_file}.tmp"
    local before_count=0
    local after_count=0
    local removed_count=0

    : > "$domain_file"
    : > "$covered_file"

    # 仅处理无 modifier 的纯域名拦截规则：||example.com^
    awk '
        {
            line = $0
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
            if (line ~ /^\|\|[A-Za-z0-9.-]+\^$/) {
                print tolower(substr(line, 3, length(line) - 3))
            }
        }
    ' "$content_file" | sort -u > "$domain_file"

    if [[ ! -s "$domain_file" ]]; then
        log_info "未找到可进行语义去重的纯域名内容规则"
        return 0
    fi

    before_count=$(wc -l < "$content_file")

    awk '
        NR == FNR {
            domains[$1] = 1
            list[++n] = $1
            next
        }
        END {
            for (i = 1; i <= n; i++) {
                d = list[i]
                split(d, parts, ".")
                for (j = 2; j <= length(parts); j++) {
                    parent = parts[j]
                    for (k = j + 1; k <= length(parts); k++) {
                        parent = parent "." parts[k]
                    }
                    if (parent in domains) {
                        print d
                        break
                    }
                }
            }
        }
    ' "$domain_file" "$domain_file" | sort -u > "$covered_file"

    awk '
        NR == FNR {
            covered[$1] = 1
            next
        }
        {
            raw = $0
            line = $0
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
            if (line ~ /^\|\|[A-Za-z0-9.-]+\^$/) {
                domain = tolower(substr(line, 3, length(line) - 3))
                if (domain in covered) {
                    next
                }
                if (domain in seen) {
                    next
                }
                seen[domain] = 1
            }
            print raw
        }
    ' "$covered_file" "$content_file" > "$tmp_output"

    mv "$tmp_output" "$content_file"
    after_count=$(wc -l < "$content_file")
    removed_count=$((before_count - after_count))
    log_info "内容规则语义去重完成: 移除 ${removed_count} 条被父域规则覆盖的纯域名规则"
}

log_info "开始生成最终版内容规则..."

temp_pre="${TMP_DIR}/content_pre.txt"
temp_final="${TMP_DIR}/content_final.txt"
remove_list="${MOD_DIR}/rules/adblock-need-remove.txt"
output_file="${ROOT_DIR}/adblock.txt"

mkdir -p "$TMP_DIR"
> "$temp_pre"

# 先合并本地规则
if [[ -f "${MOD_DIR}/rules/adblock-rules.txt" ]]; then
    cat "${MOD_DIR}/rules/adblock-rules.txt" >> "$temp_pre"
fi

# 再合并所有上游内容规则
shopt -s nullglob
content_files=("${CONTENT_DIR}"/*.txt)
shopt -u nullglob
for f in "${content_files[@]}"; do
    cat "$f" >> "$temp_pre"
done

# 过滤注释和空行（保留 cosmetic/scriptlet 语法）
awk '
    /^[[:space:]]*$/ { next }
    /^[[:space:]]*(!|\[)/ { next }
    /^[[:space:]]*#/ {
        if ($0 ~ /^[[:space:]]*(##|#@#|#\?#|#@\?#|#\$#|#@\$#|#\$\?#|#@\$\?#|#%#|#@%#)/) {
            print
        }
        next
    }
    { print }
' "$temp_pre" > "$temp_final"

# 应用移除规则
if [[ -f "$remove_list" ]]; then
    temp_removed="${TMP_DIR}/content_removed.txt"
    LC_ALL=C grep -vxFf "$remove_list" "$temp_final" > "$temp_removed" || true
    mv "$temp_removed" "$temp_final"
fi

# 去重排序
sort -u "$temp_final" -o "$temp_final"
prune_covered_content_domains "$temp_final"

count=$(wc -l < "$temp_final")
{
    cat "${MOD_DIR}/title/adblock-title.txt"
    echo "! Version: $(get_timestamp)(GMT+8)"
    echo "! Total count: $count"
    cat "$temp_final"
} > "$output_file"

log_info "最终版内容规则生成完成: ${count} 条"
