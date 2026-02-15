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

# 过滤注释和空行（保留 ABP 的 ##/#@#/#?#/#$#/#@$# 语法）
awk '
    /^[[:space:]]*$/ { next }
    /^[[:space:]]*(!|\[)/ { next }
    /^[[:space:]]*#/ {
        if ($0 ~ /^[[:space:]]*(##|#@#|#\?#|#\$#|#@\$#)/) {
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

count=$(wc -l < "$temp_final")
{
    cat "${MOD_DIR}/title/adblock-title.txt"
    echo "! Version: $(get_timestamp)(GMT+8)"
    echo "! Total count: $count"
    cat "$temp_final"
} > "$output_file"

log_info "最终版内容规则生成完成: ${count} 条"
