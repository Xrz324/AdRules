# Adblock-Rules

English | [简体中文](README_zh-CN.md)

## Rules

- Content filtering
  - `adblock.txt`
- DNS filtering (ABP syntax)
  - `dns.txt`
- Rulesets for proxy tools
  - `adrules-singbox.srs`
  - `adrules-mihomo.mrs`
- Mihomo supplements (for rules that cannot be expressed in MRS)
  - `adrules-mihomo.yaml`

## Notes

- When `dns.txt` is simplified, rules disabled by an equivalent `$badfilter` rule are intentionally omitted.
- Mihomo should load both `adrules-mihomo.mrs` and `adrules-mihomo.yaml`. The latter is a supplement only and cannot be used as a complete ruleset.
- This project includes some relatively aggressive blocking rules. Review them before deciding whether to use them.
