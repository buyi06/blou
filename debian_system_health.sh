#!/usr/bin/env bash
#
# Debian 系统全面体检脚本（带美观概览面板）
# 适用：Debian / Ubuntu / 其他基于 Debian 的系统
#
# 用法：
#   chmod +x debian_system_health.sh
#   sudo ./debian_system_health.sh
#
set -euo pipefail

############################
#      样式与工具函数
############################

# 颜色样式（tput 不可用时降级）
if command -v tput >/dev/null 2>&1; then
  RED="$(tput setaf 1)"
  GREEN="$(tput setaf 2)"
  YELLOW="$(tput setaf 3)"
  BLUE="$(tput setaf 4)"
  CYAN="$(tput setaf 6)"
  BOLD="$(tput bold)"
  RESET="$(tput sgr0)"
else
  RED=""; GREEN=""; YELLOW=""; BLUE=""; CYAN=""; BOLD=""; RESET=""
fi

OK="${GREEN}✔${RESET}"
WARN="${YELLOW}▲${RESET}"
BAD="${RED}✖${RESET}"

hr() {
  local width="${COLUMNS:-80}"
  printf '%*s\n' "$width" '' | tr ' ' '═'
}

section() {
  echo
  hr
  echo " ${BOLD}${BLUE}$1${RESET}"
  hr
}

cmd_exists() {
  command -v "$1" >/dev/null 2>&1
}

# 将百分比整数映射为状态：0 OK / 1 WARN / 2 BAD
# 参数：值 阈值_warn 阈值_bad
# 返回：echo 状态码
percent_to_state() {
  local value="$1" warn="$2" bad="$3"
  if [ "$value" -ge "$bad" ]; then
    echo 2
  elif [ "$value" -ge "$warn" ]; then
    echo 1
  else
    echo 0
  fi
}

# 取最大值
max_int() {
  local max=0
  for v in "$@"; do
    [ -n "$v" ] || continue
    if [ "$v" -gt "$max" ]; then max="$v"; fi
  done
  echo "$max"
}

############################
#     一、基础信息收集
############################

OS_NAME="未知"
OS_ID=""
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_NAME="${PRETTY_NAME:-$NAME}"
  OS_ID="${ID:-}"
fi

NOW="$(date '+%F %T')"
HOST="$(hostname)"
KERNEL="$(uname -r)"
ARCH="$(uname -m)"

if cmd_exists nproc; then
  CPU_CORES="$(nproc)"
else
  CPU_CORES="$(grep -cE '^processor' /proc/cpuinfo 2>/dev/null || echo 1)"
fi

# CPU 负载（取 1 分钟平均负载）
LOAD_1M_RAW="$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo 0)"
# 转成整数百分比：load / 核心数 * 100
LOAD_PCT="$(awk -v load="$LOAD_1M_RAW" -v cores="$CPU_CORES" 'BEGIN{ if(cores<=0) cores=1; printf "%d", (load/cores)*100 }')"

# 内存使用
if cmd_exists free; then
  MEM_TOTAL="$(free -m | awk '/^Mem:/ {print $2}')"
  MEM_USED="$(free -m | awk '/^Mem:/ {print $3}')"
  MEM_PCT="$(awk -v u="$MEM_USED" -v t="$MEM_TOTAL" 'BEGIN{ if(t<=0) t=1; printf "%d", (u/t)*100 }')"
else
  MEM_PCT=0
fi

# 磁盘使用（排除 tmpfs、devtmpfs，取最大使用率）
DISK_PCT_MAX=0
while read -r usepct mp; do
  pct="${usepct%%%}"
  [ "$pct" -gt "$DISK_PCT_MAX" ] && DISK_PCT_MAX="$pct"
done < <(df -P -x tmpfs -x devtmpfs | awk 'NR>1 {print $5" "$6}')

# 网络连通性：ping 8.8.8.8
NET_STATUS_CODE=2
NET_RTT="N/A"
if cmd_exists ping; then
  if ping -c 1 -W 2 8.8.8.8 >/tmp/debian_health_ping.log 2>&1; then
    NET_STATUS_CODE=0
    NET_RTT="$(grep -o 'time=[0-9.]\+ ms' /tmp/debian_health_ping.log | head -n1 | awk -F= '{print $2}')"
  else
    NET_STATUS_CODE=2
  fi
fi

# APT 可更新包数量
UPGRADE_COUNT="N/A"
if cmd_exists apt; then
  if apt list --upgradable 2>/dev/null | grep -v '^Listing' >/tmp/debian_health_apt.log 2>&1; then
    # 去掉空行
    UPGRADE_COUNT="$(grep -cv '^\s*$' /tmp/debian_health_apt.log || echo 0)"
  fi
fi

# systemd 失败服务数量
FAILED_SERVICES="N/A"
if cmd_exists systemctl; then
  FAILED_SERVICES="$(systemctl --failed --no-legend 2>/dev/null | grep -cv '^\s*$' || echo 0)"
fi

# SSH 配置状态
SSH_PORT="22"
SSH_ROOT_LOGIN="unknown"
SSH_PWD_AUTH="unknown"
if [ -f /etc/ssh/sshd_config ]; then
  SSH_PORT="$(grep -Ei '^\s*Port\s+' /etc/ssh/sshd_config | awk '{print $2}' | tail -n1 || echo 22)"
  SSH_ROOT_LOGIN="$(grep -Ei '^\s*PermitRootLogin\s+' /etc/ssh/sshd_config | awk '{print $2}' | tail -n1 || echo unknown)"
  SSH_PWD_AUTH="$(grep -Ei '^\s*PasswordAuthentication\s+' /etc/ssh/sshd_config | awk '{print $2}' | tail -n1 || echo unknown)"
fi

# 防火墙状态（只做简单判断）
FW_STATUS_TEXT="未检测到防火墙"
if cmd_exists ufw; then
  if ufw status | grep -iq "active"; then
    FW_STATUS_TEXT="ufw: 已启用"
  else
    FW_STATUS_TEXT="ufw: 未启用"
  fi
elif cmd_exists iptables; then
  IPT_RULES_COUNT="$(iptables -L -n 2>/dev/null | grep -cv 'Chain' || echo 0)"
  if [ "$IPT_RULES_COUNT" -gt 0 ]; then
    FW_STATUS_TEXT="iptables: 有规则"
  else
    FW_STATUS_TEXT="iptables: 无规则"
  fi
fi

############################
#     二、状态等级计算
############################

STATE_CPU="$(percent_to_state "$LOAD_PCT" 150 250)"     # 150% WARN, 250% BAD
STATE_MEM="$(percent_to_state "$MEM_PCT" 70 85)"         # 内存 >70% WARN, >85% BAD
STATE_DISK="$(percent_to_state "$DISK_PCT_MAX" 80 90)"   # 磁盘 >80% WARN, >90% BAD

# 网络：0 OK / 2 BAD
STATE_NET="$NET_STATUS_CODE"

# APT 更新：很多更新时给 WARN
STATE_UPGRADE=0
if [ "$UPGRADE_COUNT" != "N/A" ]; then
  if [ "$UPGRADE_COUNT" -ge 50 ]; then
    STATE_UPGRADE=2
  elif [ "$UPGRADE_COUNT" -ge 10 ]; then
    STATE_UPGRADE=1
  fi
fi

# systemd 失败服务
STATE_SVC=0
if [ "$FAILED_SERVICES" != "N/A" ]; then
  if [ "$FAILED_SERVICES" -ge 5 ]; then
    STATE_SVC=2
  elif [ "$FAILED_SERVICES" -ge 1 ]; then
    STATE_SVC=1
  fi
fi

# 安全：根据 SSH 和防火墙大概给个评估
STATE_SEC=0
if [ "$SSH_PWD_AUTH" = "yes" ] || [ "$SSH_ROOT_LOGIN" = "yes" ]; then
  STATE_SEC=2
elif [ "$FW_STATUS_TEXT" = "未检测到防火墙" ] || echo "$FW_STATUS_TEXT" | grep -iq "未启用"; then
  [ "$STATE_SEC" -lt 1 ] && STATE_SEC=1
fi

# 计算总健康等级：取各子项最大等级
OVERALL_STATE="$(max_int "$STATE_CPU" "$STATE_MEM" "$STATE_DISK" "$STATE_NET" "$STATE_UPGRADE" "$STATE_SVC" "$STATE_SEC")"

state_to_icon() {
  case "$1" in
    0) echo "$OK" ;;
    1) echo "$WARN" ;;
    2) echo "$BAD" ;;
    *) echo "$WARN" ;;
  esac
}

state_to_text() {
  case "$1" in
    0) echo "${GREEN}良好${RESET}" ;;
    1) echo "${YELLOW}需关注${RESET}" ;;
    2) echo "${RED}存在问题${RESET}" ;;
    *) echo "${YELLOW}未知${RESET}" ;;
  esac
}

############################
#   三、总体健康概览面板
############################

clear 2>/dev/null || true

hr
echo " ${BOLD}${CYAN}Debian 系统健康总览${RESET}"
hr

echo " 主机名     : ${BOLD}${HOST}${RESET}"
echo " 系统       : ${OS_NAME}"
echo " 内核       : ${KERNEL} (${ARCH})"
echo " 当前时间   : ${NOW}"

echo
echo " ${BOLD}总体健康状态：$(state_to_icon "$OVERALL_STATE") $(state_to_text "$OVERALL_STATE")${RESET}"
echo

# 用「卡片式」单行总览
printf ' %-12s %s\n' "CPU 负载"   "$(state_to_icon "$STATE_CPU") 约 ${LOAD_PCT}%% / ${CPU_CORES} 核心"
printf ' %-12s %s\n' "内存使用"   "$(state_to_icon "$STATE_MEM") 已用约 ${MEM_PCT}%%"
printf ' %-12s %s\n' "磁盘使用"   "$(state_to_icon "$STATE_DISK") 最大分区使用 ${DISK_PCT_MAX}%%"
if [ "$NET_STATUS_CODE" -eq 0 ]; then
  printf ' %-12s %s\n' "网络连通"   "$(state_to_icon "$STATE_NET") 可访问 8.8.8.8, RTT ${NET_RTT}"
else
  printf ' %-12s %s\n' "网络连通"   "$(state_to_icon "$STATE_NET") 无法访问 8.8.8.8"
fi

if [ "$UPGRADE_COUNT" != "N/A" ]; then
  printf ' %-12s %s\n' "系统更新"   "$(state_to_icon "$STATE_UPGRADE") 可升级包数量：${UPGRADE_COUNT}"
fi

if [ "$FAILED_SERVICES" != "N/A" ]; then
  printf ' %-12s %s\n' "系统服务"   "$(state_to_icon "$STATE_SVC") 失败服务数量：${FAILED_SERVICES}"
fi

printf ' %-12s %s\n' "安全配置" "$(state_to_icon "$STATE_SEC") SSH root=${SSH_ROOT_LOGIN}, 密码登录=${SSH_PWD_AUTH}, 防火墙：${FW_STATUS_TEXT}"

echo
hr
echo " 说明：${GREEN}✔ 良好${RESET}  ${YELLOW}▲ 需关注${RESET}  ${RED}✖ 存在问题${RESET}"
hr

############################
#   四、详细信息（可折叠结构）
############################

section "CPU 与内存详情"

echo "[CPU 基本信息]"
if cmd_exists lscpu; then
  lscpu | sed -n '1,15p'
else
  grep -m 5 "model name" /proc/cpuinfo 2>/dev/null || true
fi

echo
echo "[负载与运行时间]"
uptime || true

echo
echo "[内存使用情况]"
if cmd_exists free; then
  free -h
else
  cat /proc/meminfo | sed -n '1,15p'
fi

echo
echo "[前 10 个占用 CPU 的进程]"
ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -n 11

echo
echo "[前 10 个占用内存的进程]"
ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -n 11

section "磁盘与文件系统详情"

echo "[磁盘使用情况 df -hT]"
df -hT

echo
echo "[块设备信息 lsblk]"
if cmd_exists lsblk; then
  lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT
fi

echo
echo "[inode 使用情况]"
df -hi

echo
if cmd_exists mount; then
  echo "[挂载信息（关注是否有 read-only）]"
  mount | sed -n '1,60p'
fi

echo
if cmd_exists smartctl; then
  echo "[磁盘 SMART 状态（smartctl -H）]"
  for disk in /dev/sd? /dev/vd? /dev/nvme?n1; do
    [ -e "$disk" ] || continue
    echo
    echo "磁盘：$disk"
    smartctl -H "$disk" || true
  done
else
  echo "${YELLOW}[提示] 未安装 smartmontools，无法检测 SMART，可执行：sudo apt install smartmontools${RESET}"
fi

section "网络配置与连接详情"

echo "[IP 地址信息]"
if cmd_exists ip; then
  ip addr show
else
  ifconfig || true
fi

echo
echo "[路由信息]"
if cmd_exists ip; then
  ip route show
fi

echo
echo "[监听端口（前 50 行）]"
if cmd_exists ss; then
  ss -tulnp | head -n 50
elif cmd_exists netstat; then
  netstat -tulnp | head -n 50
else
  echo "${YELLOW}[提示] 未找到 ss/netstat，无法列出监听端口${RESET}"
fi

echo
echo "[DNS 配置]"
if cmd_exists resolvectl; then
  resolvectl status 2>/dev/null | sed -n '1,60p' || true
elif [ -f /etc/resolv.conf ]; then
  cat /etc/resolv.conf
fi

section "服务与计划任务"

if cmd_exists systemctl; then
  echo "[systemd 失败服务列表]"
  systemctl --failed || true

  echo
  echo "[开机默认目标]"
  systemctl get-default || true
fi

echo
echo "[当前登录用户]"
who || true

echo
echo "[最近登录记录（last，最近 10 条）]"
if cmd_exists last; then
  last -n 10 || true
fi

echo
echo "[计划任务 crontab]"
echo "- 当前用户 crontab："
crontab -l 2>/dev/null || echo "  无 crontab"

if [ -d /etc/cron.d ]; then
  echo
  echo "- /etc/cron.d："
  ls -l /etc/cron.d
fi

for f in /etc/crontab /etc/cron.daily /etc/cron.weekly /etc/cron.hourly; do
  [ -e "$f" ] || continue
  echo
  echo "- $f："
  ls -ld "$f"
done

section "软件包与更新情况"

if cmd_exists apt; then
  echo "[APT 源列表]"
  ls -1 /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null || true

  echo
  echo "[可升级包（前 50 行，仅作参考）]"
  if [ -s /tmp/debian_health_apt.log ]; then
    head -n 50 /tmp/debian_health_apt.log
  else
    apt list --upgradable 2>/dev/null | head -n 50 || echo "  暂无或获取失败"
  fi

  echo
  echo "[APT 缓存检查（模拟：apt-get -s check）]"
  apt-get -s check || true
else
  echo "${YELLOW}[提示] 未找到 apt 命令，可能不是基于 Debian 的系统${RESET}"
fi

section "系统日志与错误概览"

if cmd_exists journalctl; then
  echo "[最近一次启动以来的错误级别日志（journalctl -p 3 -xb，前 80 行）]"
  journalctl -p 3 -xb | head -n 80 || true
else
  echo "${YELLOW}[提示] 未找到 journalctl，可能不是 systemd 系统${RESET}"
fi

echo
echo "[dmesg 中的错误或警告（前 80 行）]"
if cmd_exists dmesg; then
  dmesg 2>/dev/null | egrep -i "error|fail|warn|critical" | head -n 80 || echo "  未发现明显错误关键字"
fi

section "基础安全检查"

echo "[SSH 关键配置项]"
if [ -f /etc/ssh/sshd_config ]; then
  egrep -ni "^\s*(Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication)" /etc/ssh/sshd_config || true
else
  echo "  未找到 /etc/ssh/sshd_config"
fi

echo
echo "[最近 50 条 SSH 登录相关日志]"
if cmd_exists journalctl; then
  journalctl -u ssh -n 50 --no-pager 2>/dev/null || journalctl -u sshd -n 50 --no-pager 2>/dev/null || echo "  无相关日志或服务名不同"
fi

echo
echo "[防火墙状态详情]"
if cmd_exists ufw; then
  ufw status verbose || true
elif cmd_exists iptables; then
  iptables -L -n -v | head -n 80 || true
else
  echo "  未检测到 ufw/iptables 管理工具"
fi

section "虚拟化与容器环境"

echo "[虚拟化检测]"
if cmd_exists systemd-detect-virt; then
  systemd-detect-virt || true
fi

echo
echo "[Docker / 容器运行时状态]"
if cmd_exists docker; then
  echo "Docker 版本："
  docker --version || true
  echo
  echo "当前容器："
  docker ps || true
fi

if cmd_exists podman; then
  echo
  echo "podman 版本："
  podman --version || true
fi

if cmd_exists containerd; then
  echo
  echo "containerd 版本："
  containerd --version || true
fi

section "体检结束"

echo "${BOLD}建议阅读顺序：${RESET}"
echo "  1. 顶部『总体健康总览』一眼判断是否有大问题"
echo "  2. 若有 WARN/✖ 项，再查看对应模块的详细信息"
echo "  3. 有需要可以将输出保存到文件："
echo
echo "     sudo ./debian_system_health.sh | tee system_health_$(date +%F).log"
echo
echo "${GREEN}本次检查已完成${RESET}"