#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd "$script_dir/.." && pwd)"
image="$project_root/images/2026-06-18-raspios-trixie-arm64-lite.img.xz"
checksum_file="$image.sha256"
imager="$project_root/tools/Raspberry_Pi_Imager-v2.0.8-desktop-x86_64.AppImage"
expected_image_sha="acff736ca7945e3b305f07cda4abdb870910e12634991da69783611756e381b3"
expected_uncompressed_image_sha="e235fd24fc5f039c08daba7d3abc04aecc7313f979d16d2a3fdad29dd44c33a9"
expected_imager_sha="700519cd01b0a2a085ac73a0e7d4a962853bdb60f091408f0fd4359ce6968110"

target=""
confirmed_target=""
hostname=""
operator_user=""
wifi_connection=""
wifi_country=""
authorized_key=""

usage() {
  cat <<'EOF'
Write and provision one collector microSD card.

Usage:
  scripts/prepare-sd.sh \
    --target /dev/sdX \
    --confirm-device /dev/sdX \
    --hostname collector-a

Required:
  --target DEVICE          Whole removable USB card-reader device, never a partition
  --confirm-device DEVICE  Exact repetition of --target as a destructive-write guard
  --hostname NAME          Unique collector hostname (lowercase letters/digits/hyphens)

Optional:
  --operator USER          Pi SSH/admin account (required)
  --wifi-connection NAME   Existing NetworkManager connection (required)
  --wifi-country CODE      Regulatory country code (required)
  --authorized-key FILE    Public SSH key to authorize (required)

This command destroys all data on the explicitly confirmed target device.
It refuses system/NVMe devices and requires a 16-512 GB removable or USB-backed disk.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) target="${2:-}"; shift 2 ;;
    --confirm-device) confirmed_target="${2:-}"; shift 2 ;;
    --hostname) hostname="${2:-}"; shift 2 ;;
    --operator) operator_user="${2:-}"; shift 2 ;;
    --wifi-connection) wifi_connection="${2:-}"; shift 2 ;;
    --wifi-country) wifi_country="${2:-}"; shift 2 ;;
    --authorized-key) authorized_key="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$target" || -z "$confirmed_target" || -z "$hostname" || -z "$operator_user" || -z "$wifi_connection" || -z "$wifi_country" || -z "$authorized_key" ]]; then
  usage >&2
  exit 2
fi
if [[ "$target" != "$confirmed_target" ]]; then
  echo "Refusing write: --confirm-device must exactly match --target." >&2
  exit 2
fi
if [[ ! "$hostname" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]; then
  echo "Invalid hostname: $hostname" >&2
  exit 2
fi
if [[ ! "$operator_user" =~ ^[a-z_][a-z0-9_-]{0,30}$ ]]; then
  echo "Invalid operator username: $operator_user" >&2
  exit 2
fi
if [[ ! "$wifi_country" =~ ^[A-Z]{2}$ ]]; then
  echo "Invalid Wi-Fi country: $wifi_country" >&2
  exit 2
fi
if [[ ! -b "$target" ]]; then
  echo "Target is not a block device: $target" >&2
  exit 2
fi

target_real="$(readlink -f -- "$target")"
target_type="$(lsblk -dnro TYPE "$target_real")"
target_rm="$(lsblk -dnro RM "$target_real")"
target_transport="$(lsblk -dnro TRAN "$target_real")"
target_size="$(lsblk -bdnro SIZE "$target_real")"
target_model="$(lsblk -dnro MODEL "$target_real" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')"
root_source="$(findmnt -no SOURCE /)"
root_parent="$(lsblk -no PKNAME "$root_source" 2>/dev/null | head -1)"

if [[ "$target_type" != "disk" ]]; then
  echo "Refusing write: target must be a whole disk, not type $target_type." >&2
  exit 2
fi
if [[ "$target_real" == /dev/nvme* || "$target_real" == /dev/mmcblk0 ]]; then
  echo "Refusing protected system-style device: $target_real" >&2
  exit 2
fi
if [[ -n "$root_parent" && "$target_real" == "/dev/$root_parent" ]]; then
  echo "Refusing root filesystem disk: $target_real" >&2
  exit 2
fi
if [[ "$target_rm" != "1" && "$target_transport" != "usb" ]]; then
  echo "Refusing non-removable, non-USB disk: $target_real" >&2
  exit 2
fi
if (( target_size < 14 * 1024 * 1024 * 1024 || target_size > 512 * 1024 * 1024 * 1024 )); then
  echo "Refusing unexpected device capacity: $target_size bytes" >&2
  exit 2
fi

for required_file in "$image" "$checksum_file" "$imager" "$authorized_key"; do
  if [[ ! -f "$required_file" ]]; then
    echo "Required file is missing: $required_file" >&2
    exit 2
  fi
done

actual_image_sha="$(sha256sum "$image" | awk '{print $1}')"
actual_imager_sha="$(sha256sum "$imager" | awk '{print $1}')"
if [[ "$actual_image_sha" != "$expected_image_sha" ]]; then
  echo "Raspberry Pi OS checksum mismatch." >&2
  exit 2
fi
if [[ "$actual_imager_sha" != "$expected_imager_sha" ]]; then
  echo "Raspberry Pi Imager checksum mismatch." >&2
  exit 2
fi

wifi_ssid="$(nmcli --get-values 802-11-wireless.ssid connection show "$wifi_connection")"
wifi_psk="$(nmcli --show-secrets --get-values 802-11-wireless-security.psk connection show "$wifi_connection")"
if [[ -z "$wifi_ssid" || -z "$wifi_psk" ]]; then
  echo "Could not read SSID/PSK from NetworkManager connection: $wifi_connection" >&2
  exit 2
fi

provision_dir="$(mktemp -d)"
first_run="$provision_dir/firstrun.sh"
cleanup() {
  if [[ -d "$provision_dir" ]]; then
    find "$provision_dir" -type f -exec shred -u -- {} + 2>/dev/null || true
    rmdir "$provision_dir" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

bundle="$provision_dir/cws-collector.tar.gz"
tar -C "$project_root" \
  --exclude='./images' \
  --exclude='./tools' \
  --exclude='./qemu' \
  --exclude='./build' \
  --exclude='./cws_autonomous_collector.egg-info' \
  --exclude='*/__pycache__' \
  -czf "$bundle" .

ssid_b64="$(printf '%s' "$wifi_ssid" | base64 -w0)"
psk_b64="$(printf '%s' "$wifi_psk" | base64 -w0)"
key_b64="$(base64 -w0 "$authorized_key")"
bundle_b64="$(base64 -w0 "$bundle")"

cat >"$first_run" <<EOF
#!/bin/bash
set -euo pipefail

hostname_value='$hostname'
operator_user='$operator_user'
wifi_country='$wifi_country'
wifi_ssid="\$(printf '%s' '$ssid_b64' | base64 -d)"
wifi_psk="\$(printf '%s' '$psk_b64' | base64 -d)"

if [[ -x /usr/lib/raspberrypi-sys-mods/imager_custom ]]; then
  /usr/lib/raspberrypi-sys-mods/imager_custom set_hostname "\$hostname_value"
  /usr/lib/raspberrypi-sys-mods/imager_custom set_wlan "\$wifi_ssid" "\$wifi_psk" "\$wifi_country"
  /usr/lib/raspberrypi-sys-mods/imager_custom enable_ssh
else
  printf '%s\n' "\$hostname_value" >/etc/hostname
  systemctl enable ssh
fi

if ! id "\$operator_user" >/dev/null 2>&1; then
  first_user="\$(getent passwd 1000 | cut -d: -f1)"
  if [[ -n "\$first_user" && -x /usr/lib/userconf-pi/userconf ]]; then
    /usr/lib/userconf-pi/userconf "\$first_user" "\$operator_user" ""
  else
    useradd --create-home --shell /bin/bash --groups sudo "\$operator_user"
  fi
fi
passwd --lock "\$operator_user" || true
systemctl disable userconfig.service || true
systemctl mask userconfig.service || true
operator_home="\$(getent passwd "\$operator_user" | cut -d: -f6)"
test -n "\$operator_home"
install -d -o "\$operator_user" -g "\$operator_user" -m 0700 "\$operator_home/.ssh"
printf '%s' '$key_b64' | base64 -d >"\$operator_home/.ssh/authorized_keys"
chown "\$operator_user:\$operator_user" "\$operator_home/.ssh/authorized_keys"
chmod 0600 "\$operator_home/.ssh/authorized_keys"
printf '%s ALL=(ALL:ALL) NOPASSWD: ALL\n' "\$operator_user" >"/etc/sudoers.d/90-cws-operator"
chmod 0440 /etc/sudoers.d/90-cws-operator
install -d -m 0755 /etc/ssh/sshd_config.d
cat >/etc/ssh/sshd_config.d/20-cws-key-only.conf <<'SSHCONF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
SSHCONF
systemctl enable ssh
if [[ -n "${CWS_TIMEZONE:-}" ]]; then
  ln -snf "/usr/share/zoneinfo/${CWS_TIMEZONE}" /etc/localtime
  printf '%s\n' "$CWS_TIMEZONE" >/etc/timezone
fi

install -d -m 0755 /opt/cws-collector-source
printf '%s' '$bundle_b64' | base64 -d >/opt/cws-collector-source.tar.gz
tar -xzf /opt/cws-collector-source.tar.gz -C /opt/cws-collector-source
chmod +x /opt/cws-collector-source/scripts/install-pi.sh

cat >/usr/local/sbin/cws-finish-provisioning <<'PROVISION'
#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
/opt/cws-collector-source/scripts/install-pi.sh --operator '$operator_user'
touch /var/lib/cws-provisioning-complete
PROVISION
chmod 0755 /usr/local/sbin/cws-finish-provisioning
cat >/etc/systemd/system/cws-finish-provisioning.service <<'UNIT'
[Unit]
Description=Finish CWS collector provisioning
Wants=network-online.target
After=network-online.target
ConditionPathExists=!/var/lib/cws-provisioning-complete

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/cws-finish-provisioning
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
UNIT
systemctl enable cws-finish-provisioning.service
rfkill unblock wifi || true
EOF
chmod 0600 "$first_run"

echo "Destructive target verified:"
printf '  device: %s\n  model: %s\n  size: %s bytes\n  transport: %s\n  removable: %s\n' \
  "$target_real" "$target_model" "$target_size" "${target_transport:-unknown}" "$target_rm"
echo "Image and Imager checksums are valid. Unmounting target partitions..."

while read -r partition partition_type mountpoints; do
  if [[ "$partition_type" == "part" && -n "${mountpoints:-}" ]]; then
    udisksctl unmount --block-device "$partition"
  fi
done < <(lsblk -nrpo NAME,TYPE,MOUNTPOINTS "$target_real")

echo "Writing Raspberry Pi OS and provisioning $hostname..."
pkexec "$imager" --appimage-extract-and-run --cli \
  --sha256 "$expected_uncompressed_image_sha" \
  --first-run-script "$first_run" \
  "$image" "$target_real"

echo "Write and verification completed for $target_real ($hostname)."
echo "Eject the card, insert it into the Raspberry Pi, and power it on near the configured Wi-Fi network."
