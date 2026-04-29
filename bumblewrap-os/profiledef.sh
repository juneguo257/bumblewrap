#!/usr/bin/env bash
# shellcheck disable=SC2034

iso_name="bumblewrap-os"
iso_label="BUMBLEWRAP_$(date --date="@${SOURCE_DATE_EPOCH:-$(date +%s)}" +%Y%m)"
iso_publisher="The Bumblewrap Team"
iso_application="Bumblewrap OS"
iso_version="$(date --date="@${SOURCE_DATE_EPOCH:-$(date +%s)}" +%Y.%m.%d)"
install_dir="arch"
buildmodes=('iso')
bootmodes=('bios.syslinux'
           'uefi.grub')
pacman_conf="pacman.conf"
airootfs_image_type="erofs"
airootfs_image_tool_options=('-zlzma,109' -E 'ztailpacking')
bootstrap_tarball_compression=(xz -9e)
file_permissions=(
  ["/etc/shadow"]="0:0:400"
  ["/etc/gshadow"]="0:0:400"
  ["/user"]="1000:1000:755"
  ["/user/.gitkeep"]="1000:1000:644"
  ["/usr/local/bin/clone-bumblewrap.sh"]="0:0:755"
)
