#! /bin/sh

echo "nameserver 1.1.1.1" > /etc/resolv.conf
git clone --depth=1 https://github.com/juneguo257/bumblewrap /opt/bumblewrap
rm /etc/pacman.d/hooks/clone-bumblewrap.hook
rm /usr/local/bin/clone-bumblewrap.sh