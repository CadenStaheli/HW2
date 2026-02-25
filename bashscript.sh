#!/usr/bin/env bash
#
# NCAE Rocky 9: SSH key auth for MULTIPLE pre-created users + Fail2Ban

set -euo pipefail

### CONFIGURE HERE ###
ALLOWED_USERS="admin serviceuser webuser"  # Space-separated PRE-CREATED users
SSH_PUBKEY=""                              # Paste ~/.ssh/id_ed25519.pub content OR file path
SSH_PORT=22
FAIL2BAN_BANTIME=3600
FAIL2BAN_MAXRETRY=5

##############################

# SELinux
if [[ $(getenforce) != "Disabled" ]]; then SELINUX="yes"; fi

echo "[*] Installing/updating packages..."
dnf install -y openssh-server fail2ban

echo "[*] Firewall..."
systemctl enable --now firewalld
firewall-cmd --add-service=ssh --permanent
firewall-cmd --reload

# Validate & add key to EACH allowed user
for USER in $ALLOWED_USERS; do
  if ! id "$USER" &>/dev/null; then
    echo "[!] User $USER does not exist—skipping."
    continue
  fi
  
  echo "[*] Configuring SSH key for $USER..."
  USERHOME=$(getent passwd "$USER" | cut -d: -f6)
  sudo -u "$USER" mkdir -p "$USERHOME/.ssh" || sudo mkdir -p "$USERHOME/.ssh"
  
  if [[ -f "$SSH_PUBKEY" ]]; then
    cat "$SSH_PUBKEY" | sudo -u "$USER" tee -a "$USERHOME/.ssh/authorized_keys" >/dev/null
  else
    echo "$SSH_PUBKEY" | sudo -u "$USER" tee -a "$USERHOME/.ssh/authorized_keys" >/dev/null
  fi
  
  sudo chown -R "$USER:$USER" "$USERHOME/.ssh"
  sudo chmod 700 "$USERHOME/.ssh"
  sudo chmod 600 "$USERHOME/.ssh/authorized_keys"
  
  if [[ $SELINUX == "yes" ]]; then
    restorecon -Rv "$USERHOME/.ssh"
  fi
  echo "  ✓ $USER ready"
done

# Harden sshd_config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
SSHD_CONFIG="/etc/ssh/sshd_config"

sed -i \
  -e 's/#*PasswordAuthentication.*/PasswordAuthentication no/' \
  -e 's/#*PubkeyAuthentication.*/PubkeyAuthentication yes/' \
  -e 's/#*PermitRootLogin.*/PermitRootLogin no/' \
  -e 's/#*X11Forwarding.*/X11Forwarding no/' \
  -e 's/#*MaxAuthTries.*/MaxAuthTries 3/' \
  -e 's/#*ClientAliveInterval.*/ClientAliveInterval 300/' \
  -e 's/#*ClientAliveCountMax.*/ClientAliveCountMax 2/' \
  -e "/^Port/s/.*/Port $SSH_PORT/" \
  "$SSHD_CONFIG"

echo "AllowUsers $ALLOWED_USERS" >> "$SSHD_CONFIG"

sshd -t || { echo "Config error! Revert: mv /etc/ssh/sshd_config.bak /etc/ssh/sshd_config"; exit 1; }
systemctl enable --now sshd
systemctl restart sshd

# Fail2Ban
mkdir -p /etc/fail2ban/jail.d
cat > /etc/fail2ban/jail.d/ncae-sshd.conf <<EOF
[sshd]
enabled  = true
port     = $SSH_PORT
filter   = sshd
logpath  = /var/log/secure
maxretry = $FAIL2BAN_MAXRETRY
findtime = 600
bantime  = $FAIL2BAN_BANTIME
EOF

systemctl enable --now fail2ban
systemctl restart fail2ban

if [[ $SELINUX == "yes" ]]; then
  setsebool -P sshd_read_user_content 1
fi

echo
echo "========================================================="
echo "Multi-user SSH hardened!"
echo "- Users with key auth: $ALLOWED_USERS"
echo "- Test each: ssh user@\$IP"
echo "- Fail2Ban: Active on sshd (/var/log/secure)"
echo "- Verify: sshd -T | grep -E 'password|permitroot|allow'"
echo "========================================================="
