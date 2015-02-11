# Offload lists to reduce enumeration-overhead
include:
  - fix_perms/0400_mode
  - fix_perms/0444_mode
  - fix_perms/0600_mode
  - fix_perms/0640_mode
  - fix_perms/0700_mode
  - fix_perms/0750_mode

# Singleton...
0744_auditdInit:
  file.managed:
  - name: /etc/rc.d/init.d/auditd
  - mode: 0744

# Singleton...
0755_EtcSecurity:
  file.directory:
  - name: /etc/security
  - dir_mode: 755
