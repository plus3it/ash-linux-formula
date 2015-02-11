# This state file addresses audit-related STIG findings:
#
#    GEN002720 (CAT II): The SA will configure the auditing system to
#         auditlogon (unsuccessful and successful) and logout (successful)
#    --------------------
#    GEN002780: (CAT II): The SA will configure the auditing system to
#         audit use of privileged commands (unsuccessful and successful)
#    --------------------
#    GEN002840: (CAT II): The SA will configure the auditing system to
#         audit all security personnel actions
#    --------------------
#    GEN002760: (CAT II): The SA will configure the auditing system to
#         audit unauthorized access attempts to files (unsuccessful)
#    --------------------
#    GEN002800: (CAT II): The SA will configure the auditing system to
#         audit files and programs deleted by the user (successful and
#         unsuccessful)
#    --------------------
#    GEN002740: (CAT II): The SA will configure the auditing system to
#         audit discretionary access control permission modification
#         (unsuccessful and successful use of chown/chmod)
#    --------------------
#    GEN002820: (CAT II): The SA will configure the auditing system to
#         audit all system administration actions
#
#############################################################################


# Make sure the package is installed
audit-pkg-local: # State ID
  pkg.installed:
  - name: audit

# Govern the permissions on our config files
auditd-etc_dir-local:
  file.directory:
  - name: /etc/audit
  - user: root
  - group: root
  - dir_mode: 700
  - file_mode: 600
  - recurse:
    - user
    - group
    - mode

# Govern the permissions on our log files
auditd-log_dir-local:
  file.directory:
  - name: /var/log/audit
  - user: root
  - group: root
  - dir_mode: 700
  - file_mode: 600
  - recurse:
    - user
    - group
    - mode

# Put reference service-config file in place
audit-conf-local:
  file.managed:
  - name: /etc/audit/auditd.conf
  - source: salt://audit/files/auditd.conf

# Put reference rules-config file in place
audit-rules-local:
  file.managed:
  - name: /etc/audit/audit.rules
  - source: salt://audit/files/audit.rules

