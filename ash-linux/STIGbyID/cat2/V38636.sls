# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38636
# Finding ID:	V-38636
# Version:	RHEL-06-000159
# Finding Level:	Medium
#
#     The system must retain enough rotated audit logs to cover the 
#     required log retention period. The total storage for audit log files 
#     must be large enough to retain log information over the period 
#     required. This is a function of the maximum log file size and the 
#     number of logs retained.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

script_V38636-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38636.sh

{% if salt['pkg.version']('audit') and salt['file.search']('/etc/audit/auditd.conf', '^num_logs') %}
file_V38636-repl:
  file.replace:
  - name: '/etc/audit/auditd.conf'
  - pattern: '^num_logs.*$'
  - repl: 'num_logs = 5'
{% elif salt['pkg.version']('audit') and not salt['file.search']('/etc/audit/auditd.conf', '^num_logs') %}
file_V38636-append:
  file.append:
  - name: '/etc/audit/auditd.conf'
  - text:
    - ' '
    - '# system must retain enough rotated logs to meet local policy (per STIG V-38636)'
    - 'num_logs = 5'
{% endif %}

