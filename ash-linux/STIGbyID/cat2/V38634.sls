# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38634
# Finding ID:	V-38634
# Version:	RHEL-06-000161
# Finding Level:	Medium
#
#     Automatically rotating logs (by setting this to "rotate") minimizes 
#     the chances of the system unexpectedly running out of disk space by 
#     being overwhelmed with log data. However, for systems that must never 
#     discard log data, or which use external processes to transfer it and 
#     reclaim space, "keep_logs" can be employed. 
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

script_V38634-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V38634.sh

{% if salt['pkg.version']('audit') and salt['file.search']('/etc/audit/auditd.conf', '^max_log_file_action') %}
file_V38634-repl:
  file.replace:
    - name: '/etc/audit/auditd.conf'
    - pattern: '^max_log_file_action.*$'
    - repl: 'max_log_file_action = rotate'
{% elif salt['pkg.version']('audit') and not salt['file.search']('/etc/audit/auditd.conf', '^max_log_file_action') %}
file_V38634-append:
  file.append:
    - name: '/etc/audit/auditd.conf'
    - text:
      - ' '
      - '# audit system must rotate logs (per STIG V-38634)'
      - 'max_log_file_action = rotate'
{% endif %}

