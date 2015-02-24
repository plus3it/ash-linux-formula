# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38680
# Finding ID:	V-38680
# Version:	RHEL-06-000313
# Finding Level:	Medium
#
#     The audit system must identify staff members to receive notifications 
#     of audit log storage volume capacity issues. Email sent to the root 
#     account is typically aliased to the administrators of the system, who 
#     can take appropriate action.
#
#  CCI: CCI-000139
#  NIST SP 800-53 :: AU-5 a
#  NIST SP 800-53A :: AU-5.1 (ii)
#  NIST SP 800-53 Revision 4 :: AU-5 a
#
############################################################

script_V38680-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V38680.sh
    - cwd: '/root'

{% if salt['file.file_exists']('/etc/audit/auditd.conf') %}
file_V38680-repl:
  file.replace:
    - name: '/etc/audit/auditd.conf'
    - pattern: '^action_mail_acct.*$'
    - repl: 'action_mail_acct = root'
{% else %}
warn_V38680:
  cmd.run:
    - name: 'echo "The audit config file (/etc/audit/auditd.conf) does not exist"'
{% endif %}
