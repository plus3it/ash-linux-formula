# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38495
# Finding ID:	V-38495
# Version:	RHEL-06-000384
# Finding Level:	Medium
#
#     Audit log files must be owned by root. If non-privileged users can 
#     write to audit logs, audit trails can be modified or destroyed.
#
#  CCI: CCI-000162
#  NIST SP 800-53 :: AU-9
#  NIST SP 800-53A :: AU-9.1
#  NIST SP 800-53 Revision 4 :: AU-9
#
############################################################

{%- set stigId = 'V38495' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

directory_{{ stigId }}:
  file.directory:
    - name: /var/log/audit
    - user: root
    - recurse:
      - user
