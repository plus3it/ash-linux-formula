# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38493
# Finding ID:	V-38493
# Version:	RHEL-06-000385
# Finding Level:	Medium
#
#     Audit log directories must have mode 0755 or less permissive. If 
#     users can delete audit logs, audit trails can be modified or 
#     destroyed.
#
#  CCI: CCI-000164
#  NIST SP 800-53 :: AU-9
#  NIST SP 800-53A :: AU-9.1
#  NIST SP 800-53 Revision 4 :: AU-9
#
############################################################

{%- set stigId = 'V38493' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

directory_{{ stigId }}:
  file.directory:
    - name: /var/log/audit
    - mode: 700
