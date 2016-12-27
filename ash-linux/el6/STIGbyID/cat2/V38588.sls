# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38588
# Finding ID:	V-38588
# Version:	RHEL-06-000070
# Finding Level:	Medium
#
#     The system must not permit interactive boot. Using interactive boot, 
#     the console user could disable auditing, firewalls, or other 
#     services, weakening system security.
#
#  CCI: CCI-000213
#  NIST SP 800-53 :: AC-3
#  NIST SP 800-53A :: AC-3.1
#  NIST SP 800-53 Revision 4 :: AC-3
#
############################################################

{%- set stigId = 'V38588' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set chkFile = '/etc/sysconfig/init' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

# Conditional replace or append
{%- if salt.file.search(chkFile, '^PROMPT') %}
file_{{ stigId }}-repl:
  file.replace:
    - name: '{{ chkFile }}'
    - pattern: '^PROMPT.*$'
    - repl: 'PROMPT=no' 
{%- else %}
file_{{ stigId }}-append:
  file.append:
    - name: '{{ chkFile }}'
    - text:
      - ' '
      - '# Disable interactive-booting of system (per STIG V-38588)'
      - 'PROMPT=no' 
{%- endif %}
