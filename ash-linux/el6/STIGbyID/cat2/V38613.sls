# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38613
# Finding ID:	V-38613
# Version:	RHEL-06-000237
# Finding Level:	Medium
#
#     The system must not permit root logins using remote access programs 
#     such as ssh. Permitting direct root login reduces auditable 
#     information about who ran privileged commands on the system and also 
#     allows direct attack attempts on root's password.
#
#  CCI: CCI-000770
#  NIST SP 800-53 :: IA-2 (5) (b)
#  NIST SP 800-53A :: IA-2 (5).2 (ii)
#  NIST SP 800-53 Revision 4 :: IA-2 (5)
#
############################################################
{%- set stigId = 'V38613' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set cfgFile = '/etc/ssh/sshd_config' %}
{%- set parmName = 'PermitRootLogin' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

{%- if salt.file.search(cfgFile, '^' + parmName)
 %}
file_{{ stigId }}-repl:
  file.replace:
    - name: '{{ cfgFile }}'
    - pattern: '^{{ parmName }}.*$'
    - repl: '{{ parmName }} no'
{%- else %}
file_{{ stigId }}-append:
  file.append:
    - name: '{{ cfgFile }}'
    - text:
      - ' '
      - '# Disable host-based authentication (per STIG V-38613)'
      - '{{ parmName }} no'
{%- endif %}
