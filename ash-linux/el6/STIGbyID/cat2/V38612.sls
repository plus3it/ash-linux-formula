# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38612
# Finding ID:	V-38612
# Version:	RHEL-06-000236
# Finding Level:	Medium
#
#     The SSH daemon must not allow host-based authentication. SSH trust 
#     relationships mean a compromise on one host can allow an attacker to 
#     move trivially to other hosts.
#
#  CCI: CCI-000766
#  NIST SP 800-53 :: IA-2 (2)
#  NIST SP 800-53A :: IA-2 (2).1
#  NIST SP 800-53 Revision 4 :: IA-2 (2)
#
############################################################

{%- set stigId = 'V38612' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set cfgFile = '/etc/ssh/sshd_config' %}
{%- set parmName = 'HostbasedAuthentication' %}

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
      - '# Disable host-based authentication (per STIG V-38612)'
      - '{{ parmName }} no'
{%- endif %}

