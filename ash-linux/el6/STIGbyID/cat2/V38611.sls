# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38611
# Finding ID:	V-38611
# Version:	RHEL-06-000234
# Finding Level:	Medium
#
#     The SSH daemon must ignore .rhosts files. SSH trust relationships 
#     mean a compromise on one host can allow an attacker to move trivially 
#     to other hosts.
#
#  CCI: CCI-000766
#  NIST SP 800-53 :: IA-2 (2)
#  NIST SP 800-53A :: IA-2 (2).1
#  NIST SP 800-53 Revision 4 :: IA-2 (2)
#
############################################################

{%- set stigId = 'V38611' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set cfgFile = '/etc/ssh/sshd_config' %}
{%- set parmName = 'IgnoreRhosts' %}

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
    - repl: '{{ parmName }} yes'
{%- else %}
file_{{ stigId }}-append:
  file.append:
    - name: '{{ cfgFile }}'
    - text:
      - ' '
      - '# Disable use of .rhosts files (per STIG V-38611)'
      - '{{ parmName }} yes'
{%- endif %}
