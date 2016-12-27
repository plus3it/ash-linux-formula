# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38615
# Finding ID:	V-38615
# Version:	RHEL-06-000240
# Finding Level:	Medium
#
#     The SSH daemon must be configured with the Department of Defense 
#     (DoD) login banner. The warning message reinforces policy awareness 
#     during the logon process and facilitates possible legal action 
#     against attackers. Alternatively, systems whose ownership should not 
#     be obvious should ...
#
#  CCI: CCI-000048
#  NIST SP 800-53 :: AC-8 a
#  NIST SP 800-53A :: AC-8.1 (ii)
#  NIST SP 800-53 Revision 4 :: AC-8 a
#
############################################################

{%- set stigId = 'V38615' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set cfgFile = '/etc/ssh/sshd_config' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

{%- if salt.file.search(cfgFile, '^Banner')
 %}
file_{{ stigId }}-repl:
  file.replace:
    - name: '{{ cfgFile }}'
    - pattern: '^Banner.*$'
    - repl: 'Banner /etc/issue'
{%- else %}
file_{{ stigId }}-append:
  file.append:
    - name: '{{ cfgFile }}'
    - text:
      - ' '
      - '# SSH service must present DoD login banners (per STIG V-38615)'
      - 'Banner /etc/issue'
{%- endif %}

