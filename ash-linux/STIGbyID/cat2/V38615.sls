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

script_V38615-describe:
  cmd.script:
    - source: salt://STIGbyID/cat2/files/V38615.sh

{% if salt['file.search']('/etc/ssh/sshd_config', '^Banner')
 %}
file_V38615-repl:
  file.replace:
    - name: '/etc/ssh/sshd_config'
    - pattern: '^Banner.*$'
    - repl: 'Banner /etc/issue'
{% else %}
file_V38615-append:
  file.append:
    - name: '/etc/ssh/sshd_config'
    - text:
      - ' '
      - '# SSH service must present DoD login banners (per STIG V-38615)'
      - 'Banner /etc/issue'
{% endif %}

