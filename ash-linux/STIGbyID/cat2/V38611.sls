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

script_V38611-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V38611.sh

{% if salt['file.search']('/etc/ssh/sshd_config', '^IgnoreRhosts')
 %}
file_V38611-repl:
  file.replace:
    - name: '/etc/ssh/sshd_config'
    - pattern: '^IgnoreRhosts.*$'
    - repl: 'IgnoreRhosts yes'
{% else %}
file_V38611-append:
  file.append:
    - name: '/etc/ssh/sshd_config'
    - text:
      - ' '
      - '# Disable use of .rhosts files (per STIG V-38611)'
      - 'IgnoreRhosts yes'
{% endif %}
