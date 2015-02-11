# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38516
# Finding ID:	V-38516
# Version:	RHEL-06-000126
# Finding Level:	Low
#
#     The Reliable Datagram Sockets (RDS) protocol must be disabled unless 
#     required. Disabling RDS protects the system against exploitation of 
#     any flaws in its implementation.
#
############################################################

script_V38516-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38516.sh

{% if not salt['file.file_exists']('/etc/modprobe.d/rds.conf') %}
file-V38516-touchRules:
  file.touch:
  - name: '/etc/modprobe.d/rds.conf'

file_V38516-appendBlacklist:
  file.append:
  - name: /etc/modprobe.d/rds.conf
  - text: 'install rds /bin/false'
{% elif salt['file.search']('/etc/modprobe.d/rds.conf', '^install rds /bin/false') %}
file_V38516-appendBlacklist:
   cmd.run:
   - name: 'echo "RDS already blacklisted in /etc/modprobe.d/rds.conf"'
{% elif salt['file.file_exists']('/etc/modprobe.d/rds.conf') %}
file_V38516-appendBlacklist:
  file.replace:
  - name: /etc/modprobe.d/rds.conf
  - pattern: '^.*install[ 	]rds.*$'
  - repl: 'install rds /bin/false'
{% endif %}
