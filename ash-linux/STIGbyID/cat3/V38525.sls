# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38525
# Finding ID:	V-38525
# Version:	RHEL-06-000169
# Finding Level:	Low
#
#     Arbitrary changes to the system time can be used to obfuscate 
#     nefarious activities in log files, as well as to confuse network 
#     services that are highly dependent upon an accurate system time (such 
#     as sshd). All changes to the system time should be audited. 
#
############################################################

script_V38525-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38525.sh

{% if grains['cpuarch'] == 'x86_64' %}
file_V38525-settimeofday:
  cmd.run:
  - name: 'echo "Not applicable to 64-bit systems: no changes made"'
{% else %}
file_V38525-settimeofday:
  cmd.run:
  - name: 'echo "Architecture not supported: no changes made"'
{% endif %}
