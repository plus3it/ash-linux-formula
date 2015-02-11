# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38522
# Finding ID:	V-38522
# Version:	RHEL-06-000167
# Finding Level:	Low
#
#     Arbitrary changes to the system time can be used to obfuscate 
#     nefarious activities in log files, as well as to confuse network 
#     services that are highly dependent upon an accurate system time (such 
#     as sshd). All changes to the system time should be audited. 
#
############################################################
 
script_V38522-describe:
  cmd.script:
    - source: salt://STIGbyID/cat3/files/V38522.sh

{% if grains['cpuarch'] == 'x86_64' %}
  {% if salt['file.search']('/etc/audit/audit.rules', '-a always,exit -F arch=b64 -S settimeofday -k audit_time_rules') %}
file_V38522-settimeofday:
  cmd.run:
    - name: 'echo "Appropriate audit-rule already present"'
  {% else %}
file_V38522-settimeofday:
  file.append:
    - name: '/etc/audit/audit.rules'
    - text:
      - '# Audit all system time-modifications via settimeofday (per STIG-ID V-38522)'
      - '-a always,exit -F arch=b64 -S settimeofday -k audit_time_rules'
  {% endif %}
{% else %}
file_V38522-settimeofday:
  cmd.run:
    - name: 'echo "Architecture not supported: no changes made"'
{% endif %}
