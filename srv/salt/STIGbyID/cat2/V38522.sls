# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38522
# Finding ID:	V-38522
# Version:	RHEL-06-000167
# Finding Level:	Medium
#
#     Arbitrary changes to the system time can be used to obfuscate 
#     nefarious activities in log files, as well as to confuse network 
#     services that are highly dependent upon an accurate system time (such 
#     as sshd). All changes to the system time should be audited. 
#
############################################################################

script_V38522-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38522.sh

{% if grains['cpuarch'] == 'x86_64' %}
file_V38522-appendTimechk:
  file.append:
  - name: /etc/audit/audit.rules
  - text: 
    - '## STIG-ID V-38522 (RHEL-06-000167) - audit all events that change system time'
    - '-a always,exit -F arch=b64 -S adjtimex -S clock_settime -S settimeofday -k SYS_time-change'
    - '-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change'
    - '-a always,exit -F arch=b64 -S clock_settime -k time-change'
    - '-w /etc/localtime -p wa -k time-change'
{% endif %}

