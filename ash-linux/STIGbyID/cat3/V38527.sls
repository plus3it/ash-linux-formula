# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38527
# Finding ID:	V-38527
# Version:	RHEL-06-000171
# Finding Level:	Low
#
#     The audit system must be configured to audit all attempts to alter 
#     system time through clock_settime. Arbitrary changes to the system 
#     time can be used to obfuscate nefarious activities in log files, as 
#     well as to confuse network services that are highly dependent upon an 
#     accurate system time (such as shd). All changes to the system time
#     should be audited.
#
############################################################
 
script_V38527-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat3/files/V38527.sh

{% if grains['cpuarch'] == 'x86_64' %}
  {% if salt['file.search']('/etc/audit/audit.rules', '-a always,exit -F arch=b64 -S clock_settime -k audit_time_rules') %}
file_V38527-settimeofday:
  cmd.run:
    - name: 'echo "Appropriate audit-rule already present"'
  {% else %}
file_V38527-settimeofday:
  file.append:
    - name: '/etc/audit/audit.rules'
    - text:
      - '# Audit all system time-modifications via clock_settime (per STIG-ID V-38527)'
      - '-a always,exit -F arch=b64 -S clock_settime -k audit_time_rules'
  {% endif %}
{% else %}
file_V38527-settimeofday:
  cmd.run:
    - name: 'echo "Architecture not supported: no changes made"'
{% endif %}
