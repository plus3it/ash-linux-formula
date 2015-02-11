# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38635
# Finding ID:	V-38635
# Version:	RHEL-06-000165
# Finding Level:	Low
#
#     The audit system must be configured to audit all attempts to alter 
#     system time through adjtimex. Arbitrary changes to the system time 
#     can be used to obfuscate nefarious activities in log files, as well 
#     as to confuse network services that are highly dependent upon an 
#     accurate system time (such as sshd). All changes to the system time 
#     should be audited. 
#
############################################################

script_V38635-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38635.sh

{% if grains['cpuarch'] == 'x86_64' %}
  {% if salt['file.search']('/etc/audit/audit.rules', '-a always,exit -F arch=b64 -S adjtimex -k audit_time_rules') %}
file_V38635-auditTime:
  cmd.run:
  - name: 'echo "Appropriate audit rule already in place"'
  {% elif salt['file.search']('/etc/audit/audit.rules', 'S adjtimex ') %}
file_V38635-auditTime:
  file.replace:
  - name: '/etc/audit/audit.rules'
  - pattern: '^.*S adjtimex .*$'
  - repl: '-a always,exit -F arch=b64 -S adjtimex -k audit_time_rules'
  {% else %}
file_V38635-auditTime:
  file.append:
  - name: '/etc/audit/audit.rules'
  - text:
    - '# Log all file deletions (per  V-38635)'
    - '-a always,exit -F arch=b64 -S adjtimex -k audit_time_rules'
  {% endif %}
{% else %}
file_V38635-auditTime:
  cmd.run:
  - name: 'echo "Architecture not supported: no changes made"'
{% endif %}

