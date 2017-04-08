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

{%- set stig_id = '38635' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/V{{ stig_id }}.sh
    - cwd: /root

{%- if grains['cpuarch'] == 'x86_64' %}
  {%- set audit_syscall = '-S adjtimex' %}
  {%- set pattern = '-a always,exit -F arch=b64 ' + audit_syscall + ' -k audit_time_rules' %}
  {%- set pattern32 = '-a always,exit -F arch=b32 ' + audit_syscall + ' -k audit_time_rules' %}
  {%- set filename = '/etc/audit/audit.rules' %}
  {%- if not salt['cmd.shell']('grep -c -E -e "' + pattern + '" ' + filename , output_loglevel='quiet') == '0' %}
file_V{{ stig_id }}-auditTime:
  cmd.run:
    - name: 'echo "Appropriate audit rule already in place"'
  {%- elif not salt['cmd.shell']('grep -c -E -e "' + audit_syscall + '" ' + filename , output_loglevel='quiet') == '0' %}
file_V{{ stig_id }}-auditTime:
  file.replace:
    - name: '/etc/audit/audit.rules'
    - pattern: '^.*{{ audit_syscall }}.*$'
    - repl: '{{ pattern32 }}\n{{ pattern }}'
  {%- else %}
file_V{{ stig_id }}-auditTime:
  file.append:
    - name: '{{ filename }}'
    - text: |
        
        # Log all changes to system time (per  V-{{ stig_id }})
        {{ pattern32 }}
        {{ pattern }}
  {%- endif %}
{%- else %}
file_V{{ stig_id }}-auditTime:
    cmd.run:
    - name: 'echo "Architecture not supported: no changes made"'
{%- endif %}
