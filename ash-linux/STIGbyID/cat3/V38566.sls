# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38566
# Finding ID:	V-38566
# Version:	RHEL-06-000197
# Finding Level:	Low
#
#     The audit system must be configured to audit failed attempts to 
#     access files and programs. Unsuccessful attempts to access files 
#     could be an indicator of malicious activity on a system. Auditing 
#     these events could serve as evidence of potential system compromise.
#
############################################################

{%- set stig_id = '38566' %}
{%- set helperLoc = 'ash-linux/STIGbyID/cat3/files' %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/V{{ stig_id }}.sh
    - cwd: /root

{%- set usertypes = {
    'selEACCESusers' : { 'search_string' : 'EACCES -F auid>=500 ',
                         'rule' : '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access',
                         'rule32' : '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access',
                       },
    'selEPERMusers'  : { 'search_string' : 'EPERM -F auid>=500 ',
                         'rule' : '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access',
                         'rule32' : '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access',
                       },
    'selEACCESroot'  : { 'search_string' : 'EACCES -F auid=0 ',
                         'rule' : '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid=0 -k access',
                         'rule32' : '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid=0 -k access',
                       },
    'selEPERMroot'   : { 'search_string' : 'EPERM -F auid=0 ',
                         'rule' : '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid=0 -k access',
                         'rule32' : '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid=0 -k access',
                       },
} %}
{%- set audit_cfg_file = '/etc/audit/audit.rules' %}

# Monitoring of SELinux DAC config
{%- if grains['cpuarch'] == 'x86_64' %}
  {%- for usertype,audit_options in usertypes.items() %}
    {%- if not salt['cmd.run']('grep -c -E -e "' + audit_options['rule'] + '" ' + audit_cfg_file ) == '0' %}
file_V{{ stig_id }}-auditRules_{{ usertype }}:
  cmd.run:
    - name: 'echo "Appropriate audit rule already in place"'
    {%- elif not salt['cmd.run']('grep -c -E -e "' + audit_options['search_string'] + '" ' + audit_cfg_file ) == '0' %}
file_V{{ stig_id }}-auditRules_{{ usertype }}:
  file.replace:
    - name: '{{ audit_cfg_file }}'
    - pattern: '^.*{{ audit_options['search_string'] }}.*$'
    - repl: '{{ audit_options['rule32'] }}\n{{ audit_options['rule'] }}'
    {%- else %}
file_V{{ stig_id }}-auditRules_{{ usertype }}:
  file.append:
    - name: '{{ audit_cfg_file }}'
    - text: |
        
        # Monitor for SELinux DAC changes (per STIG-ID V-{{ stig_id }})
        {{ audit_options['rule32'] }}
        {{ audit_options['rule'] }}
    {%- endif %}
  {%- endfor %}
{%- else %}
file_V{{ stig_id }}-auditRules_selEACCES_EPERM:
  cmd.run:
    - name: 'echo "Architecture not supported: no changes made"'
{%- endif %}
