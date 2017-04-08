# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38565
# Rule ID:		audit_rules_dac_modification_setxattr
# Finding ID:		V-38565
# Version:		RHEL-06-000196
# SCAP Security ID:	CCE-27185-8
# Finding Level:	Low
#
#     The audit system must be configured to audit all discretionary access 
#     control permission modifications using setxattr. The changing of file 
#     permissions could indicate that a user is attempting to gain access 
#     to information that would otherwise be disallowed. Auditing DAC 
#     modifications can facilitate the identification of patterns of abuse 
#     among both authorized and unauthorized users. 
#
############################################################

{%- set stig_id = '38565' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/V{{ stig_id }}.sh
    - cwd: /root

{%- set usertypes = {
    'selDACusers' : { 'search_string' : ' setxattr -F auid>=500 ',
                      'rule' : '-a always,exit -F arch=b64 -S setxattr -F auid>=500 -F auid!=4294967295 -k perm_mod',
                      'rule32' : '-a always,exit -F arch=b32 -S setxattr -F auid>=500 -F auid!=4294967295 -k perm_mod',
                    },
    'selDACroot'  : { 'search_string' : ' setxattr .*auid=0 ',
                      'rule' : '-a always,exit -F arch=b64 -S setxattr -F auid=0 -k perm_mod',
                      'rule32' : '-a always,exit -F arch=b32 -S setxattr -F auid=0 -k perm_mod',
                    },
} %}
{%- set audit_cfg_file = '/etc/audit/audit.rules' %}

# Monitoring of SELinux DAC config
{%- if grains['cpuarch'] == 'x86_64' %}
  {%- for usertype,audit_options in usertypes.items() %}
    {%- if not salt['cmd.shell']('grep -c -E -e "' + audit_options['rule'] + '" ' + audit_cfg_file , output_loglevel='quiet') == '0' %}
file_V{{ stig_id }}-auditRules_{{ usertype }}:
  cmd.run:
    - name: 'echo "Appropriate audit rule already in place"'
    {%- elif not salt['cmd.shell']('grep -c -E -e "' + audit_options['search_string'] + '" ' + audit_cfg_file , output_loglevel='quiet') == '0' %}
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
file_V{{ stig_id }}-auditRules_selDAC:
  cmd.run:
    - name: 'echo "Architecture not supported: no changes made"'
{%- endif %}
