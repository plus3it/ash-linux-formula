# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38568
# Finding ID:	V-38568
# Version:	RHEL-06-000199
# Finding Level:	Low
#
#     The audit system must be configured to audit successful file system 
#     mounts. The unauthorized exportation of data to external media could 
#     result in an information leak where classified information, Privacy 
#     Act information, and intellectual property could be lost. An audit 
#     trail should be created each time a filesystem is mounted to help 
#     identify and guard against information loss
#
############################################################

{%- set stig_id = '38568' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/V{{ stig_id }}.sh
    - cwd: /root

{%- set usertypes = {
    'MountUsers' : { 'search_string' : ' mount -F auid>=500 ',
                      'rule' : '-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k export',
                      'rule32' : '-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k export',
                    },
    'MountRoot'  : { 'search_string' : ' mount .*auid=0 ',
                      'rule' : '-a always,exit -F arch=b64 -S mount -F auid=0 -k export',
                      'rule32' : '-a always,exit -F arch=b32 -S mount -F auid=0 -k export',
                    },
} %}
{%- set audit_cfg_file = '/etc/audit/audit.rules' %}

# Monitoring of mount actions
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
        
        # Monitor filesystem mount actions (per STIG-ID V-{{ stig_id }})
        {{ audit_options['rule32'] }}
        {{ audit_options['rule'] }}
    {%- endif %}
  {%- endfor %}
{%- else %}
file_V{{ stig_id }}-auditRules_Mount:
  cmd.run:
    - name: 'echo "Architecture not supported: no changes made"'
{%- endif %}
