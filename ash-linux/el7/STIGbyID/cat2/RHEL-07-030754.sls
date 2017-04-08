# Finding ID:	RHEL-07-030754
# Version:	RHEL-07-030754_rule
# SRG ID:	SRG-OS-000466-GPOS-00210
# Finding Level:	medium
# 
# Rule Summary:
#	All uses of the unlinkat command must be audited.
#
# CCI-000172 
# CCI-002884 
#    NIST SP 800-53 :: AU-12 c 
#    NIST SP 800-53A :: AU-12.1 (iv) 
#    NIST SP 800-53 Revision 4 :: AU-12 c 
#    NIST SP 800-53 Revision 4 :: MA-4 (1) (a) 
#
#################################################################
{%- set stig_id = 'RHEL-07-030754' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set sysuserMax = salt['cmd.shell']("awk '/SYS_UID_MAX/{print $2}' /etc/login.defs") %}
{%- set act2mon = 'unlinkat' %}
{%- set key2mon = 'delete' %}
{%- set audit_cfg_file = '/etc/audit/rules.d/audit.rules' %}
{%- set usertypes = {
    'selDACusers' : { 'search_string' : ' ' + act2mon + ' -F perm=x -F auid>' + sysuserMax + ' ',
                      'rule' : '-a always,exit -F arch=b64 -S ' + act2mon + ' -F perm=x -F auid>' + sysuserMax + ' -F auid!=4294967295 -F subj_role=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -F key=' + key2mon,
                      'rule32' : '-a always,exit -F arch=b32 -S ' + act2mon + ' -F perm=x -F auid>' + sysuserMax + ' -F auid!=4294967295 -F subj_role=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -F key=' + key2mon,
                    },
    'selDACroot'  : { 'search_string' : ' ' + act2mon + ' -F perm=x -F auid=0 ',
                      'rule' : '-a always,exit -F arch=b64 -S ' + act2mon + ' -F perm=x -F auid=0 -F subj_role=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -F key=' + key2mon,
                      'rule32' : '-a always,exit -F arch=b32 -S ' + act2mon + ' -F perm=x -F auid=0 -F subj_role=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -F key=' + key2mon,
                    },
} %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

# Monitoring of SELinux DAC config
{%- if grains['cpuarch'] == 'x86_64' %}
  {%- for usertype,audit_options in usertypes.items() %}
    {%- if not salt['cmd.shell']('grep -c -E -e "' + audit_options['rule'] + '" ' + audit_cfg_file , output_loglevel='quiet') == '0' %}
file_{{ stig_id }}-auditRules_{{ usertype }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Appropriate audit rule already in place.''\n"'
    - cwd: /root
    - stateful: True
    {%- elif not salt['cmd.shell']('grep -c -E -e "' + audit_options['search_string'] + '" ' + audit_cfg_file , output_loglevel='quiet') == '0' %}
file_{{ stig_id }}-auditRules_{{ usertype }}:
  file.replace:
    - name: '{{ audit_cfg_file }}'
    - pattern: '^.*{{ audit_options['search_string'] }}.*$'
    - repl: '{{ audit_options['rule32'] }}\n{{ audit_options['rule'] }}'
    {%- else %}
file_{{ stig_id }}-auditRules_{{ usertype }}:
  file.append:
    - name: '{{ audit_cfg_file }}'
    - text: |-
        
        # Monitor for SELinux DAC changes (per STIG-ID {{ stig_id }})
        {{ audit_options['rule32'] }}
        {{ audit_options['rule'] }}
    {%- endif %}
  {%- endfor %}
{%- else %}
file_{{ stig_id }}-auditRules_selDAC:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Architecture not supported: no changes made.''\n"'
    - cwd: /root
    - stateful: True
{%- endif %}
