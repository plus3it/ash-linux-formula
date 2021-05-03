# Finding ID:	RHEL-07-030740
# Version:	RHEL-07-030740_rule
# SRG ID:	SRG-OS-000042-GPOS-00020
# Finding Level:	medium
#
# Rule Summary:
#	All uses of the mount command must be audited.
#
# CCI-000135
# CCI-002884
#    NIST SP 800-53 :: AU-3 (1)
#    NIST SP 800-53A :: AU-3 (1).1 (ii)
#    NIST SP 800-53 Revision 4 :: AU-3 (1)
#    NIST SP 800-53 Revision 4 :: MA-4 (1) (a)
#
#################################################################
{%- set stig_id = 'RHEL-07-030740' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set audit_cfg_file = '/etc/audit/rules.d/audit.rules' %}
{%- set sysuserMax = salt['cmd.shell']("awk '/SYS_UID_MAX/{ IDVAL = $2 + 1} END { print IDVAL }' /etc/login.defs") %}
{%- set act2mon = 'mount' %}
{%- set path2mon = '/bin/mount' %}
{%- set key2mon = 'privileged-mount' %}
{%- set usertypes = {
    'rootUser': { 'search_string' : ' ' + act2mon + ' -F auid=0 ',
                  'rule' : '-a always,exit -F arch=b64 -S ' + act2mon + ' -F auid=0 -k ' + key2mon,
                  'rule32' : '-a always,exit -F arch=b32 -S ' + act2mon + ' -F auid=0 -k ' + key2mon,
                },
    'regUsers': { 'search_string' : ' ' + act2mon + ' -F auid>=' + sysuserMax + ' ',
                  'rule' : '-a always,exit -F arch=b64 -S ' + act2mon + ' -F auid>=' + sysuserMax + ' -F auid!=4294967295 -k ' + key2mon,
                  'rule32' : '-a always,exit -F arch=b32 -S ' + act2mon + ' -F auid>=' + sysuserMax + ' -F auid!=4294967295 -k ' + key2mon,
                },
} %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Handler for {{ stig_id }} has been selected for skip.''\n"'
    - stateful: True
    - cwd: /root
{%- else %}
touch_{{ stig_id }}-{{ audit_cfg_file }}:
  file.touch:
    - name: '{{ audit_cfg_file }}'
    - unless:
      - 'test -e {{ audit_cfg_file }}'

file_{{ stig_id }}-{{ audit_cfg_file }}:
  file.replace:
    - name: '{{ audit_cfg_file }}'
    - pattern: '^-a always,exit -F path={{ path2mon }}.*$'
    - repl: '-a always,exit -F path={{ path2mon }} -F auid>={{ sysuserMax }} -F auid!=4294967295 -k {{ key2mon }}'
    - append_if_not_found: True

# Monitoring of SELinux DAC config
  {%- if grains['cpuarch'] == 'x86_64' %}
    {%- for usertype,audit_options in usertypes.items() %}
      {%- if not salt['cmd.shell']('grep -c -E -e "' + audit_options['rule'] + '" ' + audit_cfg_file , output_loglevel='quiet') == '0'
 %}
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

        # Monitor all uses of the {{ act2mon }} syscall (per STIG-ID {{ stig_id }})
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
{%- endif %}
