# STIG ID:	RHEL-07-030819
# Rule ID:	SV-204559r603261_rule
# Vuln ID:	V-204559
# SRG ID:	SRG-OS-000471-GPOS-00216
# Finding Level:	medium
#
# Rule Summary:
#	The operating system must audit all uses of the
#   `create_module` syscall
#
# CCI-000172
#
#################################################################
{%- set stig_id = 'RHEL-07-030819' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set act2mon = 'create_module' %}
{%- set key2mon = 'module-change' %}
{%- set audit_cfg_file = '/etc/audit/rules.d/audit.rules' %}
{%- set usertypes = {
    'rootUser': { 'search_string' : ' ' + act2mon + ' ',
                  'rule' : '-a always,exit -F arch=b64 -S ' + act2mon + ' -k ' + key2mon,
                  'rule32' : '-a always,exit -F arch=b32 -S ' + act2mon + ' -k ' + key2mon,
                },
    'regUsers': { 'search_string' : ' ' + act2mon + ' ' ,
                  'rule' : '-a always,exit -F arch=b64 -S ' + act2mon + ' -k ' + key2mon,
                  'rule32' : '-a always,exit -F arch=b32 -S ' + act2mon + ' -k ' + key2mon,
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

        # Monitor for use of {{ act2mon }} actions (per STIG-ID {{ stig_id }})
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
