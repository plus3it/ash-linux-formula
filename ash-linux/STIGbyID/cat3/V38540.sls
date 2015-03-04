# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38540
# Rule ID:		audit_network_modifications
# Finding ID:		V-38540
# Version:		RHEL-06-000182
# SCAP Identifier:	CCE-26648-6
# Finding Level:	Low
#
#     The audit system must be configured to audit modifications to the 
#     systems network configuration. The network environment should not be 
#     modified by anything other than administrator action. Any change to 
#     network parameters should be audited.
#
############################################################

{%- set stig_id = '38540' %}
{%- set helperLoc = 'ash-linux/STIGbyID/cat3/files' %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/V{{ stig_id }}.sh
    - cwd: /root

######################################################################
# Will probably want to look at method to do all the edits in one pass:
# Current method limits rollback capability
######################################################################

{%- if grains['cpuarch'] == 'x86_64' %}
  {%- set pattern = '-a always,exit -F arch=b64 -S sethostname -S setdomainname -k audit_network_modifications' %}
  {%- set filename = '/etc/audit/audit.rules' %}
  {%- if not salt['cmd.run']('grep -c -E -e "' + pattern + '" ' + filename ) == '0' %}
file_V{{ stig_id }}-sethostname_setdomainname:
  cmd.run:
    - name: 'echo "Appropriate audit-rule already present"'
  {%- else %}
file_V{{ stig_id }}-sethostname_setdomainname:
  file.append:
    - name: '{{ filename }}'
    - text: |
        
        # Audit all network configuration modifications (per STIG-ID V-{{ stig_id }})
        {{ pattern }}
  {%- endif %}
{%- else %}
file_V{{ stig_id }}-sethostname_setdomainname:
  cmd.run:
    - name: 'echo "Architecture not supported: no changes made"'
{%- endif %}

# Monitoring of networking files and directories
{%- set files = [
    '/etc/issue',
    '/etc/issue.net',
    '/etc/hosts',
    '/etc/sysconfig/network',
    '/etc/sysconfig/network-scripts/',
] %}
{%- set audit_cfg_file = '/etc/audit/audit.rules' %}
{%- set audit_options = '-w /etc/issue -p wa -k audit_network_modifications' %}

{%- for file in files %}
  {%- set rule = '-w ' + file + ' ' + audit_options %}
  {%- if not salt['cmd.run']('grep -c -E -e "' + rule + '" ' + audit_cfg_file ) == '0' %}
file_V{{ stig_id }}-auditRules_{{ file }}:
  cmd.run:
    - name: 'echo "Appropriate audit rule already in place"'
  {%- elif not salt['cmd.run']('grep -c -E -e "' + file + '" ' + audit_cfg_file ) == '0' %}
file_V{{ stig_id }}-auditRules_{{ file }}:
  file.replace:
    - name: '{{ audit_cfg_file }}'
    - pattern: '^.*{{ file }}.*$'
    - repl: '{{ rule }}'
  {%- else %}
file_V{{ stig_id }}-auditRules_{{ file }}:
  file.append:
    - name: '{{ audit_cfg_file }}'
    - text: |
        
        # Monitor {{ file }} for changes (per STIG-ID V-{{ stig_id }})
        {{ rule }}
  {%- endif %}
{%- endfor %}
