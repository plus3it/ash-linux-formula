# Finding ID:	RHEL-07-030710
# Version:	RHEL-07-030710_rule
# SRG ID:	SRG-OS-000004-GPOS-00004
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system must generate audit records for all
#	account creations, modifications, disabling, and termination
#	events.
#
# CCI-000018 
# CCI-000172 
# CCI-001403 
# CCI-002130 
#    NIST SP 800-53 :: AC-2 (4) 
#    NIST SP 800-53A :: AC-2 (4).1 (i&ii) 
#    NIST SP 800-53 Revision 4 :: AC-2 (4) 
#    NIST SP 800-53 :: AU-12 c 
#    NIST SP 800-53A :: AU-12.1 (iv) 
#    NIST SP 800-53 Revision 4 :: AU-12 c 
#    NIST SP 800-53 :: AC-2 (4) 
#    NIST SP 800-53A :: AC-2 (4).1 (i&ii) 
#    NIST SP 800-53 Revision 4 :: AC-2 (4) 
#    NIST SP 800-53 Revision 4 :: AC-2 (4) 
#
#################################################################
{%- set stig_id = 'RHEL-07-030710' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set ruleFile = '/etc/audit/rules.d/audit.rules' %}
{%- set files2mon = [
                      '/etc/group',
                      '/etc/passwd',
                      '/etc/gshadow',
                      '/etc/shadow',
                      '/etc/security/opasswd'
                     ] %}
{%- set key2mon = 'identity' %}


script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- for file2mon in files2mon %}
file_{{ stig_id }}-{{ file2mon }}:
  file.replace:
    - name: '{{ ruleFile }}'
    - pattern: '^-w {{ file2mon }} .*$'
    - repl: '-w {{ file2mon }} -p wa -k {{ key2mon }}'
    - append_if_not_found: True
{%- endfor %}
