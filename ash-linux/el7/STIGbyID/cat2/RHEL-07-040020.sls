# Finding ID:	RHEL-07-040020
# Version:	RHEL-07-040020_rule
# SRG ID:	SRG-OS-000032-GPOS-00013
# Finding Level:	medium
# 
# Rule Summary:
#	The system must log informational authentication data.
#
# CCI-000067 
# CCI-000126 
#    NIST SP 800-53 :: AC-17 (1) 
#    NIST SP 800-53A :: AC-17 (1).1 
#    NIST SP 800-53 Revision 4 :: AC-17 (1) 
#    NIST SP 800-53 :: AU-2 d 
#    NIST SP 800-53A :: AU-2.1 (v) 
#    NIST SP 800-53 Revision 4 :: AU-2 d 
#
#################################################################
{%- set stig_id = 'RHEL-07-040020' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set cfgFile = '/etc/rsyslog.conf' %}
{%- set srcPatAuth = '^auth\.\*' %}
{%- set srcPatDmn = '^daemon.notice' %}
{%- set replAuth = 'auth.*,authpriv.*	/var/log/auth.log' %}
{%- set replDmn = 'daemon.notice	/var/log/messages' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if salt.file.search(cfgFile, srcPatAuth) %}
file_{{ stig_id }}-authlog:
  file.replace:
    - name: '{{ cfgFile }}'
    - pattern: '{{ srcPatAuth }}.*$'
    - repl: '{{ replAuth }}'
{%- else %}
file_{{ stig_id }}-authlog:
  file.replace:
    - name: '{{ cfgFile }}'
    - pattern: '^(?P<srctok>#### RULES ####.*$)'
    - repl: |-
        \g<srctok>
        # Inserted per STIG {{ stig_id }}
        {{ replAuth }}
    - append_if_not_found: True
{%- endif %}

{%- if salt.file.search(cfgFile, srcPatDmn) %}
file_{{ stig_id }}-daemonlog:
  file.replace:
    - name: '{{ cfgFile }}'
    - pattern: '{{ srcPatDmn }}.*$'
    - repl: '{{ replDmn }}'
{%- else %}
file_{{ stig_id }}-daemonlog:
  file.replace:
    - name: '{{ cfgFile }}'
    - pattern: '^(?P<srctok>#### RULES ####.*$)'
    - repl: |-
        \g<srctok>
        # Inserted per STIG {{ stig_id }}
        {{ replDmn }}
    - append_if_not_found: True
{%- endif %}
