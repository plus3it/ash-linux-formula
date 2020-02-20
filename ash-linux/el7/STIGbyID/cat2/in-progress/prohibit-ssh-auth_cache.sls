# Finding ID:	RHEL-07-010402
# Version:	RHEL-07-010402_rule
# SRG ID:	SRG-OS-000383-GPOS-00166
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system must prohibit the use of cached SSH
#	authenticators after one day.
#
# CCI-002007 
#    NIST SP 800-53 Revision 4 :: IA-5 (13) 
#
#################################################################
{%- set stig_id = 'RHEL-07-010402' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set pkgChk = 'sssd-common' %}
{%- set chkFile = '/etc/sssd/sssd.conf' %}
{%- set parmName = 'ssh_known_hosts_timeout' %}
{%- set parmValu = '86400' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if salt.pkg.version(pkgChk) %}
  {%- if salt.file.file_exists(chkFile) %}
config_{{ stig_id }}-{{ pkgChk }}:
  file.replace:
    - name: '{{ chkFile }}'
    - pattern: '^{{ parmName }} = .*$'
    - repl: '{{ parmName }} = {{ parmValu }}'
    - append_if_not_found: true
  {%- else %}
config_{{ stig_id }}-{{ pkgChk }}:
  file.append:
    - name: '{{ chkFile }}'
    - text: '{{ parmName }} = {{ parmValu }}'
  {%- endif %}
{%- endif %}
