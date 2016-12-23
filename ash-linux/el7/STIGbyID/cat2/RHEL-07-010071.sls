# Finding ID:	RHEL-07-010071
# Version:	RHEL-07-010071_rule
# SRG ID:	SRG-OS-000029-GPOS-00010
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system must initiate a session lock after a
#	15-minute period of inactivity for all connection types.
#
# CCI-000057 
#    NIST SP 800-53 :: AC-11 a 
#    NIST SP 800-53A :: AC-11.1 (ii) 
#    NIST SP 800-53 Revision 4 :: AC-11 a 
#
#################################################################
{%- set stig_id = 'RHEL-07-010071' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set pkgName = 'dconf' %}
{%- set dconfDir = '/etc/dconf/db/local.d' %}
{%- set dconfCfgFile = dconfDir + '/locks/screensaver' %}


script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

# Check if target RPM is installed
{%- if salt.pkg.version(pkgName) %}
file_{{ stig_id }}-{{ dconfCfgFile }}:
  file.managed:
    - name: '{{ dconfCfgFile }}'
    - source: 'salt://{{ helperLoc }}/dconf_screensaver.src'
    - owner: 'root'
    - group: 'root'
    - mode: '0444'
{%- else %}
file_{{ stig_id }}-{{ dconfCfgFile }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Relevant subsystems not installed: skipping...''\n"'
    - cwd: /root
    - stateful: True
{%- endif %}
