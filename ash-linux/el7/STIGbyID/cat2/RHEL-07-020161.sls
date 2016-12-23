# Finding ID:	RHEL-07-020161
# Version:	RHEL-07-020161_rule
# SRG ID:	SRG-OS-000114-GPOS-00059
# Finding Level:	medium
# 
# Rule Summary:
#	File system automounter must be disabled unless required.
#
# CCI-000366 
# CCI-000778 
# CCI-001958 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#    NIST SP 800-53 :: IA-3 
#    NIST SP 800-53A :: IA-3.1 (ii) 
#    NIST SP 800-53 Revision 4 :: IA-3 
#    NIST SP 800-53 Revision 4 :: IA-3 
#
#################################################################
{%- set stig_id = 'RHEL-07-020161' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set pkgChk = 'autofs' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Handler for {{ stig_id }} has been selected for skip.''\n"'
    - cwd: /root
    - stateful: True
{%- else %}
  {%- if salt.pkg.version(pkgChk) %}
service_{{ stig_id }}-{{ pkgChk }}_dead:
  service.dead:
    - name: '{{ pkgChk }}.service'

service_{{ stig_id }}-{{ pkgChk }}_disabled:
  service.disabled:
    - name: '{{ pkgChk }}.service'

  {%- else %}
notify_{{ stig_id }}-no_{{ pkgChk }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''The {{ pkgChk }} package is not installed. Nothing to do.''\n"'
    - cwd: /root
    - stateful: True

  {%- endif %}
{%- endif %}
