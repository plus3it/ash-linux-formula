# Finding ID:	RHEL-07-021760
# Version:	RHEL-07-021760_rule
# SRG ID:	SRG-OS-000364-GPOS-00151
# Finding Level:	medium
#
# Rule Summary:
#	The system must not allow removable media to be used as the
#	boot loader unless approved.
#
# CCI-000368
# CCI-000318
# CCI-001812
# CCI-001813
# CCI-001814
#    NIST SP 800-53 :: CM-6 c
#    NIST SP 800-53A :: CM-6.1 (v)
#    NIST SP 800-53 Revision 4 :: CM-6 c
#    NIST SP 800-53 :: CM-3 e
#    NIST SP 800-53A :: CM-3.1 (v)
#    NIST SP 800-53 Revision 4 :: CM-3 f
#    NIST SP 800-53 Revision 4 :: CM-11 (2)
#    NIST SP 800-53 Revision 4 :: CM-5 (1)
#    NIST SP 800-53 Revision 4 :: CM-5 (1)
#
#################################################################
{%- set stig_id = 'RHEL-07-021760' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set grubCfgs = salt.file.find('/', type='f', name='grub.cfg') %}

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
  {%- for file in grubCfgs %}
    {%- if salt.file.search(file, '^\sset root=') %}
notify_{{ stig_id }}-{{ file }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''ALERT: alternate root-device defined in {{ file }}: please check its validity.''\n"'
    - cwd: /root
    - stateful: True
    {%- endif %}
  {%- endfor %}
{%- endif %}
