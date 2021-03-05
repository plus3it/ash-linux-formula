# Finding ID:	RHEL-07-020940
# Version:	RHEL-07-020940_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
#
# Rule Summary:
#	All system device files must be correctly labeled to prevent
#	unauthorized modification.
#
# CCI-000318
# CCI-001812
# CCI-001813
# CCI-001814
# CCI-000368
#    NIST SP 800-53 :: CM-3 e
#    NIST SP 800-53A :: CM-3.1 (v)
#    NIST SP 800-53 Revision 4 :: CM-3 f
#    NIST SP 800-53 Revision 4 :: CM-11 (2)
#    NIST SP 800-53 Revision 4 :: CM-5 (1)
#    NIST SP 800-53 Revision 4 :: CM-5 (1)
#    NIST SP 800-53 :: CM-6 c
#    NIST SP 800-53A :: CM-6.1 (v)
#    NIST SP 800-53 Revision 4 :: CM-6 c
#
#################################################################
{%- set stig_id = 'RHEL-07-020940' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set badDevNodes = [] %}
{%- if salt.cmd.which('semanage') %}
  {%- do badDevNodes.extend(salt['cmd.shell']('find / -context *:device_t:* \( -type c -o -type b \) -print ').split('\n')) %}
  {%- do badDevNodes.extend(salt['cmd.shell']('find / -context *:unlabeled_t:* \( -type c -o -type b \) -print ').split('\n')) %}
{%- endif %}

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
  {%- for file in badDevNodes %}
    {%- if file %}
      {%- if salt.lowpkg.owner(file) %}
        {%- set fixRPM = salt.lowpkg.owner(file) %}
dev_{{ stig_id }}-{{ file }}:
  pkg.install:
    - name: '{{ fixRPM }}'
    - reinstall: True
      {%- else %}
dev_{{ stig_id }}-{{ file }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Bad device {{ file }} not installed by an RPM: cannot attempt fix.''\n"'
    - cwd: /root
    - stateful: True
      {%- endif %}

    {%- endif %}
  {%- endfor %}
{%- endif %}

