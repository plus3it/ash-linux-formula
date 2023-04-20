# Ref Doc:    STIG - RHEL 8 v1r9
# Finding ID: V-230364
# Rule ID:    SV-230364r627750_rule
# STIG ID:    RHEL-08-020180
# SRG ID:     SRG-OS-000075-GPOS-00043
#
# Finding Level: medium
#
# Rule Summary:
#       Passwords managed by the operating system  must have a 24 hours/1
#       day minimum password lifetime restriction in /etc/shadow.
#
# References:
#   CCI:
#     - CCI-000198
#   NIST SP 800-53 :: IA-5 (1) (d)
#   NIST SP 800-53A :: IA-5 (1).1 (v)
#   NIST SP 800-53 Revision 4 :: IA-5 (1) (d)
#
###########################################################################
{%- set stig_id = 'RHEL-08-020180' %}
{%- set helperLoc = 'ash-linux/el8/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set userList =  salt.user.list_users() %}

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
  {%- for user in userList %}
Set minimum password lifetime for {{ user }}:
  user.present:
    - name: '{{ user }}'
    - mindays: 1
    - onlyif:
      - '[[ -n $( awk -F: ''/{{ user }}:/ && $4 < 1  {print $1 " " $4}'' /etc/shadow ) ]]'
  {%- endfor %}
{%- endif %}
