# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID:
# - sysctl_fs_suid_dumpable
#
# Security identifiers:
# - CCE-27044-7
#
# Rule Summary: Disable core dumps for SUID programs
#
# Rule Text: The core dump of a setuid program is more likely to contain 
#            sensitive data, as the program itself runs with greater 
#            privileges than the user who initiated execution of the 
#            program. Disabling the ability for any setuid program to 
#            write a core file decreases the risk of unauthorized access 
#            of such data.
#
#################################################################

{%- set helperLoc = 'ash-linux/el6/SCAPonly/low/files' %}
{%- set scapId = 'CCE-27044-7' %}
{%- set checkFile = '/etc/sysctl.conf' %}
{%- set parmName = 'fs.suid_dumpable' %}
{%- set notify_change = '''{{ parmName }}'' value set to ''0''' %}
{%- set notify_nochange = '''{{ parmName }}'' value already set to ''0''' %}

script_{{ scapId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ scapId }}.sh
    - cwd: '/root'

comment_{{ scapId }}-{{ parmName }}:
  file.append:
    - name: '{{ checkFile }}'
    - text: '# Added {{ parmName }} define per SCAP-ID: {{ scapId }}'
    - unless: 'grep "{{ parmName }}[ 	]=[ 	]0" {{ checkFile }}'

setting_{{ scapId }}-{{ parmName }}:
  sysctl.present:
    - name: '{{ parmName }}'
    - value: '0'
