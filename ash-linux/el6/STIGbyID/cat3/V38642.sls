# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38642
# Rule ID:		umask_for_daemons
# Finding ID:		V-38642
# Version:		RHEL-06-000346
# SCAP Security ID:	CCE-27031-4
# Finding Level:	Low
#
#     The system default umask for daemons must be 027 or 022. The umask 
#     influences the permissions assigned to files created by a process at 
#     run time. An unnecessarily permissive umask could result in files 
#     being created with insecure permissions.
#
############################################################

{%- set stigId = 'V38642' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}
{%- set checkFile = '/etc/init.d/functions' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

{%- if salt.file.search(checkFile, '^umask') %}
  {%- if salt.file.search(checkFile, '^umask 027') %}
file_{{ stigId }}-configSet:
  file.replace:
    - name: '{{ checkFile }}'
    - pattern: '^umask.*$'
    - repl: 'umask 027'
  {%- else %}
file_{{ stigId }}-configSet:
  cmd.run:
    - name: 'echo "Daemon umask-setting already meets STIG-defined requirements"'
  {%- endif %}
{%- else %}
file_{{ stigId }}-configSet:
  file.append:
    - name: '{{ checkFile }}'
    - text: |
        
        # Umask must be set to "022" or "027" (per STIG V-38642)
        umask 027
{%- endif %}
