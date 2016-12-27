# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38645
# Finding ID:	V-38645
# Version:	RHEL-06-000345
# Finding Level:	Low
#
#     The system default umask in /etc/login.defs must be 077. The umask 
#     value influences the permissions assigned to files when they are 
#     created. A misconfigured umask value could result in files with 
#     excessive permissions that can be read and/or written to by 
#     unauthorized users. 
#
############################################################

{%- set stigId = 'V38645' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}
{%- set checkFile = '/etc/login.defs' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

{%- if salt.file.search(checkFile, '^UMASK') %}
  {%- if salt.file.search(checkFile, '^UMASK	077') %}
file_{{ stigId }}-configSet:
  file.replace:
    - name: '{{ checkFile }}'
    - pattern: '^UMASK.*$'
    - repl: 'UMASK	077'
  {%- else %}
file_{{ stigId }}-configSet:
  cmd.run:
    - name: 'echo "Default user umask-setting already meets STIG-defined requirements"'
  {%- endif %}
{%- else %}
file_{{ stigId }}-configSet:
  file.append:
    - name: '{{ checkFile }}'
    - text: |
        
        # Umask must be set to "077" (per STIG V-38645)
        UMASK	077
{%- endif %}
