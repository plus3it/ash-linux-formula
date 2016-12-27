# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38647
# Finding ID:	V-38647
# Version:	RHEL-06-000344
# Finding Level:	Low
#
#     The system default umask in /etc/profile must be 077. The umask value 
#     influences the permissions assigned to files when they are created. A 
#     misconfigured umask value could result in files with excessive 
#     permissions that can be read and/or written to by unauthorized users. 
#
############################################################

{%- set stigId = 'V38647' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

{%- if salt.file.search('/etc/profile', '^[ 	]*umask') %}
file_{{ stigId }}-configSet:
  file.replace:
    - name: '/etc/profile'
    - pattern: 'umask.*$'
    - repl: 'umask 077'
{%- else %}
file_{{ stigId }}-configSet:
  file.append:
    - name: '/etc/profile'
    - text: |
        
        # Umask must be set to "077" (per STIG V-38647)
        umask 077
{%- endif %}
