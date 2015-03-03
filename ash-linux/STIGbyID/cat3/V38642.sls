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

script_V38642-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat3/files/V38642.sh
    - cwd: /root

{% if salt['file.search']('/etc/init.d/functions', '^umask') %}
  {% if salt['file.search']('/etc/init.d/functions', '^umask 027') %}
file_V38642-configSet:
  file.replace:
    - name: '/etc/init.d/functions'
    - pattern: '^umask.*$'
    - repl: 'umask 027'
  {% else %}
file_V38642-configSet:
  cmd.run:
    - name: 'echo "Daemon umask-setting already meets STIG-defined requirements"'
  {% endif %}
{% else %}
file_V38642-configSet:
  file.append:
    - name: '/etc/init.d/functions'
    - text:
      - ' '
      - '# Umask must be set to "022" or "027" (per STIG V-38642)'
      - 'umask 027'
{% endif %}
