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

script_V38645-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat3/files/V38645.sh
    - cwd: /root

{% if salt['file.search']('/etc/login.defs', '^UMASK') %}
  {% if salt['file.search']('/etc/login.defs', '^UMASK	077') %}
file_V38645-configSet:
  file.replace:
    - name: '/etc/login.defs'
    - pattern: '^UMASK.*$'
    - repl: 'UMASK	077'
  {% else %}
file_V38645-configSet:
  cmd.run:
    - name: 'echo "Default user umask-setting already meets STIG-defined requirements"'
  {% endif %}
{% else %}
file_V38645-configSet:
  file.append:
    - name: '/etc/login.defs'
    - text:
      - ' '
      - '# Umask must be set to "077" (per STIG V-38645)'
      - 'UMASK	077'
{% endif %}
