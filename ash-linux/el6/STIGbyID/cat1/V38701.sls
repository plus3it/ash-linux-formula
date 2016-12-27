# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38701
# Finding ID:	V-38701
# Version:	RHEL-06-000338
# Finding Level:	High
#
#     The TFTP daemon must operate in secure mode which provides access 
#     only to a single directory on the host file system. Using the "-s" 
#     option causes the TFTP service to only serve files from the given 
#     directory. Serving files from an intentionally specified directory 
#     reduces the risk of sharing files which should ...
#
############################################################

{%- set stigId = 'V38701' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat1/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

{%- if salt.pkg.version('tftp-server') %}
file_{{ stigId }}:
  file.sed:
    - name: /etc/xinetd.d/tftp
    - before: 'server_args.*=.*'
    - after: 'server_args		= -s /var/lib/tftpboot'
{%- else %}
file_{{ stigId }}:
  cmd.run:
    - name: 'echo "No applicable findings possible: ''tftp-server'' package not installed"'
{%- endif %}
