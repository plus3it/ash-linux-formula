# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-51337
# Finding ID:	V-51337
# Version:	RHEL-06-000017
# Finding Level:	Medium
#
#     Disabling a major host protection feature, such as SELinux, at boot
#     time prevents it from confining system services at boot time. Further,
#     it increases the chances that it will remain off during system
#     operation.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
#############################################################################

{%- set stig_id = 'V51337' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set chkFile = '/boot/grub/grub.conf' %}
{%- set parmSet = 'selinux=0' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: '/root'

#########################################
# Ensure SELinux is active at kernel load
{%- if salt.file.search(chkFile, 'kernel.*selinux=0', ignore_if_missing=True) %}

file_{{ stig_id }}-repl:
  file.replace:
    - name: '{{ chkFile }}'
    - pattern: ' selinux=0'
    - repl: ' selinux=1'

{%- elif salt.file.file_exists(chkFile) %}

file_{{ stig_id }}-repl:
  file.replace:
    - name: '{{ chkFile }}'
    - pattern: '^(?P<srctok>.*kernel.*$)'
    - repl: '\g<srctok> selinux=1'
    - unless: 'grep "kernel.*selinux=1" {{ chkFile }}'

status_{{ stig_id }}:
  cmd.run:
    - name: 'echo "SELinux not disabled in GRUB"'

{%- endif %}
