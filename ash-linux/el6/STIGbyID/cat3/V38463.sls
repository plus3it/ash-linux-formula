# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38463
# Finding ID:	V-38463
# Version:	RHEL-06-000003
# Finding Level:	Low
#
#     The system must use a separate file system for /var/log. Placing 
#     "/var/log" in its own partition enables better separation between log 
#     files and other files in "/var/".
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stigId = 'V38463' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}
{%- set chkFile = '/etc/fstab' %}
{%- set chkPtn = '/var/log' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

# Not really happy with how the standard mount.mounted handler deals with 
# updating the fstab. This is a bit of a hack to prevent entry-doubling, but
# need to flesh it out for additional use-cases.
{%- if salt.file.search(chkFile, '[ 	]'+ chkPtn + '[ 	]') %}
mount_{{ stigId }}-tmp:
  cmd.run:
    - name: 'echo "{{ chkPtn }} already mounted as its own filesystem"'
{%- else %}
mount_{{ stigId }}-tmp:
  cmd.run:
    - name: 'echo "Manual intervention required: create and mount a device as {{ chkPtn }}"'
{%- endif %}
