# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38467
# Finding ID:	V-38467
# Version:	RHEL-06-000004
# Finding Level:	Low
#
#     The system must use a separate file system for the system audit data 
#     path. Placing "/var/log/audit/audit" in its own partition enables better 
#     separation between audit files and other files, and helps ensure that 
#     auditing cannot be halted due to the partition running out of space.
#
#  CCI: CCI-000137
#  NIST SP 800-53 :: AU-4
#  NIST SP 800-53A :: AU-4.1 (i)
#
############################################################

{%- set stigId = 'V38467' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}
{%- set chkFile = '/etc/fstab' %}
{%- set chkPtn = '/var/log/audit' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

# Not really happy with how the standard mount.mounted handler deals with 
# updating the fstab. This is a bit of a hack to prevent entry-doubling, but
# need to flesh it out for additional use-cases.
{%- if salt.file.search(chkFile, '[ 	]' + chkPtn + '[ 	]') %}
mount_{{ stigId }}-tmp:
  cmd.run:
    - name: 'echo "{{ chkPtn }} already mounted as its own filesystem"'
{%- else %}
mount_{{ stigId }}-tmp:
  cmd.run:
    - name: 'echo "Manual intervention required: create and mount a device as {{ chkPtn }}"'
{%- endif %}
