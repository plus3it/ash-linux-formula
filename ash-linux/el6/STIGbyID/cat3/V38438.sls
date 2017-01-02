# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38438
# Finding ID:	V-38438
# Version:	RHEL-06-000525
# Finding Level:	Low
#
#     Each process on the system carries an "auditable" flag which
#     indicates whether its activities can be audited. Although "auditd"
#     takes care of enabling this for all processes which launch after it
#     does, adding the kernel argument ensures it is set for every process
#     during boot.
#
#  CCI: CCI-000169
#  NIST SP 800-53 :: AU-12 a
#  NIST SP 800-53A :: AU-12.1 (ii)
#  NIST SP 800-53 Revision 4 :: AU-12 a
#
############################################################

{%- set stig_id = '38438' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}
{%- set grubCfgFile = '/boot/grub/grub.conf' %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/V{{ stig_id }}.sh
    - cwd: '/root'

# Enable audit at kernel load
{%- if salt.file.search(grubCfgFile, 'kernel', ignore_if_missing=True) and not salt.file.search(grubCfgFile, 'kernel.*audit=1', ignore_if_missing=True) %}

file_V{{ stig_id }}-repl:
  file.replace:
    - name: '{{ grubCfgFile }}'
    - pattern: '(?P<srctok>kernel.*$)'
    - repl: '\g<srctok> audit=1'

notify_V{{ stig_id }}-audit:
  cmd.run:
    - name: 'printf "Note: Enabled audit at IPL via addition of\n      ''audit=1'' to {{ grubCfgFile }}\n"'
    - unless: 'file_V{{ stig_id }}-audit'

{%- else %}

status_V{{ stig_id }}:
  cmd.run:
    - name: 'echo "Auditing already enabled at boot"'

{%- endif %}
