# STIG URL:
# Finding ID:	RHEL-07-021810
# Version:	RHEL-07-021810_rule
# SRG ID:	
# Finding Level:	low
#
# Rule Summary:
#     The system package management tool must not automatically obtain 
#     updates.
#
# CCI-001233
#    NIST SP 800-53 :: SI-2 (2)
#    NIST SP 800-53A :: SI-2 (2).1 (ii)
#    NIST SP 800-53 Revision 4 :: SI-2 (2)
#
#################################################################
{%- set stig_id = 'RHEL-07-021810' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat3/files' %}
{%- set chkPkg = 'yum-cron' %}
{%- set chkCfg = '/etc/yum/yum-cron.conf' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if salt['pkg.version'](chkPkg) %}
file_{{ stig_id }}-config:
  file.replace:
    - name: '{{ chkCfg }}'
    - pattern: '^\s*download_updates = .*$'
    - repl: 'download_updates = no'
{%- else %}
file_{{ stig_id }}-config:
  cmd.run:
    - name: 'echo "The {{ chkPkg }} package is not installed."'
{%- endif %}
