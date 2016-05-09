# STIG URL:
# Finding ID:	RHEL-07-030760
# Version:	RHEL-07-030760_rule
# SRG ID:	
# Finding Level:	low
#
# Rule Summary:
#     xinetd logging/tracing must be enabled via rsyslog.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-030760' %}
{%- set helperLoc = 'ash-linux/STIGbyID/el7/cat3/files' %}
{%- set chkPkg = 'xinetd' %}
{%- set chkCfg = '/etc/rsyslog.conf' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

# Check if xinetd is installed
{%- if salt['pkg.version'](chkPkg) %}
  # Check if xinetd's actions are already being logged to rsyslog...
  {%- if salt['file.search'](chkCfg, '^\s*\*\.\* ') or 
         salt['file.search'](chkCfg, '^\s*daemon\.\* ')
   %}
file_{{ stig_id }}-config:
  cmd.run:
    - name: 'echo "STIG-recommended setting found in {{ chkCfg }}."'
  # ...add requisite directive if not previously logging to rsyslog
  {%- else %}
file_{{ stig_id }}-config:
  file.append:
    - name: '{{ chkCfg }}'
    - text: 'daemon.* /var/log/messages'
  {%- endif %}
# Emit a "not installed" message if no xinetd package is present
{%- else %}
file_{{ stig_id }}-config:
  cmd.run:
    - name: 'echo "The {{ chkPkg }} package is not installed."'
{%- endif %}
