# Ref Doc:
#   - STIG - RHEL 9 v2r5      (02 Jul 2025)
#   - STIG - OEL 9 v1r2       (02 Jul 2025)
#   - STIG - AlmaLinux 9 v1r3 (02 Jul 2025)
# Finding ID:
#   - RHEL: V-258129
#   - OEL:  V-271442
#   - Alma: V-269139
# Rule ID:
#   - RHEL: SV-258129r1117265_rule
#   - OEL:  SV-271442r1091038_rule
#   - Alma: SV-269139r1050021_rule
# STIG ID:
#   - RHEL-09-213065
#   - OL09-00-000044
#   - ALMA-09-030270
# SRG ID:   SRG-OS-000095-GPOS-00049
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must disable the Transparent Inter Process Communication (TIPC)
#       kernel module.
#
# References:
#   CCI:
#     - CCI-000213
#   NIST:
#     - SP 800-53 :: AC-3
#     - SP 800-53A :: AC-3.1
#     - SP 800-53 Revision 4 :: AC-3
#
###########################################################################
{%- set stigIdByVendor = {
    'AlmaLinux': 'ALMA-09-030270',
    'CentOS Stream': 'RHEL-09-213065',
    'OEL': 'OL09-00-000044',
    'RedHat': 'RHEL-09-213065',
    'Rocky': 'RHEL-09-213065',
} %}
{%- set stig_id = stigIdByVendor[salt.grains.get('os')] %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set modprobeFiles = [
    '/etc/modprobe.conf'
  ]
%}
{%- if salt.file.directory_exists("/etc/systemd/system/rescue.service.d") %}
  {%- do modprobeFiles.extend(
      salt.file.find(
        searchDir,
	type='f',
	name='*.conf',
	grep='tipc'
      )
    )
  %}
{%- endif %}



{{ stig_id }}-description:
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
             The OS must must disable the TIPC
             kernel module.
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
{%- endif %}
