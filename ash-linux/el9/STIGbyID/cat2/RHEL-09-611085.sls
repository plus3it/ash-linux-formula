# Ref Doc:
#   - STIG - RHEL 9 v2r6      (01 Oct 2025)
#   - STIG - OEL 9 v1r3       (01 Oct 2025)
#   - STIG - AlmaLinux 9 v1r4 (01 Oct 2025)
# Finding ID:
#   - RHEL: V-258106
#   - OEL:  V-271725
#   - Alma: V-269360
# Rule ID:
#   - RHEL: SV-258106r1102061_rule
#   - OEL:  SV-271725r1091887_rule
#   - Alma: SV-269360r1101822_rule
# STIG ID:
#   - RHEL-09-611085
#   - OL09-00-002363
#   - ALMA-09-032030
# SRG ID:     SRG-OS-NNNNNN-GPOS-NNNNN
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must require users to provide a password for privilege
#       escalation
#
# References:
#   CCI:
#     - CCI-000213
#   NIST:
#     - SP 800-53 ::
#     - SP 800-53A ::
#     - SP 800-53 Revision 4 ::
#
###########################################################################
{%- set stigIdByVendor = {
    'AlmaLinux': 'ALMA-09-032030',
    'CentOS Stream': 'RHEL-09-611085',
    'OEL': 'OL09-00-002363',
    'RedHat': 'RHEL-09-611085',
    'Rocky': 'RHEL-09-611085',
} %}
{%- set stig_id = stigIdByVendor[salt.grains.get('os')] %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set defSudoerFile = '/etc/sudoers' %}
{%- set searchDir = '/etc/sudoers.d' %}
{%- set sudoersFiles = [
    defSudoerFile
  ]
%}
{%- set sudoersFiles = sudoersFiles + salt.file.find(
    searchDir,
    type='f',
    grep='NOPASSWD'
  )
%}

{{ stig_id }}-description:
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
            The OS must require users to provide
            a password for privilege escalation
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
  {%- for sudoersFile in sudoersFiles %}
    {%- if (
             sudoersFile != "/etc/sudoers.d/90-cloud-init-users" and
             sudoersFile != "/etc/sudoers.d/ssm-agent-users"
           )  %}
Nuke NOPASSWD Tag_Spec from all "ALL" declarations in {{ sudoersFile }}:
  file.replace:
    - name: '{{ sudoersFile }}'
    - backup: False
    - pattern: '^((%|\w)\w*)(\s\s*)(.*)(NOPASSWD(|\s*):)(|\s*)ALL$'
    - repl: '\1\3\4ALL'
    {%- endif %}
  {%- endfor %}
{%- endif %}
