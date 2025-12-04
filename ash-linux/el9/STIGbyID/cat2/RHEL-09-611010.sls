# Ref Doc:
#   - STIG - RHEL 9 v2r6      (01 Oct 2025)
#   - STIG - OEL 9 v1r3       (01 Oct 2025)
#   - STIG - AlmaLinux 9 v1r4 (01 Oct 2025)
# Finding ID:
#   - RHEL: V-258091
#   - OEL:  V-271612
#   - Alma: V-269387
# Rule ID:
#   - RHEL: SV-258091r1045185_rule
#   - OEL:  SV-271612r1091548_rule
#   - Alma: SV-269387r1050270_rule
# STIG ID:
#   - RHEL-09-611010
#   - OL09-00-001001
#   - ALMA-09-035990
# SRG ID:     SRG-OS-000069-GPOS-00037
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must ensure the password complexity module in the system-auth
#       file is configured for three retries or less.
#
# References:
#   CCI:
#     - CCI-000192
#   NIST:
#     - SP 800-53 :: IA-5 (1) (a)
#     - SP 800-53A :: IA-5 (1).1 (v)
#     - SP 800-53 Revision 4 :: IA-5 (1) (a)
#
###########################################################################
{%- set stigIdByVendor = {
    'AlmaLinux': 'ALMA-09-035990',
    'CentOS Stream': 'RHEL-09-611010',
    'OEL': 'OL09-00-001001',
    'RedHat': 'RHEL-09-611010',
    'Rocky': 'RHEL-09-611010',
} %}
{%- set stig_id = stigIdByVendor[salt.grains.get('os')] %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set retryTimes = salt.pillar.get('ash-linux:lookup:pwquality:retries', '3') %}
{%- set pwqualityCfgFiles = [] %}
{%- set pwqualityDefCfgFile = '/etc/security/pwquality.conf' %}
{%- set searchDir = '/etc/security/pwquality.conf.d' %}
{%- if salt.file.file_exists(pwqualityDefCfgFile) %}
  {%- do pwqualityCfgFiles.append(pwqualityDefCfgFile) %}
{%- endif %}
{%- set pwqualityCfgFiles = pwqualityCfgFiles + salt.file.find(
    searchDir,
    type='f',
    name='*.conf',
    grep='retry\s*='
  )
%}

{{ stig_id }}-description:
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
             The OS must be configured to allow
             three or fewer password-failures
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
  {%- for pwqualityCfgFile in pwqualityCfgFiles %}
Modify {{ pwqualityCfgFile }}:
  file.replace:
    - name: '{{ pwqualityCfgFile }}'
    - append_if_not_found: True
    - not_found_content: |

        # Set per rule {{ stig_id }}
        # Prompt user at most '{{ retryTimes }}' times before returning with error
        retry = {{ retryTimes }}
    - onlyif:
      - 'grep -qP "retry(|\s\s*)=" {{ pwqualityCfgFile }}'
    - pattern: '(^(|\s\s*)retry)((|\s\s*)=(|\s\s*))\d'
    - repl: |-
        retry = {{ retryTimes }}
  {%- endfor %}
{%- endif %}
