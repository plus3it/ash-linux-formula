# Ref Doc:
#   - STIG - RHEL 9 v2r6      (01 Oct 2025)
#   - STIG - OEL 9 v1r3       (01 Oct 2025)
#   - STIG - AlmaLinux 9 v1r4 (01 Oct 2025)
# Finding ID:
#   - RHEL: V-258123
#   - OEL:  V-271608
#   - Alma: V-269371
# Rule ID:
#   - RHEL: SV-258123r1134923_rule
#   - OEL:  SV-271608r1091536_rule
#   - Alma: SV-269371r1050254_rule
# STIG ID:
#   - RHEL-09-611170
#   - OL09-00-000930
#   - ALMA-09-033680
# SRG ID:     SRG-OS-000375-GPOS-00160
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must implement certificate status checking for multifactor authentication
#
# References:
#   CCI:
#     - CCI-001948
#     - CCI-001954
#   NIST:
#     - SP 800-53 Revision 4 :: IA-2 (11)
#     - SP 800-53 Revision 4 :: IA-2 (12)
#
###########################################################################
{%- set stigIdByVendor = {
    'AlmaLinux': 'ALMA-09-033680',
    'CentOS Stream': 'RHEL-09-611170',
    'OEL': 'OL09-00-000930',
    'RedHat': 'RHEL-09-611170',
    'Rocky': 'RHEL-09-611170',
} %}
{%- set stig_id = stigIdByVendor[salt.grains.get('os')] %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set digestFunction = salt.pillar.get('ash-linux:lookup:sssd:special:certificate_verification:ocsp_dgst', 'sha512') %}
{%- set sssdCfgFiles = [] %}
{%- set sssdDefCfgFile = '/etc/sssd/sssd.conf' %}
{%- set searchDir = '/etc/sssd/conf.d' %}
{%- set stdVerifyCfg = searchDir + '/certificate_verification.conf' %}
{%- if salt.file.file_exists(sssdDefCfgFile) %}
  {%- do sssdCfgFiles.append(sssdDefCfgFile) %}
{%- endif %}
{%- set sssdCfgFiles = sssdCfgFiles + salt.file.find(
    searchDir,
    type='f',
    name='*.conf',
    grep='certificate_verification\s*='
  )
%}


{{ stig_id }}-description:
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
             The OS must implement certificate
             status checking for multifactor
             authentication
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
  {%- for sssdCfgFile in sssdCfgFiles %}
Ensure 'certificate_verification' options are correct for {{ sssdCfgFile }}:
  file.replace:
    - name: '{{ sssdCfgFile }}'
    - pattern: '^((|\s\s*)certificate_verification(\s*=\s*)).*'
    - repl: \1ocsp_dgst={{ digestFunction }}
    - onchanges_in:
      - service: 'Re-read SSSD configuration-options'
  {%- else %}
Create {{ stdVerifyCfg }}:
  file.managed:
    - name: '{{ stdVerifyCfg }}'
    - contents: |
        # Installed per STIG-ID '{{ stig_id }}'
        certificate_verification = ocsp_dgst={{ digestFunction }}
    - group: 'root'
    - mode: '0600'
    - selinux:
        serange: 's0'
        serole: 'object_r'
        setype: 'sssd_conf_t'
        seuser: 'system_u'
    - user: 'root'
    - watch_in:
      - service: 'Re-read SSSD configuration-options'

  {%- endfor %}
{%- endif %}

Re-read SSSD configuration-options:
  service.running:
    - name: sssd
    - enable: true
    - reload: false
    - onlyif:
      - 'test -e "{{ sssdDefCfgFile }}"'
