# Ref Doc:
#   - STIG - OEL 9 v1r3       (01 Oct 2025)
#   - STIG - AlmaLinux 9 v1r4 (01 Oct 2025)
# Finding ID:
#   - OEL:  V-271901
#   - Alma: V-269427
# Rule ID:
#   - OEL:  SV-271901r1092415_rule
#   - Alma: SV-269427r1050310_rule
# STIG ID:
#   - OL09-00-900140
#   - ALMA-09-041270
# SRG ID:     SRG-OS-000403-GPOS-00182
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must only allow the use of DOD PKI-established certificate
#       authorities for authentication in the establishment of protected
#       sessions to the operating system
#
# References:
#   CCI:
#     - CCI-002470
#   NIST:
#     - SP 800-53 Revision 4 :: SC-23 (5)
#
###########################################################################
{%- set stigIdByVendor = {
    'AlmaLinux': 'ALMA-09-041270',
    'CentOS Stream': 'ALMA-09-041270',
    'OEL': 'OL09-00-900140',
    'RedHat': 'ALMA-09-041270',
    'Rocky': 'ALMA-09-041270',
} %}
{%- set stig_id = stigIdByVendor[salt.grains.get('os')] %}
{%- set osName = salt.grains.get('os') %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set trustOutRaw = salt.cmd.shell(
    'trust list --filter=ca-anchors 2> /dev/null | ' +
    'grep -E "^(pkcs11:|\s\s*label)" |' +
    'sed -e "N ; s/cert\\n\s\s*label:\s*/cert|/"'
  )
%}
{%- set trustOutList = trustOutRaw.split('\n') %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
            The OS must blacklist non-DoD
            certificate authorities from system-
            wide trust-list
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- elif
  (
    osName == "AlmaLinux" or
    osName == "OEL"
  )
%}
  {%- for line in trustOutList %}
    {%- set certID = line.split('|')[0] %}
    {%- set certNameUTF = line.split('|')[1].replace("/", "_") %}
Write blacklist-file for {{ certNameUTF }} file:
  file.managed:
    - name: '/etc/pki/ca-trust/source/blocklist/{{ certNameUTF }}'
    - contents:
        # Installed per STIG-ID '{{ stig_id }}'
    - group: 'root'
    - mode: '0600'
    - replace: False
    - onchanges_in:
      - cmd: 'Process blacklisted root CAs'
    - user: 'root'

Add content to blacklist-file for {{ certNameUTF }}:
  cmd.run:
    - name: 'trust dump --filter "{{ certID }}" > "/etc/pki/ca-trust/source/blocklist/{{ certNameUTF }}" 2> /dev/null'
    - onchanges:
      - file: 'Write blacklist-file for {{ certNameUTF }} file'
  {%- endfor %}
Process blacklisted root CAs:
  cmd.run:
    - name: 'update-ca-trust'
{%- else %}
{%- endif %}
