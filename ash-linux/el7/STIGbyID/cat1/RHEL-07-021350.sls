# Vuln ID:	V-38653
# STIG ID:	RHEL-07-040500
# Rule ID:      SV-86691r2_rule
# SRG ID(s):    SRG-OS-000033-GPOS-00014
#               SRG-OS-000185-GPOS-00079
#               SRG-OS-000396-GPOS-00176
#               SRG-OS-000405-GPOS-00184
#               SRG-OS-000478-GPOS-00223
# Finding Level:        high
#
# Rule Summary:
#       The operating system must implement NIST FIPS-validated
#       cryptography for the following: to provision digital
#       signatures, to generate cryptographic hashes, and to
#       protect data requiring data-at-rest protections in
#       accordance with applicable federal laws, Executive
#       Orders, directives, policies, regulations, and
#       standards.
#
# CCI-000068
#    NIST SP 800-53 :: AC-17 (2)
#    NIST SP 800-53A :: AC-17 (2).1
#    NIST SP 800-53 Revision 4 :: AC-17 (2)
# CCI-001199
#    NIST SP 800-53 :: SC-28
#    NIST SP 800-53A :: SC-28.1
#    NIST SP 800-53 Revision 4 :: SC-28
# CCI-002450
#    NIST SP 800-53 Revision 4 :: SC-13
# CCI-002476
#    NIST SP 800-53 Revision 4 :: SC-28 (1)
#
#################################################################
{%- set stig_id = 'RHEL-07-021350' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set fipsMode = salt.grains.get('ash-linux:lookup:fips-state') | default(
        salt.pillar.get('ash-linux:lookup:fips-state') | default(
            'enabled',true),
        true) %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Handler for {{ stig_id }} has been selected for skip.''\n"'
    - stateful: True
    - cwd: /root
{%- else %}
fips_state-{{ stig_id }}:
  ash.fips_state:
    - value: {{ fipsMode | string | lower }}
{%- endif %}
