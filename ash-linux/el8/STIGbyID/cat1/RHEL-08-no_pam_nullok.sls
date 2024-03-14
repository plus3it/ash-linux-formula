# Ref Doc:    STIG - RHEL 8 v1r11
# Finding ID: V-244540
#             V-244541
# Rule ID:    SV-244540r743869_rule
#             SV-244541r743872_rule
# STIG ID:    RHEL-08-020331
#             RHEL-08-020332
# SRG ID:     SRG-OS-000480-GPOS-00227
#
# Finding Level: high
#
# Rule Summary:
#       The OS must not allow blank or null passwords in either the system-auth
#       or password-auth files
#
# References:
#   CCI:
#     - CCI-000366
#       - NIST SP 800-53 :: CM-6 b
#       - NIST SP 800-53A :: CM-6.1 (iv)
#       - NIST SP 800-53 Revision 4 :: CM-6 b
#
###########################################################################
{%- set stig_id = 'RHEL-08-no_pam_nullok' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |
        --------------------------------------
        STIG Finding IDs: V-244540, V-244541
             The OS must not allow blank or
             null passwords
        --------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
Update PAM and AuthSelect ({{ stig_id }}):
  pkg.latest:
    - pkgs:
      - pam
      - authselect

Disable nullok module in PAM:
  cmd.run:
    - name: authselect enable-feature without-nullok
    - cwd: /root
    - onlyif:
      - 'authselect check'
    - unless:
      - 'authselect current | grep -q "without-nullok"'

{%- endif %}

