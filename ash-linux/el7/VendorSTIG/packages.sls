# This Salt state downloads the tools necessary to scan, 
# remediate and report on the compliance-state of an EL7-based
# instance.
#
#################################################################
{%- set stig_id = 'VendorSTIG-top' %}
{%- set helperLoc = 'ash-linux-formula/ash-linux/el7/VendorSTIG/files' %}

packages_{{ stig_id }}-installed:
  pkg.installed:
    - pkgs:
      - openscap
      - openscap-scanner
{%- if salt.grains.get('os') == 'CentOS' %}
      - openscap-engine-sce
{%- endif %}
      - scap-security-guide
