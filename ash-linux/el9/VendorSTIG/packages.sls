# This Salt state downloads the tools necessary to scan,
# remediate and report on the compliance-state of an EL8-based
# instance.
#
#################################################################
{%- set stig_id = 'VendorSTIG-top' %}
{%- set helperLoc = tpldir ~ '/files' %}

packages_{{ stig_id }}-installed:
  pkg.installed:
    - pkgs:
      - openscap
      - openscap-scanner
      - scap-security-guide
