# This Salt state downloads the tools necessary to scan, 
# remediate and report on the compliance-state of an EL7-based
# instance.
#
#################################################################
{%- set stig_id = 'VendorSTIG-top' %}
{%- set helperLoc = 'ash-linux-formula/ash-linux/el7/VendorSTIG/files' %}
{%- set dsos = salt.grains.get('os')|lower %}
{%- set osrel = salt.grains.get('osmajorrelease') %}
{%- set contentDir = '/usr/share/xml/scap/ssg/content' %}
{%- set dsfile = 'ssg-' + dsos + osrel + '-ds.xml' %}
{%- set scapProf = 'xccdf_org.ssgproject.content_profile_C2S' %}

run_{{ stig_id }}-remediate:
  cmd.run:
    - name: 'oscap xccdf eval --remediate --profile {{ scapProf }} {{ contentDir }}/{{ dsfile }}'
    - cwd: '/root' 
