# This Salt state downloads the tools necessary to scan, 
# remediate and report on the compliance-state of an EL7-based
# instance.
#
#################################################################
{%- set stig_id = 'VendorSTIG-top' %}
{%- set helperLoc = 'ash-linux-formula/ash-linux/el7/VendorSTIG/files' %}
{%- set repDir = '/var/tmp' %}
{%- if salt.grains.get('os')|lower == 'redhat' %}
  {%- set dsos = 'rhel' %}
{%- else %}
  {%- set dsos = salt.grains.get('os')|lower %}
{%- endif %}
{%- set osrel = salt.grains.get('osmajorrelease') %}
{%- set contentDir = '/usr/share/xml/scap/ssg/content' %}
{%- set dsXml = contentDir + '/ssg-' + dsos + osrel + '-ds.xml' %}
{%- set cpeXml = contentDir + '/ssg-rhel7-cpe-dictionary.xml' %}
{%- set xccdfXml = contentDir + '/ssg-' + dsos + osrel + '-xccdf.xml' %}
{%- set pillProf = salt.pillar.get('ash-linux:lookup:scap-profile', 'common') %}

run_{{ stig_id }}-report:
  cmd.run:
    - name: '(oscap xccdf eval --profile {{ pillProf }} --report {{ repDir }}/oscap-report_$(date "+%Y%m%d%H%M").html --results {{ repDir }}/oscap-results_$(date "+%Y%m%d%H%M").xml --cpe {{ cpeXml }} {{ xccdfXml }} ) > /dev/null || /bin/true'
    - cwd: '/root' 

