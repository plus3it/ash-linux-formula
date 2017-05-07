# This Salt state downloads the tools necessary to scan,
# remediate and report on the compliance-state of an EL7-based
# instance.
#
#################################################################
{%- set stig_id = 'VendorSTIG-top' %}
{%- set helperLoc = 'ash-linux-formula/ash-linux/el7/VendorSTIG/files' %}
{%- set repDir = salt.pillar.get('ash-linux:lookup:scap-output') | default(
    '/var/tmp',
    true
) %}
{%- if salt.grains.get('os')|lower == 'redhat' %}
  {%- set dsos = 'rhel' %}
{%- else %}
  {%- set dsos = salt.grains.get('os')|lower %}
{%- endif %}
{%- set osrel = salt.grains.get('osmajorrelease') %}
{%- set contentDir = '/usr/share/xml/scap/ssg/content' %}
{%- set cpeXml = salt.pillar.get('ash-linux:lookup:scap-cpe') | default(
    contentDir ~ '/ssg-rhel7-cpe-dictionary.xml',
    true
) %}
{%- set xccdfXml = salt.pillar.get('ash-linux:lookup:scap-xccdf') | default(
    contentDir ~ '/ssg-' ~ dsos ~ osrel ~ '-xccdf.xml',
    true
) %}
{%- set pillProf = salt.pillar.get('ash-linux:lookup:scap-profile', 'common') %}

run_{{ stig_id }}-report:
  cmd.run:
    - name: '(oscap xccdf eval --profile {{ pillProf }} --report {{ repDir }}/oscap-report_$(date "+%Y%m%d%H%M").html --results {{ repDir }}/oscap-results_$(date "+%Y%m%d%H%M").xml --cpe {{ cpeXml }} {{ xccdfXml }} ) || /bin/true'
    - cwd: '/root'
