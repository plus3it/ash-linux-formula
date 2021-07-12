# This Salt state downloads the tools necessary to scan,
# remediate and report on the compliance-state of an EL7-based
# instance.
#
#################################################################
{%- set stig_id = 'VendorSTIG-top' %}
{%- set helperLoc = 'ash-linux-formula/ash-linux/el7/VendorSTIG/files' %}
{%- set sudoerFiles = salt.file.find('/etc/sudoers.d', maxdepth=1, type='f') %}
{%- if salt.grains.get('os')|lower == 'redhat' %}
  {%- set dsos = 'rhel' %}
{%- else %}
  {%- set dsos = salt.grains.get('os')|lower %}
{%- endif %}
{%- set osrel = salt.grains.get('osmajorrelease') %}
{%- set contentDir = '/usr/share/xml/scap/ssg/content' %}
{%- set dsfile = salt.pillar.get('ash-linux:lookup:scap-ds') | default(
    contentDir ~ '/ssg-' ~ dsos ~ osrel ~ '-ds.xml',
    true
) %}
{%- set pillProf = salt.pillar.get('ash-linux:lookup:scap-profile', 'common') %}
{%- set scapProf = 'xccdf_org.ssgproject.content_profile_' ~ pillProf %}

run_{{ stig_id }}-remediate:
  cmd.run:
    - name: 'oscap xccdf eval --remediate --profile {{ scapProf }} {{ dsfile }}'
    - cwd: '/root'
    - success_retcodes:
      - 2

# Restore NOPASSWD remediation to sudoers.d files
{%- for sudoer in sudoerFiles %}
uncomment_{{ stig_id}}-{{ sudoer }}:
  file.replace:
    - name: {{ sudoer }}
    - pattern: '(#[ \t]*)(.* NOPASSWD)'
    - repl: '\2'
    - backup: False
    - require:
      - cmd: run_{{ stig_id }}-remediate
{%- endfor %}
