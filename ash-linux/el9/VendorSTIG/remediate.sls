# This Salt state downloads the tools necessary to scan,
# remediate and report on the compliance-state of an EL9-based
# instance.
#
#################################################################
{%- set stig_id = 'VendorSTIG-top' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set sudoerFiles = salt.file.find('/etc/sudoers.d', maxdepth=1, type='f') %}
{%- if salt.grains.get('os')|lower == 'redhat' %}
  {%- set dsos = 'rhel' %}
{%- elif salt.grains.get('os')|lower == 'oel' %}
  {%- set dsos = 'ol' %}
{%- elif salt.grains.get('os')|lower == 'centos stream' %}
  {%- set dsos = 'cs' %}
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


{%- if salt.grains.get('os') != 'Amazon' and salt.grains.get('osmajorrelease') != 2023 %}
install fapolicyd:
  pkg.installed:
    - pkgs:
      - fapolicyd

script_fapolicyd_rule-files:
  cmd.script:
    - cwd: /root
    - require:
      - pkg: 'install fapolicyd'
    - require_in:
      - cmd: 'run_{{ stig_id }}-remediate'
    - source: 'salt://{{ helperLoc }}/fapolicyd_rules-helper.sh'
    - stateful: True
{%- endif %}

run_{{ stig_id }}-remediate:
  cmd.run:
    - name: 'oscap xccdf eval --remediate --profile {{ scapProf }} {{ dsfile }} > >(tee /var/log/oscap.log) 2>&1'
    - cwd: '/root'
    - shell: '/bin/bash'
    - success_retcodes:
      - 2
