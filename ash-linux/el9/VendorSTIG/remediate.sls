# This Salt state downloads the tools necessary to scan,
# remediate and report on the compliance-state of an EL8-based
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


install fapolicyd:
  pkg.installed:
    - pkgs:
      - fapolicyd

script_fapolicyd_rule-files:
  cmd.script:
    - cwd: /root
    - require:
      - pkg: 'install fapolicyd'
    - source: 'salt://{{ helperLoc }}/fapolicyd_rules-helper.sh'
    - stateful: True

run_{{ stig_id }}-remediate:
  cmd.run:
    - name: 'oscap xccdf eval --remediate --profile {{ scapProf }} {{ dsfile }} > >(tee /var/log/oscap.log) 2>&1'
    - cwd: '/root'
    - require:
      - cmd: 'script_fapolicyd_rule-files'
    - shell: '/bin/bash'
    - success_retcodes:
      - 2
