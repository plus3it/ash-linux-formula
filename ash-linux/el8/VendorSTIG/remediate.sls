# This Salt state downloads the tools necessary to scan,
# remediate and report on the compliance-state of an EL8-based
# instance.
#
#################################################################
{%- set stig_id = 'VendorSTIG-top' %}
{%- set helperLoc = 'ash-linux-formula/ash-linux/el8/VendorSTIG/files' %}
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
{%- set awscli_filetypes = [ 'executable', 'sharedlib' ] %}

run_{{ stig_id }}-remediate:
  cmd.run:
    - name: 'oscap xccdf eval --remediate --profile {{ scapProf }} {{ dsfile }} 2>&1 | tee /var/log/oscap.out'
    - cwd: '/root'
    - success_retcodes:
      - 2

# Restore NOPASSWD remediation to sudoers.d files
{%- for sudoer in sudoerFiles %}
uncomment_{{ stig_id}}-{{ sudoer }}:
  file.replace:
    - name: '{{ sudoer }}'
    - pattern: '(#[ \t]*)(.* NOPASSWD)'
    - repl: '\2'
    - backup: False
    - require:
      - cmd: run_{{ stig_id }}-remediate
{%- endfor %}

# Ensure root account password is configured to not expire
root_password_no_expire:
  user.present:
    - name: root
    - createhome: False
    - mindays: -1
    - maxdays: -1
    - require:
      - cmd: run_{{ stig_id }}-remediate

# Add fapolicyd exceptions for AWS CLI
Ensure fapolicyd exception-file exists:
  file.managed:
    - name: '/etc/fapolicyd/rules.d/30-aws.rules'
    - create: True
    - group: 'fapolicyd'
    - mode: '0644'
    - onlyif:
      - 'rpm -q fapolicyd --quiet'
      - '[[ -e /usr/local/bin/aws ]]'
    - selinux:
        serange: 's0'
        serole: 'object_r'
        setype: 'fapolicyd_config_t'
        seuser: 'system_u'
    - user: 'root'

{%- for fileType in awscli_filetypes %}
Exempt AWS CLI v2 From fapolicyd ({{ fileType }}):
  file.replace:
    - name: '/etc/fapolicyd/rules.d/30-aws.rules'
    - append_if_not_found: True
    - onchanges_in:
      - cmd: 'Reload fapolicyd config'
    - pattern: '^(allow\s*perm=).*(\s*all\s*:\s*dir=\/usr\/local\/aws-cli\/v2\/\s*type=application\/x-{{ fileType }}\s*trust\s*1.*$)'
    - repl: 'allow perm=any all : dir=/usr/local/aws-cli/v2/ type=application/x-{{ fileType }} trust 1'
    - require:
      - file: 'Ensure fapolicyd exception-file exists'
{%- endfor %}

Reload fapolicyd config:
  cmd.run:
    - name: '/usr/sbin/fapolicyd-cli -u'
    - cwd: '/root'
    - stateful: False
