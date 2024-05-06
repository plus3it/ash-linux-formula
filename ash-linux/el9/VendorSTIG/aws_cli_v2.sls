# This Salt state creats an exception in fapolicyd for the AWS
# CLI v2 if fapolicyd and the AWS CLI v2 are both installed.
#
#################################################################
{%- set awscli_filetypes = [ 'executable', 'sharedlib' ] %}
{%- set exemptionFile = '/etc/fapolicyd/rules.d/30-aws.rules' %}

# Add fapolicyd exceptions for AWS CLI
Ensure fapolicyd exception-file exists:
  file.managed:
    - name: '{{ exemptionFile }}'
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
    - name: '{{ exemptionFile }}'
    - append_if_not_found: True
    - onchanges_in:
      - cmd: 'Reload fapolicyd config'
    - ignore_if_missing: True
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
