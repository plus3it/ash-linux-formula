# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38622
# Finding ID:	V-38622
# Version:	RHEL-06-000249
# Finding Level:	Medium
#
#     Mail relaying must be restricted. This ensures "postfix" accepts mail 
#     messages (such as cron job reports) from the local system only, and 
#     not from the network, which protects it from network attack.
#
#  CCI: CCI-000382
#  NIST SP 800-53 :: CM-7
#  NIST SP 800-53A :: CM-7.1 (iii)
#  NIST SP 800-53 Revision 4 :: CM-7 b
#
############################################################

{%- set stigId = 'V38622' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set cfgFile = '/etc/postfix/main.cf' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

{%- if salt.pkg.version('postfix') and salt.file.search(cfgFile, '^inet_interfaces') %}
file_{{ stigId }}-repl:
  file.replace:
    - name: '{{ cfgFile }}'
    - pattern: '^inet_interfaces.*$'
    - repl: 'inet_interfaces = localhost'
{%- elif salt.pkg.version('postfix') and not salt.file.search(cfgFile, '^inet_interfaces') %}
file_{{ stigId }}-append:
  file.append:
    - name: '{{ cfgFile }}'
    - text:
      - ' '
      - '# SMTP service must not allow relaying (per STIG V-38622)'
      - 'inet_interfaces = localhost'
{%- elif salt.pkg.version('sendmail') %}
cmd_{{ stigId }}-NotImplemented:
  cmd.run:
    - name: 'echo "Sendmail auto-remediation not supported: manual intervention may be required"'
{%- elif salt.pkg.version('exim') %}
cmd_{{ stigId }}-NotImplemented:
  cmd.run:
    - name: 'echo "Exim auto-remediation not supported: manual intervention may be required"'
{%- endif %}
