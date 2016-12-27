# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38471
# Finding ID:	V-38471
# Version:	RHEL-06-000509
# Finding Level:	Low
#
#     The auditd service does not include the ability to send audit records 
#     to a centralized server for management directly. It does, however, 
#     include an audit event multiplexor plugin (audispd) to pass audit 
#     records to the local syslog server. 
#
#  CCI: CCI-000136
#  NIST SP 800-53 :: AU-3 (2)
#  NIST SP 800-53A :: AU-3 (2).1 (ii)
#
############################################################

{%- set stigId = 'V38471' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

{%- set syslogConf = '/etc/audisp/plugins.d/syslog.conf' %}

{%- if salt.file.search(syslogConf, 'active') %}
  {%- if salt.file.search(syslogConf, '^#.*active.*=.*yes') %}
file_{{ stigId }}-mkActive:
  file.uncomment:
    - name: '{{ syslogConf }}'
    - regex: 'active = yes'
  {%- elif salt.file.search(syslogConf, '^active.*=.*no') %}
file_{{ stigId }}-mkActive:
  file.replace:
    - name: '{{ syslogConf }}'
    - pattern: '^active.*=.*no'
    - repl: 'active = yes'
  {%- elif salt.file.search(syslogConf, '^.*active.*=.*yes') %}
file_{{ stigId }}-mkActive:
  cmd.run:
    - name: 'echo "Audit service already configured to forward logs to syslog service"'
  {%- endif %}
{%- else %}
file_{{ stigId }}-mkActive:
  file.append:
    - name: '{{ syslogConf }}'
    - text: |
        
        # Audit records must be forwarded to the syslog service (per STIG-ID V-38471)
        active = yes
{%- endif %}
