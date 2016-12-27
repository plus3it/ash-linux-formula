# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38516
# Finding ID:	V-38516
# Version:	RHEL-06-000126
# Finding Level:	Low
#
#     The Reliable Datagram Sockets (RDS) protocol must be disabled unless 
#     required. Disabling RDS protects the system against exploitation of 
#     any flaws in its implementation.
#
############################################################

{%- set stig_id = '38516' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}
{%- set file = '/etc/modprobe.d/rds.conf' %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/V{{ stig_id }}.sh
    - cwd: /root


{%- if salt.file.file_exists(file) %}

file_V{{ stig_id }}-fixBlacklist:
  file.replace:
    - name: '{{ file }}'
    - pattern: '^.*\srds\s.*$'
    - repl: 'install rds /bin/true'
    - require:
      - cmd: script_V{{ stig_id }}-describe

{%- else %}

file-V{{ stig_id }}-touchRules:
  file.touch:
    - name: '{{ file }}'
    - require:
      - cmd: script_V{{ stig_id }}-describe

file_V{{ stig_id }}-fixBlacklist:
  file.append:
    - name: '{{ file }}'
    - text: 'install rds /bin/true'
    - require:
      - file: file-V{{ stig_id }}-touchRules

{%- endif %}


