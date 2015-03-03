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
{%- set file = '/etc/modprobe.d/rds.conf' %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat3/files/V{{ stig_id }}.sh
    - cwd: /root

{%- if not salt['file.file_exists']('{{ file }}') %}

file-V{{ stig_id }}-touchRules:
  file.touch:
    - name: '{{ file }}'

file_V{{ stig_id }}-appendBlacklist:
  file.append:
    - name: '{{ file }}'
    - text: 'install rds /bin/false'
    - require:
      - file: file-V{{ stig_id }}-touchRules
    - onlyif:
      - 'test -f {{ file }}'

{%- elif salt['file.search']('{{ file }}', '^install rds /bin/false') %}

file_V{{ stig_id }}-appendBlacklist:
   cmd.run:
     - name: 'echo "RDS already blacklisted in {{ file }}"'

{%- else %}

file_V{{ stig_id }}-appendBlacklist:
  file.replace:
    - name: '{{ file }}
    - pattern: '^.*install[ \t]rds.*$'
    - repl: 'install rds /bin/false'

{%- endif %}
