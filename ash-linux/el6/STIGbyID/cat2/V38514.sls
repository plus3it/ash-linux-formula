# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38514
# Finding ID:	V-38514
# Version:	RHEL-06-000124
# Finding Level:	Medium
#
#     The Datagram Congestion Control Protocol (DCCP) must be disabled 
#     unless required. Disabling DCCP protects the system against 
#     exploitation of any flaws in its implementation.
#
#  CCI: CCI-000382
#  NIST SP 800-53 :: CM-7
#  NIST SP 800-53A :: CM-7.1 (iii)
#  NIST SP 800-53 Revision 4 :: CM-7 b
#
############################################################

{%- set stig_id = '38514' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set file = '/etc/modprobe.d/dccp.conf' %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/V{{ stig_id }}.sh
    - cwd: /root


{%- if salt.file.file_exists(file) %}

file_V{{ stig_id }}-fixBlacklist:
  file.replace:
    - name: '{{ file }}'
    - pattern: '^.*\sdccp\s.*$'
    - repl: 'install dccp /bin/true'
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
    - text: 'install dccp /bin/true'
    - require:
      - file: file-V{{ stig_id }}-touchRules

{%- endif %}


