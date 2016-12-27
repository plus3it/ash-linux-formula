# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38682
# Finding ID:	V-38682
# Version:	RHEL-06-000315
# Finding Level:	Medium
#
#     The Bluetooth kernel module must be disabled. If Bluetooth 
#     functionality must be disabled, preventing the kernel from loading 
#     the kernel module provides an additional safeguard against its 
#     activation.
#
#  CCI: CCI-000085
#  NIST SP 800-53 :: AC-19 c
#  NIST SP 800-53A :: AC-19.1 (iii)
#
############################################################

{%- set stig_id = '38682' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set file = '/etc/modprobe.d/bluetooth.conf' %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/V{{ stig_id }}.sh
    - cwd: '/root'

{%- if salt.file.file_exists(file) %}

file_V{{ stig_id }}-fixBtBlacklist:
  file.replace:
    - name: '{{ file }}'
    - pattern: '^.*\sbluetooth\s.*$'
    - repl: 'install bluetooth /bin/true'
    - require:
      - cmd: script_V{{ stig_id }}-describe

file_V{{ stig_id }}-fixNpfBlacklist:
  file.replace:
    - name: '{{ file }}'
    - pattern: '^.*\snet-pf-31\s.*$'
    - repl: 'install net-pf-31 /bin/true'
    - require:
      - cmd: script_V{{ stig_id }}-describe

{%- else %}

file-V{{ stig_id }}-touchRules:
  file.touch:
    - name: '{{ file }}'
    - require:
      - cmd: script_V{{ stig_id }}-describe

file_V{{ stig_id }}-fixBTblacklist:
  file.append:
    - name: '{{ file }}'
    - text: 'install bluetooth /bin/true'
    - require:
      - file: file-V{{ stig_id }}-touchRules

file_V{{ stig_id }}-fixNPFblacklist:
  file.append:
    - name: '{{ file }}'
    - text: 'install net-pf-31 /bin/true'
    - require:
      - file: file-V{{ stig_id }}-touchRules

{%- endif %}
