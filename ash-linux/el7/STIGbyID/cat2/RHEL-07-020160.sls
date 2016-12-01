# Finding ID:	RHEL-07-020160
# Version:	RHEL-07-020160_rule
# SRG ID:	SRG-OS-000114-GPOS-00059
# Finding Level:	medium
# 
# Rule Summary:
#	USB mass storage must be disabled.
#
# CCI-000366 
# CCI-000778 
# CCI-001958 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#    NIST SP 800-53 :: IA-3 
#    NIST SP 800-53A :: IA-3.1 (ii) 
#    NIST SP 800-53 Revision 4 :: IA-3 
#    NIST SP 800-53 Revision 4 :: IA-3 
#
#################################################################
{%- set stig_id = 'RHEL-07-020160' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set foundMods = [] %}
{%- set modFiles = [] %}
{%- for modFile in salt.file.find('/etc/modprobe.d', maxdepth='0', type='f') %}
  {%- do modFiles.append(modFile) %}
{%- endfor %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- for modFile in modFiles %}
  {%- if salt.file.search(modFile, '^[a-z]*\susb') %}
    {%- do foundMods.append(modFile) %}
file_{{ stig_id }}-foundin-{{ modFile }}:
  file.replace:
    - name: '{{ modFile }}'
    - pattern: '^[a-z]*\susb.*$'
    - repl: 'install usb-storage /bin/true'
    - backup: False
  {%- endif %}

{%- endfor %}

{%- if not foundMods %}
file_{{ stig_id }}-nousbstorage:
  file.append:
    - name: '/etc/modprobe.d/nousbstorage'
    - text: 'install usb-storage /bin/true'
{%- endif %}
