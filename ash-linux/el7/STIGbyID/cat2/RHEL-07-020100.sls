# STIG ID:	RHEL-07-020100
# Rule ID:	SV-86607r4_rule
# Vuln ID:	V-71983
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
{%- set stig_id = 'RHEL-07-020100' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set foundMods = [] %}
{%- set modFiles = [] %}
{%- for modFile in salt.file.find('/etc/modprobe.d', maxdepth=1, type='f') %}
  {%- do modFiles.append(modFile) %}
{%- endfor %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Handler for {{ stig_id }} has been selected for skip.''\n"'
    - stateful: True
    - cwd: /root
{%- else %}
  {%- for modFile in modFiles %}
    {%- if salt.file.search(modFile, '^[a-z]*\susb') %}
      {%- do foundMods.append(modFile) %}
file_{{ stig_id }}-foundin-{{ modFile }}-install:
  file.replace:
    - name: '{{ modFile }}'
    - pattern: ^[s]*install[s]*usb-storage[s]*/bin/true.*$
    - repl: 'install usb-storage /bin/true'
    - append_if_not_found: True
    - backup: False
file_{{ stig_id }}-foundin-{{ modFile }}-blacklist:
  file.replace:
    - name: '{{ modFile }}'
    - pattern: ^[s]*blacklist[s]*usb-storage.*$
    - repl: 'blacklist usb-storage'
    - append_if_not_found: True
    - backup: False
    {%- endif %}

  {%- endfor %}

  {%- if not foundMods %}
file_{{ stig_id }}-nousbstorage:
  file.append:
    - name: '/etc/modprobe.d/nousbstorage.conf'
    - text: |-
        install usb-storage /bin/true
        blacklist usb-storage
  {%- endif %}
{%- endif %}
