# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID:
# - network_disable_zeroconf
#
# Security identifiers:
# - CCE-27151-0
#
# Rule Summary: Disable Zeroconf Networking
#
# Rule Text: Zeroconf networking allows the system to assign itself an 
#            IP address and engage in IP communication without a 
#            statically-assigned address or even a DHCP server. 
#            Automatic address assignment via Zeroconf (or DHCP) is not 
#            recommended.
#
#################################################################

{%- set helperLoc = 'ash-linux/el6/SCAPonly/low/files' %}
{%- set scapId = 'CCE-27151-0' %}
{%- set checkFile = '/etc/sysconfig/network' %}

script_{{ scapId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ scapId }}.sh
    - cwd: '/root'

alter_{{ scapId }}-{{ checkFile }}:
  file.replace:
    - name: '{{ checkFile }}'
    - pattern: '^NOZEROCONF=no'
    - repl: 'NOZEROCONF=yes'
    - onlyif: 'grep -E "^NOZEROCONF=no" {{ checkFile }}'

append_{{ scapId }}-{{ checkFile }}:
  file.append:
    - name: '{{ checkFile }}'
    - text: |
        # Added per SCAP-ID CCE-27151-0
        NOZEROCONF=yes
    - unless: 'grep -E "^NOZEROCONF=" {{ checkFile }}'
  
