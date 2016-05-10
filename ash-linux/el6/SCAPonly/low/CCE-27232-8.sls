# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID:
# - network_ipv6_disable_rpc
#
# Security identifiers:
# - CCE-27232-8
#
# Rule Summary: Disable udp6 and tcp6 entries in /etc/netconfig
#
# Rule Text: RPC services for NFSv4 try to load transport modules for 
#            udp6 and tcp6 by default, even if IPv6 has been disabled in 
#            /etc/modprobe.d. To prevent RPC services such as rpc.mountd 
#            from attempting to start IPv6 network listeners, remove or 
#            comment out the following two lines in /etc/netconfig:
#
#################################################################

{%- set helperLoc = 'ash-linux/el6/SCAPonly/low/files' %}
{%- set scapId = 'CCE-27232-8' %}
{%- set checkFile = '/etc/netconfig' %}
{%- set checkPat = [ 'udp6', 'tcp6' ] %}
{%- set notify_change = '''{{ svcName }}'' has been enabled' %}
{%- set notify_nochange = '''{{ svcName }}'' already enabled' %}

script_{{ scapId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ scapId }}.sh
    - cwd: '/root'

{%- for proto in checkPat %}
comment_{{ scapId }}-{{ proto }}:
  file.comment:
    - name: '{{ checkFile }}'
    - regex: '^{{ proto }}'
    - backup: '.bak-{{ proto }}'
    - onlyif: 'grep "^{{ proto }}" {{ checkFile }}'
{%- endfor %}
