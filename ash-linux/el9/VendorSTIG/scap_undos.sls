# This Salt state undoes anything put in place by the
# "remediate" state that shouldn't have been done as part of the
# generic OSCAP content
#
#################################################################
{%- set sudoerFiles = [ '/etc/sudoers' ] %}
{%- set sudoerFiles = sudoerFiles + salt.file.find('/etc/sudoers.d', maxdepth=1, type='f') %}


# Undo SCAP's appending of a `*.* @@logcollector` config-token in the
# rsyslog.conf file
undo logcollector in /etc/rsyslog.conf:
  file.replace:
    - name: '/etc/rsyslog.conf'
    - not_found_content: ''
    - pattern: '^(\s*|#*\s*|)\*\.\*\s*@*logcollector$'
    - repl: ''

# Restore NOPASSWD remediation to sudoers.d files
{%- for sudoer in sudoerFiles %}
uncomment-{{ sudoer }}:
  file.replace:
    - name: '{{ sudoer }}'
    - pattern: '(#[ \t]*)(.* NOPASSWD)'
    - repl: '\2'
    - backup: False
{%- endfor %}

# Ensure root account password is configured to not expire
root_password_no_expire:
  user.present:
    - name: root
    - createhome: False
    - mindays: -1
    - maxdays: -1
