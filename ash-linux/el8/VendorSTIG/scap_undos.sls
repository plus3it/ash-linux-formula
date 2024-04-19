# This Salt state undoes anything put in place by the
# "remediate" state that shouldn't have been done as part of the
# generic OSCAP content
#
#################################################################

# Undo SCAP's appending of a `*.* @@logcollector` config-token in the
# rsyslog.conf file
undo logcollector in /etc/rsyslog.conf:
  file.replace:
    - name: '/etc/rsyslog.conf'
    - not_found_content: ''
    - pattern: '^(\s*|#*\s*|)\*\.\*\s*@*logcollector$'
    - repl: ''
