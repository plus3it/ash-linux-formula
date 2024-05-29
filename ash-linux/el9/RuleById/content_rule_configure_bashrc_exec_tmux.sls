# Rule ID:              content_rule_configure_bashrc_exec_tmux
# Finding Level:        medium
#
# Rule Summary:
#       The tmux terminal multiplexer is used to implement automatic session
#       locking. It should be started from /etc/bashrc or drop-in files within
#       /etc/profile.d/.
#
# Identifiers:
#   - content_rule_configure_bashrc_exec_tmux
#
# References:
#   - DISA
#     - CCI-000056
#     - CCI-000058
#   - OSPP
#     - FMT_SMF_EXT.1
#     - FMT_MOF_EXT.1
#     - FTA_SSL.1
#   - OS-SRG
#     - SRG-OS-000031-GPOS-00012
#     - SRG-OS-000028-GPOS-00009
#     - SRG-OS-000030-GPOS-00011
#
#################################################################
{%- set stig_id = 'configure_bashrc_exec_tmux' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set profileFile ='/etc/profile.d/tmux.sh' %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |
        -------------------------------------------
        STIG Finding ID: configure_bashrc_exec_tmux
           The tmux terminal multiplexer is used to
           implement automatic session locking. It
           should be started for every interactive
           login-shell.
        -------------------------------------------

# Ensure profile.d file exists
file_{{ stig_id }}-{{ profileFile }}:
  file.managed:
    - name: '{{ profileFile }}'
    - user: 'root'
    - group: 'root'
    - mode: '0644'
    - makedirs: True
    - dir_mode: '0755'
    - contents: |-
        # Check if tmux is available
        if [[ $( rpm -q tmux --quiet )$? -ne 0 ]] || [[ ! -x /usr/bin/tmux ]]
        then
           return
        fi

        # Check if shell is interactive
        if [ "$PS1" ]; then
          parent=$(ps -o ppid= -p $$)
          name=$(ps -o comm= -p $parent)
          case "$name" in (sshd|login) tmux ;; esac
        fi
