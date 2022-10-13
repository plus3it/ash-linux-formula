# Finding ID:
# Versions:
#   - mount_option_boot.sls
# SRG ID:
# Finding Level:	medium
#
# Rule Summary:
#       The tmux terminal multiplexer is used to implement automatic
#       session locking. It should be started for every interactive
#       login-shell
#
# Identifiers:
#   - CCE-82266-8
#
# References:
#   - CCI-000056
#   - CCI-000058
#   - FMT_SMF_EXT.1
#   - FMT_MOF_EXT.1
#   - FTA_SSL.1
#   - SRG-OS-000031-GPOS-00012
#   - SRG-OS-000028-GPOS-00009
#   - SRG-OS-000030-GPOS-00011
#   - RHEL-08-020041
#   - SV-230349r810020_rule
#
#################################################################
{%- set stig_id = 'configure_bashrc_exec_tmux' %}
{%- set helperLoc = 'ash-linux/el8/RuleById/files' %}
{%- set profileFile ='/etc/profile.d/tmux.sh' %}

# Log a description of what we're setting
script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

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
        # Check if shell is interactive
        if [[ $- == *i* ]] && [[ $( rpm --quiet -q tmux )$? -eq 0 ]]
        then
           parent=$( ps -o ppid= -p $$ )
           name=$( ps -o comm= -p $parent )

           # Check if controlling-process is target-value
           case "$name" in
              sshd|login)
                 exec tmux
                 ;;
           esac
        fi
