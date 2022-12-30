# Ref Doc:    STIG - RHEL 8 v1r7
# Finding ID: V-230349
# STIG ID:    RHEL-08-020041
# Rule ID:    SV-230349r833388_rule
# SRG ID:     SRG-OS-000028-GPOS-00009
#
# Finding Level: medium
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
#
# NIST SP 800-53 :: AC-11 b
# NIST SP 800-53A :: AC-11.1 (iii)
# NIST SP 800-53 Revision 4 :: AC-11 b
#
#################################################################
{%- set stig_id = 'RHEL-08-020041' %}
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
