# Finding URL:	https://www.tenable.com/plugins/index.php?view=single&id=71049
# Family:	Miscellaneous
# Nessus ID:	71049
# Bugtraq ID:	
# CVE ID:	
# Finding Level:	low
#
#     The SSH daemon must be configured to use only strong MAC
#     algorithms. Configured algorithms should not allow MD5
#     or 96-bit MAC algorithms.
#
############################################################

{%- set stigId = 'Nessus-71049' %}
{%- set helperLoc = 'ash-linux/el6/Nessus/low/files' %}
{%- set cfgFile = '/etc/ssh/sshd_config' %}
{%- set parmName = 'MACs' %}
{%- set parmVal = 'hmac-sha1,umac-64@openssh.com,hmac-ripemd160,hmac-sha2-256,hmac-sha2-512,hmac-ripemd160@openssh.com' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

{%- if salt.file.search(cfgFile, '^' + parmName)
 %}
file_{{ stigId }}-repl:
  file.replace:
    - name: '{{ cfgFile }}'
    - pattern: '^{{ parmName }}.*$'
    - repl: '{{ parmName }} {{parmVal }}'
{%- else %}
file_{{ stigId }}-append:
  file.append:
    - name: '{{ cfgFile }}'
    - text:
      - ' '
      - '# SSH service must allow only FIPS 140-2 ciphers (per {{ stigId }})'
      - '{{ parmName }} {{ parmVal }}'
{%- endif %}

