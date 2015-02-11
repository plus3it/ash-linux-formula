{% from "fix_perms/0600_mode.jinja" import mode_0600_files with context %}

{% for filename in mode_0600_files %}
{{ filename }}:
  file.managed:
    - mode: 0600
{% endfor %}
