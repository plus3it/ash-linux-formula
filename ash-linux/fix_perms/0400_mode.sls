{% from "fix_perms/0400_mode.jinja" import mode_0400_files with context %}

{% for filename in mode_0400_files %}
{{ filename }}:
   file.managed:
     - mode: 0400
{% endfor %}
