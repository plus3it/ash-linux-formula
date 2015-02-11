{% from "ash-linux/fix_perms/0400_mode.jinja" import mode_0400_files with context %}

{% for filename in mode_0400_files %}
  {% if salt['file.file_exists'](filename) %}
{{ filename }}:
  file.managed:
    - mode: 0400
  {% endif %}
{% endfor %}
