{% from "ash-linux/fix_perms/0640_mode.jinja" import mode_0640_files with context %}

{% for filename in mode_0640_files %}
  {% if salt['file.file_exists'](filename) %}
{{ filename }}:
  file.managed:
    - mode: 0640
  {% endif %}
{% endfor %}
