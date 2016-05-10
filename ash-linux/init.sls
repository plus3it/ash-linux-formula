{%- if grains['osrelease'] == '7' %}
include:
  - ash-linux.el7
{%- elif grains['osrelease'] == '6' %}
include:
  - ash-linux.stig
  - ash-linux.scap
{%- endif %}
