{%- if grains['osmajorrelease'] == '7' %}
include:
  - ash-linux.el7
{%- elif grains['osmajorrelease'] == '6' %}
include:
  - ash-linux.stig-el6
  - ash-linux.scap-el6
{%- endif %}
