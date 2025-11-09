import json
from django import template

register = template.Library()

@register.filter(name='to_json')
def to_json(value):
    """Convert a Python object to JSON string"""
    return json.dumps(value)
