"""
Django template tags for Vue.js island integration.

Usage in templates:
    {% load vue_tags %}

    <!-- Load Vue island JS/CSS -->
    {% vue_island 'tasks-island' %}

    <!-- Serialize data for Vue props -->
    <div id="tasks-app" data-props='{% vue_props initial_data %}'>
"""

import json
import os
from django import template
from django.conf import settings
from django.utils.safestring import mark_safe

register = template.Library()


def get_vite_manifest():
    """Load and cache the Vite manifest file."""
    manifest_paths = [
        os.path.join(settings.BASE_DIR, 'static', 'vue', '.vite', 'manifest.json'),
        os.path.join(settings.STATIC_ROOT or '', 'vue', '.vite', 'manifest.json'),
    ]

    for manifest_path in manifest_paths:
        if os.path.exists(manifest_path):
            try:
                with open(manifest_path, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
    return None


@register.simple_tag(takes_context=True)
def vue_island(context, island_name):
    """
    Load a Vue island's JS and CSS from Vite manifest or dev server.

    Priority:
    1. If built assets exist (manifest.json), use those
    2. If VITE_DEV_MODE setting is True, use Vite dev server
    3. Otherwise, show error message

    Usage:
        {% vue_island 'tasks-island' %}

    Settings:
        VITE_DEV_MODE = True  # Enable Vite dev server mode
        VITE_DEV_SERVER_URL = 'http://localhost:5173'  # Custom Vite URL
    """
    # Always try built assets first
    manifest = get_vite_manifest()

    if manifest is not None:
        entry_key = f'src/islands/{island_name}.ts'
        if entry_key in manifest:
            entry = manifest[entry_key]
            js_file = entry.get('file', '')
            css_files = entry.get('css', [])

            static_url = getattr(settings, 'STATIC_URL', '/static/')

            tags = []

            # Load CSS files
            for css_file in css_files:
                tags.append(f'<link rel="stylesheet" href="{static_url}vue/{css_file}">')

            # Load JS module
            if js_file:
                tags.append(f'<script type="module" src="{static_url}vue/{js_file}"></script>')

            return mark_safe('\n'.join(tags))

    # No built assets - check if Vite dev mode is enabled
    vite_dev_mode = getattr(settings, 'VITE_DEV_MODE', False)

    if vite_dev_mode:
        # Get Vite dev server URL from settings or derive from request
        vite_url = getattr(settings, 'VITE_DEV_SERVER_URL', None)

        if not vite_url:
            # Try to use the same host as the request
            request = context.get('request')
            if request:
                host = request.get_host().split(':')[0]  # Get hostname without port
                vite_url = f'http://{host}:5173'
            else:
                vite_url = 'http://localhost:5173'

        return mark_safe(f'''
            <script type="module" src="{vite_url}/src/islands/{island_name}.ts"></script>
        ''')

    # No assets and dev mode not enabled
    return mark_safe(f'''
        <!-- Vue island "{island_name}" not found.
             Either run "cd frontend && npm run build" to build assets,
             or set VITE_DEV_MODE=True in settings and run "cd frontend && npm run dev" -->
    ''')


@register.simple_tag
def vue_props(data):
    """
    Serialize Python data to JSON for passing to Vue components via data attributes.

    Usage:
        <div id="app" data-props='{% vue_props context_data %}'></div>

    Note: Uses single quotes around the template tag since JSON uses double quotes.
    """
    try:
        json_str = json.dumps(data, default=str)
        # Escape for HTML attribute (replace special characters)
        json_str = json_str.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        return mark_safe(json_str)
    except (TypeError, ValueError) as e:
        return mark_safe('{}')


@register.simple_tag(takes_context=True)
def vue_mount_point(context, island_name, element_id=None):
    """
    Create a complete Vue mount point with common data attributes.

    Usage:
        {% vue_mount_point 'tasks-island' %}
        {% vue_mount_point 'tasks-island' 'custom-id' %}
    """
    request = context.get('request')

    if element_id is None:
        element_id = f'{island_name.replace("-island", "")}-app'

    # Build common props
    common_props = {}

    if request:
        # Add user info
        if request.user.is_authenticated:
            common_props['user'] = {
                'id': request.user.id,
                'username': request.user.username,
                'is_superuser': request.user.is_superuser,
                'is_staff': request.user.is_staff,
            }
            # Add permissions
            common_props['permissions'] = {
                'can_poll_accounts': (
                    request.user.has_perm('resources.can_poll_accounts') or
                    request.user.is_superuser
                ),
            }

    props_json = json.dumps(common_props, default=str)

    # Get CSRF token
    csrf_token = ''
    if hasattr(context, 'request') and hasattr(context['request'], 'META'):
        csrf_token = context['request'].META.get('CSRF_COOKIE', '')

    return mark_safe(f'''
        <div id="{element_id}"
             data-props='{props_json}'
             data-csrf-token="{csrf_token}">
            <div class="flex justify-center items-center py-12">
                <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-aws-orange"></div>
                <span class="ml-3 text-gray-600">Loading...</span>
            </div>
        </div>
    ''')


@register.inclusion_tag('resources/partials/vue_island_loader.html', takes_context=True)
def vue_island_full(context, island_name, initial_data=None):
    """
    Full Vue island loader with mount point and script loading.

    Usage:
        {% vue_island_full 'tasks-island' initial_data %}
    """
    request = context.get('request')
    element_id = f'{island_name.replace("-island", "")}-app'

    props = initial_data or {}

    # Add user permissions
    if request and request.user.is_authenticated:
        props['_user'] = {
            'id': request.user.id,
            'username': request.user.username,
            'is_superuser': request.user.is_superuser,
            'can_poll_accounts': (
                request.user.has_perm('resources.can_poll_accounts') or
                request.user.is_superuser
            ),
        }

    return {
        'island_name': island_name,
        'element_id': element_id,
        'props': props,
        'csrf_token': context.get('csrf_token', ''),
        'DEBUG': settings.DEBUG,
    }
