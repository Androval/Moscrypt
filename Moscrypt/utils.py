import re
import html
from functools import wraps
from flask import request, abort

def sanitize_html(text):
    """Sanitize HTML to prevent XSS attacks"""
    if not text:
        return text
    
    # Convert HTML entities
    text = html.escape(str(text))
    
    return text

def sanitize_filename(filename):
    """Sanitize a filename to prevent path traversal and XSS"""
    if not filename:
        return filename
    
    # Remove any path components
    filename = re.sub(r'[/\\]', '', filename)
    
    # Remove any non-alphanumeric chars except for certain safe ones
    filename = re.sub(r'[^a-zA-Z0-9._-]', '', filename)
    
    # Prevent directory traversal
    filename = filename.lstrip('.')
    
    return filename

def sanitize_form_data(form_data):
    """Sanitize all form data values"""
    if not form_data:
        return {}
    
    sanitized = {}
    for key, value in form_data.items():
        if isinstance(value, list):
            sanitized[key] = [sanitize_html(v) for v in value]
        else:
            sanitized[key] = sanitize_html(value)
    
    return sanitized

def xss_protect(f):
    """Decorator to sanitize all form input"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If this is a POST/PUT/PATCH request, sanitize the form data
        if request.method in ('POST', 'PUT', 'PATCH'):
            request.form = sanitize_form_data(request.form)
        return f(*args, **kwargs)
    return decorated_function 