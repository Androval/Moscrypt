# Moscrypt UI Styling Guide

This document was generated by AI

This document outlines the styling and user interface components available in the Moscrypt application.

## Overview

Moscrypt uses a clean, modern design system with a focus on security and usability. The styling is built with:

- CSS custom properties (variables) for consistent theming
- Responsive design for mobile and desktop
- A clean, minimal aesthetic that emphasizes content
- Security-focused UI elements

## Setup

The styling system consists of:

1. **CSS File**: `static/css/styles.css` 
2. **JavaScript**: `static/js/main.js`
3. **Base Template**: `templates/layout.html`
4. **Font Dependencies**: Google Fonts (Roboto)
5. **Icon Dependencies**: Font Awesome

## Getting Started

To use the styling in your templates:

1. Extend the base layout template:
   ```html
   {% extends 'layout.html' %}
   
   {% block title %}Your Page Title{% endblock %}
   
   {% block content %}
     <!-- Your content here -->
   {% endblock %}
   ```

2. Make sure your static files are properly served:
   - Place CSS files in `/static/css/`
   - Place JS files in `/static/js/`
   - Place images in `/static/images/`

## Color System

The color system uses CSS variables defined in the `:root` selector:

- `--primary`: #1a73e8 (Blue) - Primary actions and emphasis
- `--secondary`: #34a853 (Green) - Secondary actions
- `--danger`: #ea4335 (Red) - Destructive actions and errors
- `--warning`: #fbbc05 (Yellow) - Warnings and cautions
- `--success`: #34a853 (Green) - Success states
- `--light`: #f8f9fa (Light gray) - Background
- `--dark`: #202124 (Dark gray) - Text and headers

## Components

### Cards

Cards are used to group related content:

```html
<div class="card">
  <div class="card-header">Card Title</div>
  <div class="card-body">
    Card content goes here.
  </div>
  <div class="card-footer">
    Footer actions
  </div>
</div>
```

For sessions, use the session-specific card styling:

```html
<div class="card session-card">
  <!-- Session content -->
</div>

<!-- For inactive sessions -->
<div class="card session-card inactive">
  <!-- Inactive session content -->
</div>
```

### Buttons

Several button styles are available:

```html
<button class="btn btn-primary">Primary Action</button>
<button class="btn btn-secondary">Secondary Action</button>
<button class="btn btn-success">Success Action</button>
<button class="btn btn-danger">Dangerous Action</button>
<button class="btn btn-link">Link Button</button>
```

For dangerous actions that require confirmation:

```html
<button class="btn btn-danger" data-confirm="Are you sure you want to delete this?">Delete</button>
```

### Forms

Form elements are styled for consistency:

```html
<div class="form-group">
  <label class="form-label" for="username">Username</label>
  <input type="text" class="form-control" id="username" name="username">
</div>

<div class="form-group">
  <label class="form-label" for="password">Password</label>
  <input type="password" class="form-control" id="password" name="password" data-password-strength>
</div>

<div class="form-group">
  <label class="form-label" for="role">Role</label>
  <select class="form-select" id="role" name="role">
    <option value="user">User</option>
    <option value="admin">Admin</option>
  </select>
</div>
```

For password fields with strength indicators, add the `data-password-strength` attribute.

### Alerts

Flash messages are automatically styled, but you can also create alerts manually:

```html
<div class="alert alert-success">Success message</div>
<div class="alert alert-danger">Error message</div>
<div class="alert alert-warning">Warning message</div>
<div class="alert alert-info">Info message</div>
```

### Tables

Tables are styled for readability:

```html
<table class="table">
  <thead>
    <tr>
      <th>Name</th>
      <th>Email</th>
      <th>Actions</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>John Doe</td>
      <td>john@example.com</td>
      <td>
        <button class="btn btn-primary btn-sm">Edit</button>
        <button class="btn btn-danger btn-sm">Delete</button>
      </td>
    </tr>
  </tbody>
</table>
```

### File Lists

For displaying files in the vault:

```html
<div class="file-item">
  <div class="file-icon">
    <i class="fas fa-file-alt"></i>
  </div>
  <div class="file-name">document.pdf</div>
  <div class="file-actions">
    <a href="#" class="btn btn-primary btn-sm">Download</a>
    <button class="btn btn-danger btn-sm">Delete</button>
  </div>
</div>
```

### Participant Lists

For displaying session participants:

```html
<div class="participant-list">
  <span class="participant-badge">User1 (Creator)</span>
  <span class="participant-badge">User2</span>
  <span class="participant-badge">User3</span>
</div>
```

## JavaScript Features

The included JavaScript provides several features:

### 1. Flash Message Auto-Dismiss

Success messages are automatically dismissed after 5 seconds. All messages have a close button.

### 2. Password Strength Indicator

Password fields with the `data-password-strength` attribute get an automatic strength meter.

### 3. File Upload Validation

File inputs can have size validation with the `data-max-size` attribute (in MB):

```html
<input type="file" data-max-size="5" id="file-upload" name="file">
<div data-file-preview="file-upload"></div>
```

### 4. Copy to Clipboard

Add copy functionality to any element:

```html
<input type="text" id="api-key" value="your-api-key-here" readonly>
<button data-copy-target="api-key">Copy</button>
```

### 5. Confirmation Dialogs

Add confirmation dialogs to dangerous actions:

```html
<button data-confirm="Are you sure? This cannot be undone.">Delete Account</button>
```

## Utility Classes

Several utility classes are available:

- Text alignment: `.text-center`, `.text-right`
- Text colors: `.text-danger`, `.text-success`, `.text-warning`, `.text-muted`
- Flex utilities: `.d-flex`, `.justify-content-between`, `.align-items-center`
- Margin utilities: `.mt-1` through `.mt-4`, `.mb-1` through `.mb-4`
- Auto margins: `.ml-auto`, `.mr-auto`

## Responsive Design

The styling is mobile-friendly and adjusts automatically for smaller screens. The navigation menu collapses on mobile devices, and tables become scrollable.

## Security Features

- CSRF protection is automatically added to AJAX requests
- All form inputs should be properly sanitized serverside
- Dangerous actions require confirmation
- Inactive sessions are visually distinguished

## Adding Custom CSS

To add page-specific CSS, use the `extra_css` block:

```html
{% block extra_css %}
<style>
  /* Your custom CSS here */
</style>
{% endblock %}
```

## Adding Custom JavaScript

To add page-specific JavaScript, use the `extra_js` block:

```html
{% block extra_js %}
<script>
  // Your custom JavaScript here
</script>
{% endblock %}
``` 