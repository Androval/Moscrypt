/**
 * Moscrypt - Main JavaScript File
 * Enhances the user experience with interactive elements
 */

document.addEventListener('DOMContentLoaded', function() {
    // Flash message auto-dismiss
    const flashMessages = document.querySelectorAll('.alert');
    if (flashMessages.length > 0) {
        flashMessages.forEach(message => {
            // Auto-dismiss success messages after 5 seconds
            if (message.classList.contains('alert-success')) {
                setTimeout(() => {
                    message.style.opacity = '0';
                    setTimeout(() => message.remove(), 500);
                }, 5000);
            }
            
            // Add close button to all messages
            const closeButton = document.createElement('button');
            closeButton.className = 'close';
            closeButton.innerHTML = '&times;';
            closeButton.style.float = 'right';
            closeButton.style.fontSize = '1.25rem';
            closeButton.style.fontWeight = '700';
            closeButton.style.lineHeight = '1';
            closeButton.style.color = 'inherit';
            closeButton.style.opacity = '0.5';
            closeButton.style.background = 'none';
            closeButton.style.border = '0';
            closeButton.style.padding = '0.25rem 0.5rem';
            closeButton.style.marginRight = '-0.5rem';
            closeButton.style.marginTop = '-0.25rem';
            
            closeButton.addEventListener('click', function() {
                message.style.opacity = '0';
                setTimeout(() => message.remove(), 500);
            });
            
            message.insertBefore(closeButton, message.firstChild);
        });
    }
    
    // Password strength indicator
    const passwordFields = document.querySelectorAll('input[type="password"][data-password-strength]');
    passwordFields.forEach(field => {
        const strengthMeter = document.createElement('div');
        strengthMeter.className = 'password-strength-meter';
        strengthMeter.style.height = '4px';
        strengthMeter.style.backgroundColor = '#eee';
        strengthMeter.style.marginTop = '5px';
        strengthMeter.style.borderRadius = '2px';
        
        const strengthBar = document.createElement('div');
        strengthBar.className = 'password-strength-bar';
        strengthBar.style.height = '100%';
        strengthBar.style.width = '0%';
        strengthBar.style.backgroundColor = '#fbbc05';
        strengthBar.style.borderRadius = '2px';
        strengthBar.style.transition = 'width 0.3s, background-color 0.3s';
        
        strengthMeter.appendChild(strengthBar);
        
        const strengthText = document.createElement('small');
        strengthText.className = 'password-strength-text';
        strengthText.style.fontSize = '0.75rem';
        strengthText.style.marginTop = '3px';
        strengthText.style.display = 'block';
        
        field.parentNode.insertBefore(strengthMeter, field.nextSibling);
        field.parentNode.insertBefore(strengthText, strengthMeter.nextSibling);
        
        field.addEventListener('input', function() {
            const password = this.value;
            let score = 0;
            
            // Length check
            if (password.length >= 8) score += 20;
            
            // Complexity checks
            if (/[A-Z]/.test(password)) score += 20; // Uppercase
            if (/[a-z]/.test(password)) score += 20; // Lowercase
            if (/[0-9]/.test(password)) score += 20; // Numbers
            if (/[^A-Za-z0-9]/.test(password)) score += 20; // Special chars
            
            // Update strength bar
            strengthBar.style.width = score + '%';
            
            // Update color based on score
            if (score < 40) {
                strengthBar.style.backgroundColor = '#ea4335'; // Red
                strengthText.innerText = 'Weak';
                strengthText.style.color = '#ea4335';
            } else if (score < 80) {
                strengthBar.style.backgroundColor = '#fbbc05'; // Yellow
                strengthText.innerText = 'Moderate';
                strengthText.style.color = '#fbbc05';
            } else {
                strengthBar.style.backgroundColor = '#34a853'; // Green
                strengthText.innerText = 'Strong';
                strengthText.style.color = '#34a853';
            }
            
            if (password.length === 0) {
                strengthBar.style.width = '0%';
                strengthText.innerText = '';
            }
        });
    });
    
    // File upload preview and validation
    const fileInputs = document.querySelectorAll('input[type="file"]');
    fileInputs.forEach(input => {
        const maxSize = input.getAttribute('data-max-size') || 10; // Default 10MB
        
        input.addEventListener('change', function() {
            const file = this.files[0];
            if (!file) return;
            
            // Check file size
            const fileSizeMB = file.size / 1024 / 1024;
            if (fileSizeMB > maxSize) {
                alert(`File size exceeds the maximum limit of ${maxSize}MB.`);
                this.value = ''; // Clear the input
                return;
            }
            
            // Show file name in a preview element if one exists
            const previewElement = document.querySelector('[data-file-preview="' + this.id + '"]');
            if (previewElement) {
                previewElement.textContent = file.name;
            }
        });
    });
    
    // Copy to clipboard functionality
    const copyButtons = document.querySelectorAll('[data-copy-target]');
    copyButtons.forEach(button => {
        button.addEventListener('click', function() {
            const targetId = this.getAttribute('data-copy-target');
            const targetElement = document.getElementById(targetId);
            
            if (!targetElement) return;
            
            const textToCopy = targetElement.value || targetElement.textContent;
            
            // Create temporary textarea to copy from
            const textarea = document.createElement('textarea');
            textarea.value = textToCopy;
            textarea.setAttribute('readonly', '');
            textarea.style.position = 'absolute';
            textarea.style.left = '-9999px';
            document.body.appendChild(textarea);
            
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
            
            // Show success feedback
            const originalText = this.textContent;
            this.textContent = 'Copied!';
            setTimeout(() => {
                this.textContent = originalText;
            }, 2000);
        });
    });

    // Add confirm dialogs to dangerous actions
    const dangerButtons = document.querySelectorAll('[data-confirm]');
    dangerButtons.forEach(button => {
        button.addEventListener('click', function(event) {
            const message = this.getAttribute('data-confirm');
            if (!confirm(message)) {
                event.preventDefault();
            }
        });
    });
}); 