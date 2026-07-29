/**
 * SentinelSOC Form Validators
 */
const Validators = {
  email(value) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(value) ? null : 'Please enter a valid email address';
  },

  username(value) {
    if (!value || value.length < 3 || value.length > 30) {
      return 'Username must be between 3 and 30 characters';
    }
    const re = /^[a-zA-Z0-9_]+$/;
    return re.test(value) ? null : 'Username can only contain letters, numbers, and underscores';
  },

  password(value) {
    if (!value || value.length < 8) {
      return 'Password must be at least 8 characters long';
    }
    if (!/[A-Z]/.test(value)) {
      return 'Password must contain at least one uppercase letter';
    }
    if (!/[a-z]/.test(value)) {
      return 'Password must contain at least one lowercase letter';
    }
    if (!/[0-9]/.test(value)) {
      return 'Password must contain at least one number';
    }
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>/?]/.test(value)) {
      return 'Password must contain at least one special character';
    }
    return null;
  },

  required(value, name = 'This field') {
    return value && value.trim() !== '' ? null : `${name} is required`;
  },

  validateForm(formElement, validationConfig) {
    let isValid = true;
    const errors = {};

    Object.keys(validationConfig).forEach(fieldName => {
      const input = formElement.querySelector(`[name="${fieldName}"]`);
      if (!input) return;

      const value = input.value;
      const rules = validationConfig[fieldName];
      let fieldError = null;

      for (let rule of rules) {
        if (rule === 'required') {
          fieldError = this.required(value, input.placeholder || fieldName);
        } else if (typeof this[rule] === 'function') {
          fieldError = this[rule](value);
        }
        if (fieldError) break;
      }

      const group = input.closest('.form-group');
      if (group) {
        const errorLabel = group.querySelector('.form-error');
        if (fieldError) {
          group.classList.add('has-error');
          if (errorLabel) {
            errorLabel.textContent = fieldError;
            errorLabel.style.display = 'block';
          }
          errors[fieldName] = fieldError;
          isValid = false;
        } else {
          group.classList.remove('has-error');
          if (errorLabel) {
            errorLabel.style.display = 'none';
          }
        }
      }
    });

    return { isValid, errors };
  }
};

window.Validators = Validators;
