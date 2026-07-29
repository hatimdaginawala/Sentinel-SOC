/**
 * SentinelSOC Form Helpers
 */
const Forms = {
  /**
   * Bind async submit handler with button spinner management and validation
   * @param {HTMLFormElement} form - The form element
   * @param {object} validationConfig - Field validation requirements
   * @param {function} submitHandler - Async submit handler returning true on success
   */
  bind(form, validationConfig, submitHandler) {
    if (!form) return;

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      
      // Clean up previous general errors
      const errorSummary = form.querySelector('.form-error-summary');
      if (errorSummary) {
        errorSummary.style.display = 'none';
        errorSummary.textContent = '';
      }

      // Validate fields
      if (validationConfig) {
        const { isValid, errors } = Validators.validateForm(form, validationConfig);
        if (!isValid) {
          console.log('Form validation failed:', errors);
          return;
        }
      }

      // Find submit button
      const submitBtn = form.querySelector('[type="submit"]');
      const originalText = submitBtn ? submitBtn.innerHTML : '';

      try {
        if (submitBtn) {
          submitBtn.classList.add('btn-loading');
          submitBtn.disabled = true;
        }

        const success = await submitHandler(new FormData(form));
        if (success) {
          form.reset();
        }
      } catch (err) {
        console.error('Form submission error:', err);
        if (errorSummary) {
          errorSummary.textContent = err.message || 'An unexpected error occurred. Please try again.';
          errorSummary.style.display = 'block';
        } else {
          Swal.fire('Error', err.message || 'Form submission failed', 'error');
        }
      } finally {
        if (submitBtn) {
          submitBtn.classList.remove('btn-loading');
          submitBtn.disabled = false;
        }
      }
    });
  },

  /**
   * Populate form input fields from an object
   */
  populate(form, data) {
    if (!form || !data) return;

    Object.keys(data).forEach(key => {
      const field = form.querySelector(`[name="${key}"]`);
      if (!field) return;

      if (field.type === 'checkbox') {
        field.checked = !!data[key];
      } else {
        field.value = data[key] !== null && data[key] !== undefined ? data[key] : '';
      }
    });
  }
};

window.Forms = Forms;
