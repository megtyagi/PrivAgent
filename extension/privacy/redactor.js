/**
 * PrivAgent - Redactor
 * Replaces detected PII values with safe placeholders.
 * Operates on a COPY of the data — never modifies the actual DOM values.
 */

const Redactor = (() => {
  const PLACEHOLDERS = {
    password: '[REDACTED_PASSWORD]',
    email: '[REDACTED_EMAIL]',
    phone: '[REDACTED_PHONE]',
    aadhaar: '[REDACTED_ID]',
    credit_card: '[REDACTED_CREDIT_CARD]',
    ssn: '[REDACTED_SSN]',
    pan: '[REDACTED_PAN]',
    bank_account: '[REDACTED_BANK_ACCOUNT]',
    name: '[REDACTED_NAME]',
    dob: '[REDACTED_DOB]',
    pii: '[REDACTED_PII]',
  };

  /**
   * Redact a single field value based on its PII type.
   */
  function redactValue(value, piiType) {
    if (!value) return { value: '', redacted: false };
    return {
      value: PLACEHOLDERS[piiType] || PLACEHOLDERS.pii,
      redacted: true,
      originalLength: value.length,
    };
  }

  /**
   * Redact PII patterns from a text string.
   * Returns the sanitized string.
   */
  function redactText(text) {
    if (!text || typeof text !== 'string') return text;

    let result = text;
    const patterns = PIIDetector.PATTERNS;

    // Replace each pattern type
    result = result.replace(patterns.email, PLACEHOLDERS.email);
    result = result.replace(patterns.creditCard, PLACEHOLDERS.credit_card);
    result = result.replace(patterns.aadhaar, PLACEHOLDERS.aadhaar);
    result = result.replace(patterns.phone, PLACEHOLDERS.phone);
    result = result.replace(patterns.ssn, PLACEHOLDERS.ssn);
    result = result.replace(patterns.panCard, PLACEHOLDERS.pan);

    return result;
  }

  /**
   * Check if a string is already a safe placeholder.
   */
  function isPlaceholder(value) {
    return Object.values(PLACEHOLDERS).includes(value);
  }

  return {
    redactValue,
    redactText,
    isPlaceholder,
    PLACEHOLDERS,
  };
})();

if (typeof window !== 'undefined') {
  window.Redactor = Redactor;
}
