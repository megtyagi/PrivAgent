/**
 * PrivAgent - PII Detector
 * Local regex + DOM-based PII detection. Runs entirely in-browser.
 * NO data leaves the browser from this module.
 */

const PIIDetector = (() => {
  // --- Regex patterns ---
  const PATTERNS = {
    email: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
    phone: /(?:\+?\d{1,3}[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}/g,
    aadhaar: /\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b/g,
    creditCard: /\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b/g,
    ssn: /\b\d{3}[\s\-]\d{2}[\s\-]\d{4}\b/g,
    panCard: /\b[A-Z]{5}\d{4}[A-Z]\b/g,
  };

  // --- Field-type heuristics ---
  const SENSITIVE_TYPES = ['password', 'email', 'tel'];
  const SENSITIVE_NAME_KEYWORDS = [
    'password', 'passwd', 'pwd', 'pass',
    'email', 'e-mail', 'mail',
    'phone', 'tel', 'mobile', 'cell',
    'aadhaar', 'aadhar', 'uid',
    'ssn', 'social',
    'credit', 'card', 'cc', 'cvv', 'cvc',
    'pan', 'passport',
    'dob', 'birth',
    'account', 'routing',
    'secret', 'token', 'api_key', 'apikey',
  ];
  const PERSONAL_NAME_MARKERS = [
    'fullname', 'firstname', 'lastname', 'givenname', 'familyname',
    'surname', 'applicantname', 'studentname',
  ];

  /**
   * Check if a form field is sensitive based on its attributes.
   */
  function isFieldSensitive(element) {
    // Password type is always sensitive
    if (element.type === 'password') return { sensitive: true, type: 'password' };

    const attrs = [
      element.type,
      element.name,
      element.id,
      element.placeholder,
      element.getAttribute('aria-label'),
      element.getAttribute('autocomplete'),
    ].filter(Boolean).map(s => s.toLowerCase());

    // Match explicit personal-name fields without classifying fields such as
    // institutionName or courseName as PII.
    for (const attr of attrs) {
      const normalized = attr.replace(/[\s_-]/g, '');
      if (PERSONAL_NAME_MARKERS.some(marker => normalized.includes(marker))) {
        return { sensitive: true, type: 'name' };
      }
      if (normalized.includes('pan')) {
        return { sensitive: true, type: 'pan' };
      }
      if (normalized.includes('bankaccount') || normalized.includes('routing')) {
        return { sensitive: true, type: 'bank_account' };
      }
    }

    // Check input type
    if (element.type === 'email') return { sensitive: true, type: 'email' };
    if (element.type === 'tel') return { sensitive: true, type: 'phone' };

    // Check attributes against keywords
    for (const attr of attrs) {
      for (const keyword of SENSITIVE_NAME_KEYWORDS) {
        if (attr.includes(keyword)) {
          const piiType = _classifyKeyword(keyword);
          return { sensitive: true, type: piiType };
        }
      }
    }

    // Check associated label
    const label = _getFieldLabel(element);
    if (label) {
      const labelLower = label.toLowerCase();
      for (const keyword of SENSITIVE_NAME_KEYWORDS) {
        if (labelLower.includes(keyword)) {
          return { sensitive: true, type: _classifyKeyword(keyword) };
        }
      }
    }

    return { sensitive: false, type: null };
  }

  /**
   * Scan a string value for PII patterns.
   */
  function scanValue(value) {
    if (!value || typeof value !== 'string') return [];

    const detections = [];
    for (const [type, regex] of Object.entries(PATTERNS)) {
      regex.lastIndex = 0;
      const matches = value.match(regex);
      if (matches) {
        detections.push({
          type,
          count: matches.length,
          // Never include the actual matched value
        });
      }
    }
    return detections;
  }

  /**
   * Scan all form fields on the page.
   */
  function scanPage() {
    const results = {
      totalFields: 0,
      sensitiveFields: 0,
      detections: [],
      timestamp: Date.now(),
    };

    const inputs = document.querySelectorAll('input, textarea, select');
    results.totalFields = inputs.length;

    inputs.forEach((el) => {
      const check = isFieldSensitive(el);
      if (check.sensitive) {
        results.sensitiveFields++;
        results.detections.push({
          fieldId: el.id || el.name || null,
          fieldType: el.type,
          piiType: check.type,
          hasValue: !!el.value,
          // NEVER include el.value here
        });
      }

      // Also scan current value for PII patterns
      if (el.value) {
        const valueDetections = scanValue(el.value);
        if (valueDetections.length > 0) {
          results.detections.push({
            fieldId: el.id || el.name || null,
            fieldType: el.type,
            piiTypes: valueDetections.map(d => d.type),
            hasValue: true,
          });
        }
      }
    });

    return results;
  }

  // --- Helpers ---

  function _classifyKeyword(keyword) {
    if (['password', 'passwd', 'pwd', 'pass', 'secret', 'token', 'api_key', 'apikey'].includes(keyword)) return 'password';
    if (['email', 'e-mail', 'mail'].includes(keyword)) return 'email';
    if (['phone', 'tel', 'mobile', 'cell'].includes(keyword)) return 'phone';
    if (['aadhaar', 'aadhar', 'uid'].includes(keyword)) return 'aadhaar';
    if (['ssn', 'social'].includes(keyword)) return 'ssn';
    if (['credit', 'card', 'cc', 'cvv', 'cvc'].includes(keyword)) return 'credit_card';
    if (['pan', 'passport'].includes(keyword)) return 'pan';
    if (['account', 'routing'].includes(keyword)) return 'bank_account';
    if (['dob', 'birth'].includes(keyword)) return 'dob';
    return 'pii';
  }

  function _getFieldLabel(element) {
    // Try for/id label
    if (element.id) {
      const label = document.querySelector(`label[for="${element.id}"]`);
      if (label) return label.textContent.trim();
    }
    // Try parent label
    const parentLabel = element.closest('label');
    if (parentLabel) return parentLabel.textContent.trim();
    // Try aria-label
    return element.getAttribute('aria-label') || null;
  }

  return {
    isFieldSensitive,
    scanValue,
    scanPage,
    PATTERNS,
  };
})();

// Make available globally for content script
if (typeof window !== 'undefined') {
  window.PIIDetector = PIIDetector;
}
