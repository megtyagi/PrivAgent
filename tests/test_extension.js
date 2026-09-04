/**
 * JavaScript & DOM Privacy Verification Test Suite
 * Tests extension modules in simulated browser / DOM sandbox.
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const assert = require('assert');

console.log('=== Running PrivAgent JavaScript Verification Suite ===\n');

// Setup mock browser window/document sandbox
function createSandbox() {
  const sandbox = {
    console: console,
    performance: { now: () => Date.now() },
    setTimeout: setTimeout,
    clearTimeout: clearTimeout,
    Promise: Promise,
    Float32Array: Float32Array,
    Uint8Array: Uint8Array,
    Array: Array,
    Object: Object,
    JSON: JSON,
    RegExp: RegExp,
    String: String,
    Number: Number,
    Math: Math,
    Event: function(type) { this.type = type; },
    CSS: {
      escape: (s) => s.replace(/[!"#$%&'()*+,.\/:;<=>?@[\\\]^`{|}~]/g, '\\$&')
    },
    navigator: {
      gpu: undefined // WebGPU not available in bare node
    },
    location: {
      pathname: '/scholarship.html',
      hostname: 'localhost',
      href: 'http://localhost:8000/scholarship.html'
    },
    document: {
      title: 'Scholarship Application',
      querySelectorAll: (sel) => {
        if (sel.includes('input, textarea, select')) {
          return sandbox._mockInputs || [];
        }
        if (sel.includes('button, input[type="submit"]')) {
          return sandbox._mockButtons || [];
        }
        if (sel.includes('img')) {
          return sandbox._mockImages || [];
        }
        if (sel.includes('a[href]')) {
          return sandbox._mockLinks || [];
        }
        return [];
      },
      querySelector: (sel) => {
        const all = [
          ...(sandbox._mockInputs || []),
          ...(sandbox._mockButtons || []),
          ...(sandbox._mockImages || []),
          ...(sandbox._mockLinks || [])
        ];
        if (sel.startsWith('#')) {
          const id = sel.substring(1);
          return all.find(el => el.id === id) || null;
        }
        if (sel.includes('[name=')) {
          const match = sel.match(/\[name="?([^"\]]+)"?\]/);
          if (match) return all.find(el => el.name === match[1]) || null;
        }
        if (sel.includes('label[for=')) {
          const match = sel.match(/\[for="?([^"\]]+)"?\]/);
          if (match && sandbox._mockLabels) {
            return sandbox._mockLabels[match[1]] || null;
          }
        }
        return null;
      },
      getElementById: (id) => {
        const all = [
          ...(sandbox._mockInputs || []),
          ...(sandbox._mockButtons || []),
          ...(sandbox._mockImages || [])
        ];
        return all.find(el => el.id === id) || null;
      },
      createElement: (tag) => {
        return {
          tagName: tag.toUpperCase(),
          getContext: () => ({
            drawImage: () => {},
            getImageData: () => ({ data: new Uint8Array(320 * 320 * 4), width: 320, height: 320 })
          }),
          remove: () => {}
        };
      }
    }
  };

  sandbox.window = sandbox;
  sandbox.global = sandbox;
  sandbox.globalThis = sandbox;
  sandbox.window.HTMLInputElement = { prototype: { value: '' } };
  sandbox.window.HTMLTextAreaElement = { prototype: { value: '' } };
  sandbox.window.getComputedStyle = () => ({ display: 'block', visibility: 'visible' });
  sandbox.window.scrollBy = (opts) => { sandbox._lastScroll = opts; };

  return sandbox;
}

const sandbox = createSandbox();
const context = vm.createContext(sandbox);

function loadScript(relPath) {
  const code = fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');
  vm.runInContext(code, context);
}

// Load extension scripts in order
loadScript('extension/privacy/pii-detector.js');
loadScript('extension/privacy/redactor.js');
loadScript('extension/privacy/sanitizer.js');
loadScript('extension/privacy/face-detector.js');
loadScript('extension/ai/local-model.js');
loadScript('extension/ai/inference.js');
loadScript('extension/actions/executor.js');

let passedCount = 0;
let totalCount = 0;

function it(desc, fn) {
  totalCount++;
  try {
    fn();
    console.log(`  ✓ ${desc}`);
    passedCount++;
  } catch (err) {
    console.error(`  ✗ ${desc}`);
    console.error(`    ${err.message}`);
    process.exitCode = 1;
  }
}

async function itAsync(desc, fn) {
  totalCount++;
  try {
    await fn();
    console.log(`  ✓ ${desc}`);
    passedCount++;
  } catch (err) {
    console.error(`  ✗ ${desc}`);
    console.error(`    ${err.message}`);
    process.exitCode = 1;
  }
}

(async () => {
  console.log('1. PII Detector Module:');
  it('detects email in raw text', () => {
    const res = sandbox.window.PIIDetector.scanValue('Contact rahul@example.com for help');
    assert.strictEqual(res.length, 1);
    assert.strictEqual(res[0].type, 'email');
  });

  it('detects phone in raw text', () => {
    const res = sandbox.window.PIIDetector.scanValue('Call +91 9876543210 today');
    assert.strictEqual(res.length, 1);
    assert.strictEqual(res[0].type, 'phone');
  });

  it('detects Aadhaar in raw text', () => {
    const res = sandbox.window.PIIDetector.scanValue('Aadhaar: 1234 5678 9012');
    assert.strictEqual(res.length, 1);
    assert.strictEqual(res[0].type, 'aadhaar');
  });

  it('detects PAN Card in raw text', () => {
    const res = sandbox.window.PIIDetector.scanValue('PAN is ABCDE1234F');
    assert.strictEqual(res.length, 1);
    assert.strictEqual(res[0].type, 'panCard');
  });

  it('flags sensitive input elements by type', () => {
    const mockEl = {
      type: 'password',
      id: 'pwd',
      name: 'user_password',
      getAttribute: () => null,
      closest: () => null
    };
    const res = sandbox.window.PIIDetector.isFieldSensitive(mockEl);
    assert.strictEqual(res.sensitive, true);
    assert.strictEqual(res.type, 'password');
  });

  it('classifies personal names and bank accounts without classifying legitimate fields', () => {
    const nameField = {
      type: 'text',
      id: 'fullName',
      name: 'fullName',
      getAttribute: () => null,
      closest: () => null
    };
    const bankField = {
      type: 'text',
      id: 'bankAccount',
      name: 'bankAccount',
      getAttribute: () => null,
      closest: () => null
    };
    const institutionField = {
      type: 'text',
      id: 'institution',
      name: 'institution',
      getAttribute: () => null,
      closest: () => null
    };

    const nameResult = sandbox.window.PIIDetector.isFieldSensitive(nameField);
    const bankResult = sandbox.window.PIIDetector.isFieldSensitive(bankField);
    const institutionResult = sandbox.window.PIIDetector.isFieldSensitive(institutionField);
    assert.strictEqual(nameResult.sensitive, true);
    assert.strictEqual(nameResult.type, 'name');
    assert.strictEqual(bankResult.sensitive, true);
    assert.strictEqual(bankResult.type, 'bank_account');
    assert.strictEqual(institutionResult.sensitive, false);
    assert.strictEqual(institutionResult.type, null);
  });

  console.log('\n2. Redactor Module:');
  it('replaces values with semantic placeholders', () => {
    const emailRedacted = sandbox.window.Redactor.redactValue('secret@org.com', 'email');
    assert.strictEqual(emailRedacted.value, '[REDACTED_EMAIL]');
    assert.strictEqual(emailRedacted.redacted, true);

    const passRedacted = sandbox.window.Redactor.redactValue('Secret123!', 'password');
    assert.strictEqual(passRedacted.value, '[REDACTED_PASSWORD]');
  });

  it('redacts text containing multiple PII entries', () => {
    const raw = 'Email rahul@test.com or phone 9876543210';
    const clean = sandbox.window.Redactor.redactText(raw);
    assert(!clean.includes('rahul@test.com'));
    assert(!clean.includes('9876543210'));
    assert(clean.includes('[REDACTED_EMAIL]'));
    assert(clean.includes('[REDACTED_PHONE]'));
  });

  console.log('\n3. Sanitizer & Privacy Boundary:');
  it('extracts and sanitizes simulated form inputs without leaking raw values', () => {
    // Setup synthetic scholarship form
    sandbox._mockInputs = [
      {
        tagName: 'INPUT',
        type: 'text',
        id: 'fullName',
        name: 'fullName',
        value: 'Rahul Sharma',
        placeholder: 'Enter full name',
        getAttribute: (attr) => attr === 'aria-label' ? 'Full Name' : null,
        closest: () => null,
        offsetParent: {}
      },
      {
        tagName: 'INPUT',
        type: 'text',
        id: 'panCard',
        name: 'panCard',
        value: 'ABCDE1234F',
        placeholder: 'PAN Card',
        getAttribute: () => null,
        closest: () => null,
        offsetParent: {}
      },
      {
        tagName: 'INPUT',
        type: 'text',
        id: 'bankAccount',
        name: 'bankAccount',
        value: '1234567890',
        placeholder: 'Bank Account Number',
        getAttribute: () => null,
        closest: () => null,
        offsetParent: {}
      },
      {
        tagName: 'INPUT',
        type: 'text',
        id: 'institution',
        name: 'institution',
        value: 'IIT Delhi',
        placeholder: 'Institution Name',
        getAttribute: () => null,
        closest: () => null,
        offsetParent: {}
      },
      {
        tagName: 'INPUT',
        type: 'email',
        id: 'email',
        name: 'email',
        value: 'rahul.sharma@gmail.com',
        placeholder: 'Enter email',
        getAttribute: () => null,
        closest: () => null,
        offsetParent: {}
      },
      {
        tagName: 'INPUT',
        type: 'tel',
        id: 'phone',
        name: 'phone',
        value: '+91 9876543210',
        placeholder: 'Phone',
        getAttribute: () => null,
        closest: () => null,
        offsetParent: {}
      },
      {
        tagName: 'INPUT',
        type: 'text',
        id: 'aadhaar',
        name: 'aadhaar',
        value: '1234 5678 9012',
        placeholder: 'Aadhaar',
        getAttribute: () => null,
        closest: () => null,
        offsetParent: {}
      },
      {
        tagName: 'INPUT',
        type: 'password',
        id: 'password',
        name: 'password',
        value: 'SuperSecret123!',
        placeholder: 'Password',
        getAttribute: () => null,
        closest: () => null,
        offsetParent: {}
      }
    ];

    sandbox._mockButtons = [
      {
        tagName: 'BUTTON',
        type: 'submit',
        id: 'submitApplication',
        textContent: 'Submit Application',
        getAttribute: () => null,
        offsetParent: {}
      }
    ];

    const payload = sandbox.window.Sanitizer.buildSanitizedPayload();
    const serialized = JSON.stringify(payload);

    // Strict assertions: Raw PII must NEVER exist in the serialized network payload
    assert(!serialized.includes('rahul.sharma@gmail.com'), 'Raw email must not be in payload');
    assert(!serialized.includes('9876543210'), 'Raw phone must not be in payload');
    assert(!serialized.includes('1234 5678 9012'), 'Raw Aadhaar must not be in payload');
    assert(!serialized.includes('SuperSecret123!'), 'Raw password must not be in payload');
    assert(!serialized.includes('Rahul Sharma'), 'Raw name must not be in payload');
    assert(!serialized.includes('ABCDE1234F'), 'Raw PAN must not be in payload');
    assert(!serialized.includes('1234567890'), 'Raw bank account must not be in payload');
    assert(serialized.includes('IIT Delhi'), 'Institution name should remain in payload');

    // Placeholders must be present
    assert(serialized.includes('[REDACTED_EMAIL]'), 'Email placeholder missing');
    assert(serialized.includes('[REDACTED_PHONE]'), 'Phone placeholder missing');
    assert(serialized.includes('[REDACTED_ID]'), 'Aadhaar placeholder missing');
    assert(serialized.includes('[REDACTED_PASSWORD]'), 'Password placeholder missing');
    assert(serialized.includes('[REDACTED_NAME]'), 'Name placeholder missing');
    assert(serialized.includes('[REDACTED_PAN]'), 'PAN placeholder missing');
    assert(serialized.includes('[REDACTED_BANK_ACCOUNT]'), 'Bank account placeholder missing');

    assert.strictEqual(payload.privacy_summary.redacted_count, 7);
  });

  console.log('\n4. Action Executor & Security:');
  it('executes click action on valid button target', () => {
    let clicked = false;
    let focused = false;
    sandbox._mockButtons = [
      {
        tagName: 'BUTTON',
        id: 'submitApplication',
        focus: () => { focused = true; },
        click: () => { clicked = true; },
        textContent: 'Submit Application',
        getAttribute: () => null
      }
    ];

    const result = sandbox.window.ActionExecutor.execute({
      action: 'click',
      target: 'submitApplication'
    });

    assert.strictEqual(result.success, true);
    assert.strictEqual(clicked, true);
    assert.strictEqual(focused, true);
  });

  it('executes fill action on valid input target', () => {
    let dispatched = [];
    const targetInput = {
      tagName: 'INPUT',
      id: 'fullName',
      type: 'text',
      value: '',
      dispatchEvent: (evt) => { dispatched.push(evt.type); },
      getAttribute: () => null
    };
    sandbox._mockInputs = [targetInput];

    const result = sandbox.window.ActionExecutor.execute({
      action: 'fill',
      target: 'fullName',
      value: 'Rahul Sharma'
    });

    assert.strictEqual(result.success, true);
    assert.strictEqual(targetInput.value, 'Rahul Sharma');
    assert(dispatched.includes('input'));
    assert(dispatched.includes('change'));
  });

  it('executes scroll action safely', () => {
    const result = sandbox.window.ActionExecutor.execute({
      action: 'scroll',
      direction: 'down'
    });

    assert.strictEqual(result.success, true);
    assert.strictEqual(result.action, 'scroll');
    assert.strictEqual(result.direction, 'down');
  });

  it('blocks dangerous injection payloads and unapproved actions', () => {
    const dangerous = [
      { action: 'fill', target: 'input', value: 'javascript:alert(1)' },
      { action: 'fill', target: 'input', value: 'eval(document.cookie)' },
      { action: 'fill', target: 'input', value: '<script>fetch("bad.com")</script>' },
      { action: 'exec_js', target: 'window', value: 'alert(1)' }
    ];

    dangerous.forEach((action) => {
      const res = sandbox.window.ActionExecutor.execute(action);
      assert.strictEqual(res.success, false, `Dangerous action should be blocked: ${JSON.stringify(action)}`);
    });
  });

  console.log('\n5. Local Vision & Face Detection Abstractions:');
  await itAsync('initializes LocalVisionProcessor and feature detects WebGPU/WASM', async () => {
    const res = await sandbox.window.LocalVisionProcessor.initialize();
    assert.strictEqual(res.backend, 'wasm', 'Should fallback to WASM when WebGPU absent');
    assert.strictEqual(res.capabilities.wasm, true);
  });

  await itAsync('runs FaceDetector heuristic fallback without uploading images', async () => {
    sandbox._mockImages = [
      {
        alt: 'User profile avatar photo',
        title: '',
        className: 'avatar-placeholder',
        id: 'profilePhoto',
        getAttribute: () => 'Profile photo'
      }
    ];

    const res = await sandbox.window.FaceDetector.detect(null);
    assert.strictEqual(res.detected, true);
    assert.strictEqual(res.method, 'heuristic');
  });

  console.log(`\n==================================================`);
  console.log(`JavaScript Suite Results: ${passedCount}/${totalCount} tests passed`);
  console.log(`==================================================\n`);
})();
