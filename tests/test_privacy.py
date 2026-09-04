"""
Unit tests for the Privacy Boundary and Server-Side Validation Layer.
Asserts that raw PII cannot leak through payload validation and sanitization.
"""

import json
import pytest
from backend.privacy.validator import validate_payload, sanitize_payload

def test_privacy_boundary_clean_payload():
    """Clean payload with only semantic representations and placeholders must pass."""
    payload = {
        "page": {"url": "/scholarship.html", "title": "Scholarship Application"},
        "fields": [
            {
                "id": "fullName",
                "type": "text",
                "label": "Full Name",
                "value": "[REDACTED_NAME]",
                "redacted": True
            },
            {
                "id": "email",
                "type": "email",
                "label": "Email Address",
                "value": "[REDACTED_EMAIL]",
                "redacted": True
            },
            {
                "id": "phone",
                "type": "tel",
                "label": "Phone Number",
                "value": "[REDACTED_PHONE]",
                "redacted": True
            },
            {
                "id": "aadhaar",
                "type": "text",
                "label": "Aadhaar Number",
                "value": "[REDACTED_ID]",
                "redacted": True
            },
            {
                "id": "password",
                "type": "password",
                "label": "Password",
                "value": "[REDACTED_PASSWORD]",
                "redacted": True
            }
        ]
    }
    result = validate_payload(payload)
    assert result.is_safe is True
    assert len(result.violations) == 0

def test_privacy_boundary_catches_raw_pii_leak():
    """Unsanitized payload containing raw PII must be detected and flagged."""
    raw_email = "real_user@sensitive.org"
    raw_phone = "+91 9876543210"
    raw_aadhaar = "1234 5678 9012"
    raw_pan = "ABCDE1234F"

    leaky_payload = {
        "fields": [
            {"id": "email", "value": raw_email},
            {"id": "phone", "value": raw_phone},
            {"id": "aadhaar", "value": raw_aadhaar},
            {"id": "pan", "value": raw_pan}
        ]
    }
    
    result = validate_payload(leaky_payload)
    assert result.is_safe is False
    assert result.violation_count >= 4
    
    violation_types = [v.pii_type for v in result.violations]
    assert "email" in violation_types
    assert "phone" in violation_types
    assert "aadhaar" in violation_types
    assert "pan_card" in violation_types

def test_sanitize_payload_redacts_raw_values():
    """Server-side sanitize_payload must replace raw PII with placeholders."""
    raw_email = "victim@example.com"
    raw_phone = "9876543210"
    raw_aadhaar = "9999 8888 7777"

    leaky_payload = {
        "user_email": raw_email,
        "contact_info": {
            "mobile": raw_phone,
            "gov_id": raw_aadhaar
        }
    }

    sanitized = sanitize_payload(leaky_payload)
    serialized = json.dumps(sanitized)

    # STRICT ASSERTIONS: Raw PII must NOT exist in the serialized payload
    assert raw_email not in serialized
    assert raw_phone not in serialized
    assert raw_aadhaar not in serialized

    # Placeholders must be present
    assert "[REDACTED_EMAIL]" in serialized
    assert "[REDACTED_PHONE]" in serialized
    assert "[REDACTED_ID]" in serialized

    # The sanitized output must now pass validation
    validation_after = validate_payload(sanitized)
    assert validation_after.is_safe is True


def test_semantic_fields_use_specific_redaction_placeholders():
    """Semantic field metadata must select name, PAN, and bank placeholders."""
    payload = {
        "fields": [
            {"id": "fullName", "label": "Full Name", "value": "Rahul Sharma"},
            {"id": "panCard", "label": "PAN Card", "value": "ABCDE1234F"},
            {"id": "bankAccount", "label": "Bank Account", "value": "1234567890"},
            {"id": "institution", "label": "Institution Name", "value": "IIT Delhi"},
            {"id": "course", "label": "Course", "value": "B.Tech Computer Science"},
        ]
    }

    result = validate_payload(payload)
    assert result.is_safe is False
    sanitized = sanitize_payload(payload)
    fields = {field["id"]: field["value"] for field in sanitized["fields"]}
    assert fields["fullName"] == "[REDACTED_NAME]"
    assert fields["panCard"] == "[REDACTED_PAN]"
    assert fields["bankAccount"] == "[REDACTED_BANK_ACCOUNT]"
    assert fields["institution"] == "IIT Delhi"
    assert fields["course"] == "B.Tech Computer Science"
    assert validate_payload(sanitized).is_safe is True
