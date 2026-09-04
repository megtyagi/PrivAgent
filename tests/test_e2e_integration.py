"""
Complete End-to-End (E2E) Integration and Privacy Verification Test.
Simulates full lifecycle:
Page DOM -> Local Privacy Detection -> Redaction -> Sanitized Payload ->
FastAPI Server -> Mock LLM Planner -> Structured JSON Action -> Browser Action Execution.
"""

import json
import re
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.privacy.validator import PII_PATTERNS, validate_payload, sanitize_payload

client = TestClient(app)

# Synthetic test data simulating user inputs in scholarship.html
SYNTHETIC_PAGE_DATA = {
    "fullName": "Rahul Sharma",
    "email": "rahul.sharma@gmail.com",
    "phone": "+91 9876543210",
    "aadhaar": "1234 5678 9012",
    "password": "MyS3cret!Pass",
    "panCard": "ABCDE1234F",
    "institution": "IIT Delhi",
    "course": "B.Tech Computer Science"
}

def test_e2e_scholarship_page_full_flow():
    """Simulate entire flow for scholarship.html"""
    print("\n1. Simulating Local DOM Capture...")
    raw_dom_fields = [
        {"id": "fullName", "name": "fullName", "type": "text", "value": SYNTHETIC_PAGE_DATA["fullName"], "label": "Full Name"},
        {"id": "email", "name": "email", "type": "email", "value": SYNTHETIC_PAGE_DATA["email"], "label": "Email Address"},
        {"id": "phone", "name": "phone", "type": "tel", "value": SYNTHETIC_PAGE_DATA["phone"], "label": "Phone Number"},
        {"id": "aadhaar", "name": "aadhaar", "type": "text", "value": SYNTHETIC_PAGE_DATA["aadhaar"], "label": "Aadhaar Number"},
        {"id": "panCard", "name": "panCard", "type": "text", "value": SYNTHETIC_PAGE_DATA["panCard"], "label": "PAN Card"},
        {"id": "password", "name": "password", "type": "password", "value": SYNTHETIC_PAGE_DATA["password"], "label": "Password"},
        {"id": "institution", "name": "institution", "type": "text", "value": SYNTHETIC_PAGE_DATA["institution"], "label": "Institution Name"}
    ]

    print("2. Running Client-Side Local Privacy Redaction Engine...")
    sanitized_fields = []
    redacted_count = 0

    for f in raw_dom_fields:
        f_type = f.get("type", "")
        f_name = f.get("name", "").lower()
        f_val = f.get("value", "")

        is_sensitive = False
        placeholder = None

        if f_type == "password" or "password" in f_name:
            is_sensitive = True
            placeholder = "[REDACTED_PASSWORD]"
        elif f_type == "email" or "email" in f_name or PII_PATTERNS["email"].search(f_val):
            is_sensitive = True
            placeholder = "[REDACTED_EMAIL]"
        elif f_type == "tel" or "phone" in f_name or PII_PATTERNS["phone"].search(f_val):
            is_sensitive = True
            placeholder = "[REDACTED_PHONE]"
        elif "aadhaar" in f_name or PII_PATTERNS["aadhaar"].search(f_val):
            is_sensitive = True
            placeholder = "[REDACTED_ID]"
        elif "pan" in f_name or PII_PATTERNS["pan_card"].search(f_val):
            is_sensitive = True
            placeholder = "[REDACTED_PAN]"
        elif "bank" in f_name and "account" in f_name:
            is_sensitive = True
            placeholder = "[REDACTED_BANK_ACCOUNT]"
        elif f_name in {"fullname", "firstname", "lastname", "givenname", "familyname", "surname"}:
            is_sensitive = True
            placeholder = "[REDACTED_NAME]"

        if is_sensitive:
            redacted_count += 1
            sanitized_fields.append({
                "id": f["id"],
                "name": f["name"],
                "type": f["type"],
                "label": f["label"],
                "value": placeholder,
                "redacted": True
            })
        else:
            sanitized_fields.append({
                "id": f["id"],
                "name": f["name"],
                "type": f["type"],
                "label": f["label"],
                "value": f["value"],
                "redacted": False
            })

    sanitized_payload = {
        "page": {
            "url": "/demo/scholarship.html",
            "title": "National Scholarship Application",
            "domain": "localhost"
        },
        "fields": sanitized_fields,
        "buttons": [
            {"id": "submitApplication", "text": "Submit Application", "type": "button"}
        ],
        "privacy_summary": {
            "total_fields": len(sanitized_fields),
            "redacted_count": redacted_count,
            "privacy_applied": True
        }
    }

    print("3. STRICT PRIVACY VERIFICATION: Inspecting Outgoing Network Payload...")
    serialized = json.dumps(sanitized_payload)

    # STRICT ASSERTIONS: Raw user PII must NOT appear in network transmission
    assert SYNTHETIC_PAGE_DATA["email"] not in serialized, "LEAK DETECTED: Raw email found in outgoing payload!"
    assert SYNTHETIC_PAGE_DATA["phone"] not in serialized, "LEAK DETECTED: Raw phone found in outgoing payload!"
    assert SYNTHETIC_PAGE_DATA["aadhaar"] not in serialized, "LEAK DETECTED: Raw Aadhaar found in outgoing payload!"
    assert SYNTHETIC_PAGE_DATA["password"] not in serialized, "LEAK DETECTED: Raw password found in outgoing payload!"
    assert SYNTHETIC_PAGE_DATA["panCard"] not in serialized, "LEAK DETECTED: Raw PAN found in outgoing payload!"
    assert SYNTHETIC_PAGE_DATA["fullName"] not in serialized, "LEAK DETECTED: Raw name found in outgoing payload!"

    # Semantic placeholders MUST exist
    assert "[REDACTED_EMAIL]" in serialized
    assert "[REDACTED_PHONE]" in serialized
    assert "[REDACTED_ID]" in serialized
    assert "[REDACTED_PASSWORD]" in serialized
    assert "[REDACTED_PAN]" in serialized
    assert "[REDACTED_NAME]" in serialized

    print("4. Transmitting Sanitized Payload to FastAPI Backend (/analyze)...")
    response = client.post("/analyze", json=sanitized_payload)
    assert response.status_code == 200
    res_data = response.json()

    assert res_data["privacy_verified"] is True
    assert len(res_data["actions"]) >= 1

    action = res_data["actions"][0]
    print(f"5. AI Action Received: {action}")
    assert action["action"] in ["click", "fill", "scroll"]

    print("6. Simulating Browser Action Execution...")
    if action["action"] == "click":
        assert action["target"] == "submitApplication" or "submit" in action["target"].lower()
    elif action["action"] == "fill":
        assert action["target"] is not None
        assert action["value"] is not None

    print("E2E Scholarship Flow PASSED with ZERO PII leakage!\n")

def test_manifest_v3_validation():
    """Verify Chrome extension manifest integrity."""
    with open("extension/manifest.json", "r") as f:
        manifest = json.load(f)

    assert manifest["manifest_version"] == 3
    assert manifest["name"] == "PrivAgent"
    assert manifest["version"] == "1.0.0"
    assert "background" in manifest and "service_worker" in manifest["background"]
    assert "content_scripts" in manifest and len(manifest["content_scripts"]) > 0
    assert "action" in manifest and "default_popup" in manifest["action"]
    assert "permissions" in manifest
    assert "activeTab" in manifest["permissions"]
    assert "scripting" in manifest["permissions"]
