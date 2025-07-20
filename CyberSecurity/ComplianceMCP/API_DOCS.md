# ComplianceMCP API Documentation

## Table of Contents
- [Overview](#overview)
- [Authentication](#authentication)
- [Tools](#tools)
  - [Compliance Tools](#compliance-tools)
  - [Risk Management](#risk-management)
  - [Vendor Management](#vendor-management)
  - [Policy Management](#policy-management)
  - [Security Tools](#security-tools)
- [Resources](#resources)
- [Prompts](#prompts)
- [Error Handling](#error-handling)
- [Rate Limiting](#rate-limiting)

## Overview

This document provides comprehensive documentation for the ComplianceMCP API, which offers tools and resources for managing compliance across various frameworks including GDPR, HIPAA, PCI-DSS, and ISO27001.

## Authentication

All API endpoints require authentication using an API key. Include the API key in the `X-API-Key` header of your requests.

```http
GET /api/endpoint
X-API-Key: your_api_key_here
```

## Tools

### Compliance Tools

#### Check Compliance Status
- **Endpoint**: `GET /compliance/{framework}`
- **Description**: Check the compliance status for a specific framework
- **Parameters**:
  - `framework` (path): The compliance framework (GDPR, HIPAA, PCI-DSS, ISO27001)
- **Response**:
  ```json
  {
    "status": "Compliant",
    "last_updated": "2025-07-20T09:30:00Z",
    "alerts_count": 0,
    "source": "unizo",
    "details": "No compliance violations detected"
  }
  ```

#### Generate Compliance Report
- **Endpoint**: `GET /report/{framework}`
- **Description**: Generate a detailed compliance report
- **Parameters**:
  - `framework` (path): The compliance framework
- **Response**: PDF or JSON report

#### Perform Gap Analysis
- **Endpoint**: `POST /gap-analysis`
- **Description**: Perform a gap analysis for a compliance framework
- **Request Body**:
  ```json
  {
    "framework": "GDPR",
    "scope": ["data_processing", "consent_management"]
  }
  ```
- **Response**:
  ```json
  {
    "missing_controls": ["GDPR-ART-30", "GDPR-ART-35"],
    "recommendations": ["Implement data mapping", "Update DPIAs"],
    "compliance_score": 0.75
  }
  ```

### Risk Management

#### Assess Risk
- **Endpoint**: `POST /risks/assess`
- **Description**: Assess a new risk
- **Request Body**:
  ```json
  {
    "description": "Unauthorized data access",
    "impact": "High",
    "likelihood": "Medium"
  }
  ```
- **Response**:
  ```json
  {
    "risk_id": "RISK-1234",
    "severity": "High",
    "mitigation": "Implement MFA and access controls"
  }
  ```

#### Get Risk Register
- **Endpoint**: `GET /risks`
- **Description**: Retrieve all recorded risks
- **Response**:
  ```json
  [
    {
      "id": "RISK-1234",
      "description": "Unauthorized data access",
      "severity": "High",
      "status": "Open"
    }
  ]
  ```

### Vendor Management

#### Assess Vendor
- **Endpoint**: `POST /vendors/assess`
- **Description**: Assess a vendor's compliance status
- **Request Body**:
  ```json
  {
    "vendor_id": "VEND-001",
    "name": "Acme Corp",
    "services": ["data_processing", "cloud_storage"]
  }
  ```
- **Response**:
  ```json
  {
    "vendor_id": "VEND-001",
    "status": "Compliant",
    "assessment_date": "2025-07-20"
  }
  ```

### Policy Management

#### Get Policy Document
- **Endpoint**: `GET /policies/{policy_id}`
- **Description**: Retrieve a specific policy document
- **Parameters**:
  - `policy_id` (path): The ID of the policy to retrieve
- **Response**:
  ```json
  {
    "id": "POL-001",
    "title": "Data Protection Policy",
    "content": "...policy content...",
    "version": "2.1",
    "last_updated": "2025-06-15"
  }
  ```

#### Update Policy Version
- **Endpoint**: `PUT /policies/{policy_id}`
- **Description**: Update a policy with a new version
- **Request Body**:
  ```json
  {
    "content": "Updated policy content...",
    "version_notes": "Updated to reflect new regulations"
  }
  ```
- **Response**:
  ```json
  {
    "policy_id": "POL-001",
    "version": "2.2",
    "updated_at": "2025-07-20T10:30:00Z"
  }
  ```

### Security Tools

#### Validate Encryption
- **Endpoint**: `POST /security/validate-encryption`
- **Description**: Validate encryption standards for a system
- **Request Body**:
  ```json
  {
    "system": "payment-gateway",
    "expected_standard": "TLS 1.3"
  }
  ```
- **Response**:
  ```json
  {
    "system": "payment-gateway",
    "encryption_standard": "TLS 1.3",
    "is_compliant": true,
    "details": "All endpoints using TLS 1.3 with strong ciphers"
  }
  ```

## Resources

### Data Flows
- **Endpoint**: `GET /data/flows`
- **Description**: Retrieve data flow mappings
- **Response**:
  ```
  Data Flow: CRM -> Database -> Analytics (GDPR-compliant)
  ```

### Compliance Requirements
- **Endpoint**: `GET /compliance/requirements/{framework}`
- **Description**: Get requirements for a compliance framework
- **Response**:
  ```
  GDPR: Data minimization, consent, right to erasure
  ```

### Control Mappings
- **Endpoint**: `GET /controls/{framework}`
- **Description**: Get control mappings for a framework
- **Response**:
  ```
  GDPR: Article 5: Principles, Article 32: Security of processing
  ```

## Prompts

### Policy Review
- **Template**: `policy_review(policy_id: str, style: str = "formal")`
- **Description**: Generate a prompt for reviewing a policy
- **Example**:
  ```python
  policy_review("GDPR-POL-001", "technical")
  # Returns: "Please provide a detailed technical analysis of the policy with ID GDPR-POL-001."
  ```

### Vendor Due Diligence
- **Template**: `vendor_due_diligence(vendor_id: str)`
- **Description**: Generate a prompt for vendor due diligence
- **Example**:
  ```python
  vendor_due_diligence("VEND-001")
  # Returns: "Perform due diligence on the vendor with ID VEND-001 for compliance."
  ```

### Risk Assessment
- **Template**: `risk_assessment(risk_id: str)`
- **Description**: Generate a prompt for risk assessment
- **Example**:
  ```python
  risk_assessment("RISK-0042")
  # Returns: "Assess the risk with ID RISK-0042 and recommend mitigation strategies."
  ```

## Error Handling

All error responses follow this format:

```json
{
  "error": {
    "code": "error_code",
    "message": "Human-readable error message",
    "details": {
      "field": "Additional error details"
    }
  }
}
```

### Common Error Codes
- `400`: Bad Request - Invalid request parameters
- `401`: Unauthorized - Missing or invalid API key
- `403`: Forbidden - Insufficient permissions
- `404`: Not Found - Resource not found
- `429`: Too Many Requests - Rate limit exceeded
- `500`: Internal Server Error - Server error

## Rate Limiting

- **Rate Limit**: 100 requests per minute per API key
- **Headers**:
  - `X-RateLimit-Limit`: Maximum number of requests allowed
  - `X-RateLimit-Remaining`: Remaining number of requests
  - `X-RateLimit-Reset`: Timestamp when the limit resets

## Best Practices

1. Always check the response status code
2. Implement proper error handling
3. Cache responses when possible
4. Respect rate limits
5. Use HTTPS for all requests
6. Keep your API key secure

## Support

For support, please contact [support@compliancemcp.com](mailto:support@compliancemcp.com) or open an issue on our [GitHub repository](https://github.com/yourusername/ComplianceMCP).
