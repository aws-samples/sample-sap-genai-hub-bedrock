"""Universal OData API integration tool for Strands Agent.

This module provides a simple, generic interface to any OData v4 service,
allowing you to execute OData operations against any OData endpoint.

Key Features:
- Universal OData v4 support
- Standard OData query parameters ($filter, $select, $expand, etc.)
- Basic authentication options
- CRUD operations (GET, POST, PATCH, DELETE)
- Error handling and response formatting

Usage Examples:
```python
# Basic OData query
agent.tool.odata_caller(
    base_url="https://services.odata.org/TripPinRESTierService/(S(1234))/",
    endpoint="People",
    operation="get"
)

# Query with OData parameters
agent.tool.odata_caller(
    base_url="https://your-service.com/odata/",
    endpoint="Products",
    operation="get",
    odata_params={"$filter": "Name eq 'Widget'", "$select": "Name,Price"}
)
```
"""

import datetime
import json
import logging
import os
from typing import Any, Dict, Optional
from urllib.parse import urlencode
import requests

from strands import tool

logger = logging.getLogger(__name__)


def handle_jwt(config: Dict[str, str]) -> str:
    """Process JWT authentication and generate token."""
    try:
        import jwt  # Imported here to avoid global dependency
    except ImportError:
        raise ImportError(
            "PyJWT package is required for JWT authentication. Install with: pip install PyJWT"
        ) from None

    # Get configuration with defaults
    secret = config.get("secret")
    algorithm = config.get("algorithm", "HS256")
    expiry_seconds = int(config.get("expiry", 3600))  # Default 1 hour

    if not secret:
        raise ValueError("JWT secret is required in jwt_config")

    # Create expiration time
    expiry_time = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        seconds=expiry_seconds
    )

    # Create JWT payload
    payload = {"exp": expiry_time}

    # Generate token
    token = jwt.encode(payload, secret, algorithm=algorithm)

    # Convert token to string based on type (PyJWT versions handle this differently)
    token_str = token.decode("utf-8") if hasattr(token, "decode") else str(token)

    return token_str


def build_odata_url(
    base_url: str, endpoint: str, odata_params: Optional[Dict[str, str]] = None
) -> str:
    """Build OData URL with query parameters."""
    if not base_url.startswith(("http://", "https://")):
        base_url = "https://" + base_url

    url = base_url.rstrip("/")
    if endpoint:
        url += "/" + endpoint.lstrip("/")

    if odata_params:
        filtered_params = {k: str(v) for k, v in odata_params.items() if v is not None}
        if filtered_params:
            url += "?" + urlencode(filtered_params)

    return url


@tool
def odata_caller(
    base_url: str,
    endpoint: str = "",
    operation: str = "get",
    odata_params: Optional[Dict[str, str]] = None,
    body: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    auth_type: Optional[str] = None,
    auth_token: Optional[str] = None,
    auth_env_var: Optional[str] = None,
    basic_auth: Optional[Dict[str, str]] = None,
    jwt_config: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Execute OData v4 operations with comprehensive query parameter support.

    This tool provides a universal interface to any OData v4 service, allowing you to execute
    queries, create, update, and delete operations with full OData query parameter support.

    Args:
        base_url: Base URL of the OData service (e.g., "https://services.odata.org/TripPinRESTierService/")
        endpoint: OData endpoint/entity set (e.g., "People", "Products", "$metadata")
        operation: HTTP operation to perform (get, post, patch, delete)
        odata_params: Optional OData query parameters dictionary:
            - "$filter": Filter results (e.g., "Name eq 'John'")
            - "$select": Select specific fields (e.g., "Name,Email")
            - "$expand": Expand related entities (e.g., "Orders")
            - "$orderby": Sort results (e.g., "Name asc")
            - "$top": Limit results (e.g., "10")
            - "$skip": Skip results for paging (e.g., "20")
            - "$count": Include count (e.g., "true")
        body: Request body for POST/PATCH operations (JSON dictionary)
        headers: Additional HTTP headers
        auth_type: Authentication type ("Bearer", "token", "basic", "digest", "jwt", "aws_sig_v4", "kerberos", "custom", "api_key")
        auth_token: Authentication token
        auth_env_var: Environment variable name containing the auth token
        basic_auth: Basic auth credentials with 'username' and 'password' keys
        jwt_config: JWT configuration with 'secret', 'algorithm', and 'expiry' keys

    Returns:
        Dict containing status and response content

    Examples:
        # Get all entities
        result = agent.tool.odata_caller(
            base_url="https://services.odata.org/TripPinRESTierService/",
            endpoint="People",
            operation="get"
        )

        # Query with filters
        result = agent.tool.odata_caller(
            base_url="https://your-service.com/odata/",
            endpoint="Products",
            operation="get",
            odata_params={
                "$filter": "Price gt 100",
                "$select": "Name,Price",
                "$top": "10"
            }
        )

        # Create new entity
        result = agent.tool.odata_caller(
            base_url="https://your-service.com/odata/",
            endpoint="Products",
            operation="post",
            body={"Name": "Widget", "Price": 99.99}
        )
    """

    # Build the complete URL
    full_url = build_odata_url(base_url, endpoint, odata_params)

    # Build headers
    request_headers = headers or {}

    # Handle metadata requests - they return XML, not JSON
    if endpoint == "$metadata" or endpoint.endswith("/$metadata"):
        request_headers["Accept"] = "application/xml"
    else:
        request_headers["Accept"] = "application/json"

    if body:
        request_headers["Content-Type"] = "application/json"

    # Add SAP-specific headers for SAP APIs
    if "sandbox.api.sap.com" in base_url or "api.sap.com" in base_url:
        request_headers["DataServiceVersion"] = "2.0"

    # Handle environment variable authentication
    if auth_env_var:
        auth_token = os.getenv(auth_env_var)
        if not auth_token:
            raise ValueError(
                f"Environment variable '{auth_env_var}' not found or empty"
            )

    # Handle basic authentication with username/password
    auth = None
    if basic_auth and isinstance(basic_auth, dict):
        username = basic_auth.get("username")
        password = basic_auth.get("password")
        if username and password:
            auth = requests.auth.HTTPBasicAuth(username, password)

    # Handle JWT configuration to generate token
    if auth_type and auth_type.lower() == "jwt" and jwt_config and not auth_token:
        try:
            auth_token = handle_jwt(jwt_config)
        except Exception as e:
            return {
                "status": "error",
                "content": [{"text": f"JWT generation error: {str(e)}"}],
            }

    # Handle authentication headers
    if auth_type and auth_token:
        auth_type_lower = auth_type.lower()
        if auth_type_lower in ["bearer", "token"]:
            request_headers["Authorization"] = f"Bearer {auth_token}"
        elif auth_type_lower == "basic":
            # For basic auth, auth_token should be "username:password"
            if ":" in auth_token:
                username, password = auth_token.split(":", 1)
                auth = requests.auth.HTTPBasicAuth(username, password)
        elif auth_type_lower == "api_key":
            # For SAP APIs, use APIKey header instead of X-API-Key
            if "sandbox.api.sap.com" in full_url or "api.sap.com" in full_url:
                request_headers["APIKey"] = auth_token
            else:
                request_headers["X-API-Key"] = auth_token
        elif auth_type_lower == "jwt":
            request_headers["Authorization"] = f"Bearer {auth_token}"
        elif auth_type_lower == "custom":
            # For custom auth, assume auth_token contains the full header value
            request_headers["Authorization"] = auth_token
        # Note: digest, aws_sig_v4, kerberos require more complex implementation
        # and would be handled by requests library or specialized auth handlers

    # Map operation to HTTP method
    method_map = {
        "get": "GET",
        "post": "POST",
        "patch": "PATCH",
        "put": "PUT",
        "delete": "DELETE",
    }

    http_method = method_map.get(operation.lower(), operation.upper())

    try:
        # Prepare request data
        request_data = None
        if body and http_method in ["POST", "PATCH", "PUT"]:
            request_data = json.dumps(body)

        # Execute the HTTP request using requests directly
        response = requests.request(
            method=http_method,
            url=full_url,
            headers=request_headers,
            data=request_data,
            auth=auth,
            timeout=30,
            verify=True,
        )

        # Check if request was successful
        if response.status_code >= 400:
            error_msg = f"❌ HTTP {response.status_code}: {response.reason}\n"

            try:
                # Try to parse error response
                error_json = response.json()
                if "error" in error_json:
                    error_details = error_json["error"]
                    if isinstance(error_details, dict):
                        error_msg += (
                            f"Error: {error_details.get('message', 'Unknown error')}\n"
                        )
                        if "details" in error_details:
                            for detail in error_details["details"]:
                                error_msg += (
                                    f"  • {detail.get('message', 'No details')}\n"
                                )
                    else:
                        error_msg += f"Error: {error_details}\n"
                else:
                    error_msg += f"Response: {json.dumps(error_json, indent=2)}\n"
            except:
                # Not JSON or different error format
                error_msg += (
                    f"Response: {response.text[:500]}...\n"
                    if len(response.text) > 500
                    else f"Response: {response.text}\n"
                )

            # Add troubleshooting suggestions
            error_msg += get_odata_error_suggestions(response.status_code, full_url)

            return {"status": "error", "content": [{"text": error_msg}]}

        # Parse successful response
        is_metadata = endpoint == "$metadata" or endpoint.endswith("/$metadata")

        if is_metadata:
            # Metadata responses are XML
            result = response.text
            content_type = "XML"
        else:
            try:
                result = response.json()
                content_type = "JSON"
            except:
                # Not JSON response
                result = response.text
                content_type = "Text"

        # Format successful response
        response_text = f"✅ OData {operation.upper()} {endpoint or 'Service Root'}\n"
        response_text += f"🌐 URL: {full_url}\n"
        response_text += f"📊 Status: {response.status_code} {response.reason}\n"
        response_text += f"📋 Content-Type: {content_type}\n\n"

        if isinstance(result, dict):
            if "@odata.count" in result:
                response_text += f"📈 Total Count: {result['@odata.count']}\n"

            if "value" in result and isinstance(result["value"], list):
                response_text += f"📦 Items: {len(result['value'])}\n"

                # Show sample item fields
                if result["value"]:
                    first_item = result["value"][0]
                    if isinstance(first_item, dict):
                        response_text += f"📋 Sample Fields: {', '.join(list(first_item.keys())[:8])}\n"
                        if len(first_item.keys()) > 8:
                            response_text += (
                                f"    ... and {len(first_item.keys()) - 8} more\n"
                            )

            response_text += f"\n📄 Response:\n{json.dumps(result, indent=2)}"
        elif is_metadata:
            # For metadata, show a truncated version since XML can be very long
            if len(result) > 2000:
                response_text += f"📄 Metadata (truncated - {len(result)} chars total):\n{result[:2000]}...\n\n"
                response_text += "💡 Metadata successfully retrieved! Use this to understand available entities and their properties."
            else:
                response_text += f"📄 Metadata:\n{result}"
        else:
            response_text += f"📄 Response:\n{str(result)}"

        return {"status": "success", "content": [{"text": response_text}]}

    except requests.exceptions.RequestException as ex:
        error_msg = f"❌ Request Error: {str(ex)}\n\n"
        error_msg += get_request_error_suggestions(str(ex))

        return {"status": "error", "content": [{"text": error_msg}]}
    except Exception as ex:
        error_msg = f"❌ Unexpected Error: {str(ex)}\n\n"
        error_msg += "💡 General Suggestions:\n"
        error_msg += "• Check URL format and accessibility\n"
        error_msg += "• Verify authentication credentials\n"
        error_msg += "• Check network connectivity"

        return {"status": "error", "content": [{"text": error_msg}]}


def get_odata_error_suggestions(status_code: int, url: str) -> str:
    """Generate helpful suggestions based on HTTP status code."""
    suggestions = "\n💡 Suggestions:\n"

    if status_code == 400:
        suggestions += "• Check OData query syntax ($filter, $select, etc.)\n"
        suggestions += "• Verify field names exist in the entity\n"
        suggestions += "• Check request body format for POST/PATCH operations\n"
    elif status_code == 401:
        suggestions += "• Check authentication token/credentials\n"
        suggestions += "• Verify auth_type is correct (Bearer, Basic, api_key)\n"
        suggestions += "• Ensure token has not expired\n"
    elif status_code == 403:
        suggestions += "• Check if you have permissions for this operation\n"
        suggestions += "• Verify API key/token has required scopes\n"
    elif status_code == 404:
        suggestions += f"• Check if endpoint exists: {url}\n"
        suggestions += "• Use /$metadata to discover available entities\n"
        suggestions += "• Verify base_url is correct\n"
    elif status_code >= 500:
        suggestions += "• Service may be temporarily unavailable\n"
        suggestions += "• Check if the OData service is running\n"
        suggestions += "• Verify server configuration\n"
    else:
        suggestions += f"• HTTP {status_code} indicates a client or server issue\n"
        suggestions += "• Check OData service documentation\n"

    suggestions += "• Try using /$metadata endpoint to explore service structure\n"
    return suggestions


def get_request_error_suggestions(error_msg: str) -> str:
    """Generate suggestions for request-level errors."""
    suggestions = "💡 Request Error Suggestions:\n"
    error_lower = error_msg.lower()

    if "timeout" in error_lower:
        suggestions += "• Service may be slow - try increasing timeout\n"
        suggestions += "• Check network connectivity\n"
    elif "connection" in error_lower:
        suggestions += "• Check if the service URL is accessible\n"
        suggestions += "• Verify network connectivity and firewall rules\n"
    elif "ssl" in error_lower or "certificate" in error_lower:
        suggestions += "• SSL certificate issue - verify service certificate\n"
        suggestions += "• For development, you might disable SSL verification\n"
    else:
        suggestions += "• Check URL format and accessibility\n"
        suggestions += "• Verify service is running and accessible\n"

    return suggestions
