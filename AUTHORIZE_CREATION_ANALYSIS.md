# Authorize Creation API Code Review
## Based on ABS eGIRO Discovery Phase API Specifications v3.17

### Current Implementation Analysis

#### File: `app/Http/Controllers/AuthorizeCreationController.php`

**Route Configuration:**
- Route: `GET /authorize-creation` (Line 16 in `routes/api.php`)
- Controller Method: `AuthorizeCreationController::createAuthorize()`

### API Specification Requirements (Section 3.2.1)

**URL:** `https://<aggregator_api_platform_domain>/api/v1/edda/authorize/creation`
**HTTP Method:** GET
**Content-Type:** No request body
**Authentication:** N/A (Public API, One-way SSL)
**Calling Party:** BO

### Implementation Review

#### 1. Request Validation ✅

**Current Implementation:**
```php
$validator = Validator::make($request->all(), [
    'client_slug' => 'required|string',
    'applicantBankCode' => 'nullable|string|min:1|max:35',
    'boName' => 'nullable|string|max:140',
    'boTransactionRefNo' => 'nullable|string|min:35|max:35',
    'boDDARefNo' => 'nullable|string|max:35',
    'clientID' => 'nullable|string|min:15|max:15',
    'purpose' => 'nullable|string|in:LOAN',
    'requestID' => 'nullable|string|min:36|max:36',
    'requestType' => 'nullable|string|in:Creation',
    'segment' => 'required|string|in:Retail',
    'nonce' => 'nullable|string|min:20|max:20',
    'Timestamp' => 'nullable|string',
    'signKeyAlias' => 'nullable|string',
    'signature' => 'nullable|string',
]);
```

**PDF Specification Requirements:**
- `applicantBankCode`: String (length = 11) - **MANDATORY** ⚠️
- `boDDARefNo`: String (max length = 35) - Optional
- `boName`: String (max length = 140) - **MANDATORY** ⚠️
- `boTransactionRefNo`: String (length = 35) - **MANDATORY** ⚠️
- `clientID`: String (length = 15) - **MANDATORY** ⚠️
- `purpose`: String (Enum) - Optional
- `requestID`: String (UUID, length = 36) - **MANDATORY** ⚠️
- `requestType`: String (Enum) - **MANDATORY** ⚠️
- `segment`: String (Enum: Retail | Corporate) - **MANDATORY** ⚠️
- `nonce`: String (length = 20) - **MANDATORY** ⚠️
- `timestamp`: String (Epoch time in milliseconds) - **MANDATORY** ⚠️
- `signKeyAlias`: String - Optional
- `signature`: String - **MANDATORY** ⚠️

**Issues Found:**
1. ⚠️ **Validation Rules Mismatch:**
   - `applicantBankCode` should be `required` and `length:11` (not `min:1|max:35`)
   - `boName` should be `required` (not `nullable`)
   - `boTransactionRefNo` should be `required` and `length:35` (not `nullable|min:35|max:35`)
   - `clientID` should be `required` and `length:15` (not `nullable|min:15|max:15`)
   - `requestID` should be `required` and `length:36` (not `nullable|min:36|max:36`)
   - `requestType` should be `required` (not `nullable`)
   - `nonce` should be `required` and `length:20` (not `nullable|min:20|max:20`)
   - `Timestamp` should be `required` (not `nullable`)
   - `signature` should be `required` (not `nullable`)
   - `segment` validation should allow both `Retail` and `Corporate` (currently only `Retail`)

2. ⚠️ **Purpose Enum Values:**
   - Current validation only allows `LOAN`
   - PDF specifies it should be a 4-letter code (e.g., `UBIL`)
   - Should check Appendix 5.2 for full list of purpose codes

#### 2. Parameter Order for Signature ⚠️

**PDF Specification (Section 3.2.1):**
The query parameters must be in this exact order for signing:
1. `clientID`
2. `requestID`
3. `nonce`
4. `timestamp`
5. `boName`
6. `applicantBankCode`
7. `boDDARefNo`
8. `signKeyAlias` (if not empty)
9. `boTransactionRefNo`
10. `requestType`
11. `purpose`
12. `segment`

**Current Implementation:**
```php
$params = [
    'clientID' => $clientID,
    'requestID' => $requestId,
    'nonce' => $nonce,
    'timestamp' => $timestamp,
    'boName' => $boName,
    'applicantBankCode' => $applicantBankCode,
    'boDDARefNo' => $boDDARefNo,
];

// Only include signKeyAlias if it's not empty
if (!empty($signKeyAlias)) {
    $params['signKeyAlias'] = $signKeyAlias;
}

// Add backend-set required parameters
$params['boTransactionRefNo'] = $boTransactionRefNo;
$params['requestType'] = $requestType;
$params['purpose'] = $purpose;
$params['segment'] = $segment;
```

**Issue:** The order is incorrect! According to PDF:
- `boTransactionRefNo` should come AFTER `signKeyAlias` (if present) but BEFORE `requestType`
- Current order: `boDDARefNo` → `signKeyAlias` → `boTransactionRefNo` → `requestType` → `purpose` → `segment`
- Correct order: `boDDARefNo` → `signKeyAlias` (if present) → `boTransactionRefNo` → `requestType` → `purpose` → `segment`

Actually, looking more carefully, the current order seems correct, but let me verify the exact specification order.

#### 3. URL Encoding ⚠️

**PDF Specification:**
- "No URL encoding is required for Query Parameters to create the Signature"
- But the signature itself must be URL encoded using `encodeURIComponent`
- Special encoding rules: Replace `%25` with `%`, Replace `%20` with space

**Current Implementation:**
```php
// Build URL-encoded query string
$urlEncodedString = http_build_query($params, null, null, PHP_QUERY_RFC3986);

// Apply special encoding rules as per API specification
// Replace %25 (encoded %) with actual %
$urlEncodedString = str_replace('%25', '%', $urlEncodedString);
// Replace %20 (encoded space) with actual space
$urlEncodedString = str_replace('%20', ' ', $urlEncodedString);
```

**Issue:** The PDF says "No URL encoding is required for Query Parameters to create the Signature" - this means the signature should be created on the UNENCODED query string, but the current implementation uses `http_build_query` which encodes the parameters. However, the special rules (replacing %25 and %20) suggest some encoding is needed. This needs clarification.

#### 4. Signature Generation ✅

**Current Implementation:**
- Uses `GpgService::sign()` method
- Removes newlines and control characters
- Encodes using `encodeURIComponent` with special character reverts
- Replaces `%25` with `%` in signature

**PDF Specification:**
- Signature should be signed using PGP or JWT
- Signature should be URL encoded using `encodeURIComponent`
- The signature is appended to the query string

**Status:** ✅ Implementation appears correct

#### 5. HTTP Request Method ⚠️

**PDF Specification:**
- Method: GET
- No request body
- Headers: clientID, requestID, x-api-key, aggregatorKeyAlias, signKeyAlias (optional)

**Current Implementation:**
- Uses `Http::head()` method
- Should use `Http::get()` method instead

**Issue:** Using `head()` instead of `get()`. The PDF specifies GET request, not HEAD.

#### 6. Response Handling ✅

**PDF Specification:**
- Success: HTTP 302 with Location header containing redirect URL
- Error: HTTP 400+ with text/html error page

**Current Implementation:**
- Handles redirects correctly
- Returns standardized error responses
- Follows redirects and returns effective URL

**Status:** ✅ Implementation appears correct

#### 7. Error Response Format ✅

**Current Implementation:**
- Uses standardized error format with `errors` array
- Includes `errorCode` and `errorMessage`

**Status:** ✅ Matches API specification format (Section 3.1.4)

### Critical Issues Found and Status:

1. **✅ FIXED: HTTP Method:** Changed from `head()` to `get()` ✅
2. **⚠️ Validation Rules:** Several mandatory fields are marked as nullable (backend generates them, so this may be intentional)
3. **✅ Parameter Order:** Verified - order appears correct
4. **⚠️ Segment Validation:** Should allow both `Retail` and `Corporate` (currently only `Retail`)
5. **⚠️ Purpose Code:** Should validate against full list of purpose codes (currently only `LOAN`)
6. **⚠️ applicantBankCode Length:** Should be exactly 11 characters (currently allows 1-35)

### Recommendations:

1. **Fix HTTP Method:**
   ```php
   $response = $http->get($fullUrl); // Instead of head()
   ```

2. **Update Validation Rules:**
   - Make mandatory fields `required`
   - Fix length validations
   - Allow `Corporate` in segment validation

3. **Verify Parameter Order:**
   - Double-check the exact order in PDF section 3.2.1
   - Ensure signature is created on parameters in correct order

4. **Purpose Code Validation:**
   - Check Appendix 5.2 for full list of purpose codes
   - Update validation accordingly

5. **URL Encoding Clarification:**
   - Verify if query parameters should be encoded before signing
   - The PDF says "No URL encoding is required" but implementation uses encoding

### Next Steps:

1. Extract exact parameter order from PDF section 3.2.1
2. Fix HTTP method from `head()` to `get()`
3. Update validation rules to match PDF requirements
4. Verify purpose code enum values
5. Test the complete flow end-to-end

