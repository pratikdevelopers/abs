<?php

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use App\Services\GpgService;

class AuthorizeCreationController extends Controller
{
    /**
     * Create authorization for eDDA creation
     * Based on ABS eGIRO Discovery Phase API Specifications v3.17 Section 3.2.1
     * 
     * URL: https://<aggregator_api_platform_domain>/api/v1/edda/authorize/creation
     * Method: GET
     * Authentication: N/A (Public API, One-way SSL)
     */
    public function createAuthorize(Request $request): JsonResponse
    {
        // Validate client_slug first
        $validator = Validator::make($request->all(), [
            'client_slug' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'errors' => [
                    [
                        'errorCode' => 'AG0001',
                        'errorMessage' => 'Validation failed: client_slug is required',
                    ],
                ],
            ], 422);
        }

        $clientSlug = $request->string('client_slug');
        $clientConfig = config('clients.' . $clientSlug);

        if (!is_array($clientConfig) || empty($clientConfig[env('APP_ENV')])) {
            return response()->json([
                'errors' => [
                    [
                        'errorCode' => 'AG0002',
                        'errorMessage' => 'Invalid client configuration',
                    ],
                ],
            ], 422);
        }

        $clientConfig = $clientConfig[env('APP_ENV')];

        // Validate all required parameters
        $validator = Validator::make($request->all(), [
            'client_slug' => 'required|string',
            'applicantBankCode' => 'required|string|size:11',
            'boName' => 'required|string|max:140',
            'boTransactionRefNo' => 'required|string|size:35',
            'boDDARefNo' => 'nullable|string|max:35',
            'clientID' => 'required|string|size:15',
            'purpose' => 'nullable|string|size:4',
            'requestID' => 'required|string|size:36',
            'requestType' => 'required|string|in:Creation',
            'segment' => 'required|string|in:Retail,Corporate',
            'nonce' => 'required|string|size:20',
            'timestamp' => 'required|string',
            'signKeyAlias' => 'nullable|string',
            'signature' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'errors' => [
                    [
                        'errorCode' => 'AG0003',
                        'errorMessage' => 'Validation failed',
                        'details' => $validator->errors(),
                    ],
                ],
            ], 422);
        }

        // Get parameters from request
        $applicantBankCode = $request->input('applicantBankCode');
        $boName = $request->input('boName');
        $boTransactionRefNo = $request->input('boTransactionRefNo');
        $boDDARefNo = $request->input('boDDARefNo');
        $clientID = $request->input('clientID') ?: $clientConfig['client_id'];
        $purpose = $request->input('purpose');
        $requestID = $request->input('requestID') ?: Str::uuid()->toString();
        $requestType = $request->input('requestType') ?: 'Creation';
        $segment = $request->input('segment');
        $nonce = $request->input('nonce') ?: $this->generateNonce();
        $timestamp = $request->input('timestamp') ?: (string) (now()->timestamp * 1000);
        $signKeyAlias = $request->input('signKeyAlias') ?: ($clientConfig['sign_key_alias'] ?? '');
        $signature = $request->input('signature');

        // Use boName from config if not provided
        if (empty($boName)) {
            $boName = $clientConfig['bo_name'] ?? '';
        }

        // Build query parameters in the exact order specified in PDF Section 3.2.1
        // Order: clientID, requestID, nonce, timestamp, boName, applicantBankCode, 
        //        boDDARefNo (optional), signKeyAlias (optional), boTransactionRefNo, 
        //        requestType, purpose (optional), segment
        // Using an ordered array to maintain parameter order for signature generation
        $params = [];
        $params['clientID'] = $clientID;
        $params['requestID'] = $requestID;
        $params['nonce'] = $nonce;
        $params['timestamp'] = $timestamp;
        $params['boName'] = $boName;
        $params['applicantBankCode'] = $applicantBankCode;
        
        // boDDARefNo is optional, only include if provided
        if (!empty($boDDARefNo)) {
            $params['boDDARefNo'] = $boDDARefNo;
        }
        
        // signKeyAlias is optional, only include if not empty
        if (!empty($signKeyAlias)) {
            $params['signKeyAlias'] = $signKeyAlias;
        }
        
        $params['boTransactionRefNo'] = $boTransactionRefNo;
        $params['requestType'] = $requestType;
        
        // purpose is optional, only include if provided
        if (!empty($purpose)) {
            $params['purpose'] = $purpose;
        }
        
        $params['segment'] = $segment;

        // Generate signature if not provided
        if (empty($signature)) {
            try {
                $signature = $this->generateSignature($params, $clientConfig);
            } catch (\Throwable $e) {
                return response()->json([
                    'errors' => [
                        [
                            'errorCode' => 'AG0004',
                            'errorMessage' => 'Failed to generate signature',
                            'details' => $e->getMessage(),
                        ],
                    ],
                ], 500);
            }
        }

        // Add signature to params
        $params['signature'] = $signature;

        // Build URL
        $url = config('abs.' . env('APP_ENV') . '.authorizeCreation.api_url');

        // Build headers as per API specification
        $headers = [
            'clientID' => $clientID,
            'requestID' => $requestID,
            'x-api-key' => $clientConfig['x-api-key'],
            'aggregatorKeyAlias' => $clientConfig['aggregator_key_alias'],
        ];

        // Add optional signKeyAlias header if available
        if (!empty($signKeyAlias)) {
            $headers['signKeyAlias'] = $signKeyAlias;
        }

        // Build query string for URL (URL encode all parameters including signature)
        $queryString = http_build_query($params, null, null, PHP_QUERY_RFC3986);
        
        // Apply special encoding rules as per API specification
        // Replace %25 (encoded %) with actual %
        $queryString = str_replace('%25', '%', $queryString);
        // Replace %20 (encoded space) with actual space
        $queryString = str_replace('%20', ' ', $queryString);

        $fullUrl = $url . '?' . $queryString;

        // Make GET request (One-way SSL, no mutual TLS for this endpoint)
        $http = Http::withHeaders($headers);

        $response = $http->get($fullUrl);

        // Handle redirect response (HTTP 302)
        if ($response->status() === 302) {
            $location = $response->header('Location');
            if ($location) {
                return response()->json([
                    'message' => 'Authorization redirect',
                    'redirect_url' => $location,
                    'status' => 302,
                ], 302);
            }
        }

        // Handle error responses
        if ($response->failed()) {
            return response()->json([
                'request_data' => [
                    'url' => $fullUrl,
                    'headers' => $headers,
                    'query_params' => $params,
                    'timestamp' => now()->format('Y-m-d H:i:s'),
                ],
                'response_data' => [
                    'status' => $response->status(),
                    'body' => $response->body(),
                ],
                'errors' => [
                    [
                        'errorCode' => 'AG' . str_pad($response->status(), 4, '0', STR_PAD_LEFT),
                        'errorMessage' => 'Authorization request failed',
                    ],
                ],
            ], $response->status() ?: 502);
        }

        // Return success response
        return response()->json([
            'message' => 'Authorization created successfully',
            'data' => $response->json(),
        ]);
    }

    /**
     * Generate PGP signature for query parameters
     * 
     * @param array $params Query parameters in correct order
     * @param array $clientConfig Client configuration
     * @return string URL-encoded signature
     */
    private function generateSignature(array $params, array $clientConfig): string
    {
        $pgpConfig = $clientConfig['pgp'] ?? [];
        
        if (empty($pgpConfig)) {
            throw new \RuntimeException('Missing PGP configuration for client');
        }

        $privateKeyPath = $pgpConfig['private_key'] ?? null;
        $passphrase = $pgpConfig['passphrase'] ?? '';
        $issuerFingerprint = $pgpConfig['fingerprint'] ?? null;

        if (!$privateKeyPath || !file_exists($privateKeyPath)) {
            throw new \RuntimeException('Issuer private key not found');
        }

        // Build query string for signing (no URL encoding as per PDF spec)
        // "No URL encoding is required for Query Parameters to create the Signature"
        $signingString = '';
        $first = true;
        foreach ($params as $key => $value) {
            if (!$first) {
                $signingString .= '&';
            }
            $signingString .= $key . '=' . $value;
            $first = false;
        }

        // Sign the string using PGP
        $gpgService = new GpgService();
        $pgpSignature = $gpgService->sign(
            $signingString,
            $privateKeyPath,
            $passphrase,
            $issuerFingerprint
        );

        // Remove newlines and control characters from signature
        $pgpSignature = preg_replace('/[\r\n\t]/', '', $pgpSignature);
        $pgpSignature = preg_replace('/[\x00-\x1F\x7F]/', '', $pgpSignature);

        // URL encode the signature using encodeURIComponent rules
        // Special encoding: Replace %25 with %, Replace %20 with space
        $encodedSignature = $this->encodeURIComponent($pgpSignature);
        
        // Apply special encoding rules
        $encodedSignature = str_replace('%25', '%', $encodedSignature);
        $encodedSignature = str_replace('%20', ' ', $encodedSignature);

        return $encodedSignature;
    }

    /**
     * Generate a 20-character nonce
     * 
     * @return string
     */
    private function generateNonce(): string
    {
        return Str::random(20);
    }

    /**
     * Encode URI component with special character reverts
     * As per API specification: encodeURIComponent with special reverts
     * 
     * @param string $queryParam
     * @return string
     */
    private function encodeURIComponent(string $queryParam): string
    {
        $revert = [
            '%21' => '!',
            '%2A' => '*',
            '%27' => "'",
            '%28' => '(',
            '%29' => ')',
        ];

        return strtr(rawurlencode($queryParam), $revert);
    }
}
