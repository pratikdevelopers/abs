<?php

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redirect;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use App\Services\GpgService;

class AuthorizeCreationController extends Controller
{
    public function createAuthorize(Request $request): JsonResponse|RedirectResponse
    {
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
        if ($validator->fails()) {
            $errors = [];
            foreach ($validator->errors()->all() as $error) {
                $errors[] = [
                    'errorCode' => 'AG0001',
                    'errorMessage' => $error,
                ];
            }
            return response()->json([
                'errors' => $errors,
            ], 422);
        }

        $clientSlug = $request->string('client_slug');
        $clientConfig = config('clients.' . $clientSlug);
        if (!is_array($clientConfig) || empty($clientConfig[env('APP_ENV')])) {
            return response()->json([
                'errors' => [
                    [
                        'errorCode' => 'AG0001',
                        'errorMessage' => 'Invalid client configuration',
                    ],
                ],
            ], 422);
        }
        $clientConfig = $clientConfig[env('APP_ENV')];

        // Set backend-generated values
        $boName = $request->input('boName') ?: $clientConfig['bo_name'];
        $applicantBankCode = $request->input('applicantBankCode') ?: 'UOVBSGSGXXX';
        $clientID = $request->input('clientID') ?: $clientConfig['client_id'];
        $requestType = $request->input('requestType') ?: 'Creation';
        $purpose = $request->input('purpose') ?: 'LOAN';
        $segment = $request->input('segment') ?: 'Retail';
        $boDDARefNo = $request->input('boDDARefNo') ?: str_replace('.', '', uniqid('eDDA', true));

        // Generate boTransactionRefNo if not provided
        // Format: {clientID}{datetime}{random_digits}
        // Client ID (15) + Datetime YYYYMMDDhhmmss (14) + Random digits (6) = 35 characters total
        $boTransactionRefNo = $request->input('boTransactionRefNo');
        if (empty($boTransactionRefNo)) {
            // Get Client ID and pad to 15 characters (left-padded with zeros as per original logic)
            $client_id_padded = str_pad(substr($clientID, 0, 15), 15, '0', STR_PAD_LEFT);

            // Generate datetime in YYYYMMDDhhmmss format (14 characters)
            $datetime = date('YmdHis');

            // Generate 6 random digits (left-padded with zeros)
            $random_digits = str_pad(rand(0, 999999), 6, '0', STR_PAD_LEFT);

            // Combine: Client ID (15) + Datetime (14) + Random digits (6) = 35 characters total
            $boTransactionRefNo = $client_id_padded . $datetime . $random_digits;
        }

        $pgpConfig = $clientConfig['pgp'] ?? [];
        if (empty($pgpConfig)) {
            return response()->json([
                'errors' => [
                    [
                        'errorCode' => 'AG1001',
                        'errorMessage' => 'Missing PGP configuration for client',
                    ],
                ],
            ], 422);
        }

        $privateKeyPath = $pgpConfig['private_key'] ?? null;
        $passphrase = $pgpConfig['passphrase'] ?? '';
        $issuerFingerprint = $pgpConfig['fingerprint'] ?? null;

        if (!$privateKeyPath || !file_exists($privateKeyPath)) {
            return response()->json([
                'errors' => [
                    [
                        'errorCode' => 'AG1001',
                        'errorMessage' => 'Issuer private key not found',
                    ],
                ],
            ], 422);
        }

        // Generate values if not provided in request
        $requestId = $request->input('requestID') ?: Str::uuid()->toString();
        // Generate unique 20-digit random number for nonce (created for every request)
        $nonce = $request->input('nonce');
        if (empty($nonce)) {
            // Generate 20 random digits
            $nonce = '';
            for ($i = 0; $i < 20; $i++) {
                $nonce .= rand(0, 9);
            }
        }
        $timestamp = $request->input('Timestamp') ?: (string) (time() * 1000);
        $signKeyAlias = $request->input('signKeyAlias') ?: ($clientConfig['sign_key_alias'] ?? '');

        // Build signature parameters in correct order, excluding empty optional fields
        $signatureParams = $this->buildSignatureParams($request, $requestId, $nonce, $timestamp, $signKeyAlias, $clientID, $boTransactionRefNo, $requestType, $boName, $applicantBankCode, $boDDARefNo, $purpose, $segment);

        // Generate signature
        $signature = $this->generateSignature($signatureParams, $privateKeyPath, $passphrase, $issuerFingerprint);
        if ($signature === false) {
            return response()->json([
                'errors' => [
                    [
                        'errorCode' => 'AG1001',
                        'errorMessage' => 'Signature generation failed',
                    ],
                ],
            ], 500);
        }

        // Replace %25 with % in signature (as per API specification)
        $signature = str_replace('%25', '%', $signature);

        // Append signature to the URL-encoded string
        // The signature is already encoded with encodeURIComponent, append directly
        $requestParamsString = $signatureParams . '&signature=' . $signature;

        // Make API request
        return $this->makeApiRequest($requestParamsString, $clientConfig, $requestId);
    }

    /**
     * Build signature parameters in correct order, excluding empty optional fields
     */
    private function buildSignatureParams(Request $request, string $requestId, string $nonce, string $timestamp, string $signKeyAlias, string $clientID, string $boTransactionRefNo, string $requestType, string $boName, string $applicantBankCode, string $boDDARefNo, string $purpose, string $segment): string
    {
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

        // Build URL-encoded query string
        $urlEncodedString = http_build_query($params, null, null, PHP_QUERY_RFC3986);

        // Apply special encoding rules as per API specification
        // Replace %25 (encoded %) with actual %
        $urlEncodedString = str_replace('%25', '%', $urlEncodedString);
        // Replace %20 (encoded space) with actual space
        $urlEncodedString = str_replace('%20', ' ', $urlEncodedString);

        return $urlEncodedString;
    }

    /**
     * Generate signature using GPG service and encode it
     */
    private function generateSignature(string $signatureParams, string $privateKeyPath, string $passphrase, ?string $issuerFingerprint): string|false
    {
        try {
            $gpgService = new GpgService();

            // Sign the URL-encoded string
            $signature = $gpgService->sign(
                $signatureParams,
                $privateKeyPath,
                $passphrase,
                $issuerFingerprint
            );

            // Remove any newlines or control characters that might break URL
            $signature = str_replace(["\r", "\n", "\t"], '', $signature);
            
            // Encode the signature using encodeURIComponent
            $signature = $this->encodeURIComponent($signature);

            return $signature;

        } catch (\Throwable $e) {
            return false;
        }
    }


    /**
     * Make HTTP request to authorize creation API using cURL
     * Follows redirects and returns the effective URL
     */
    private function makeApiRequest(string $requestParamsString, array $clientConfig, string $requestId): JsonResponse|RedirectResponse
    {
        $url = config('abs.' . env('APP_ENV') . '.authorizeCreation.api_url');
        
        // Build headers
        $headers = [
            'clientID: ' . $clientConfig['client_id'],
            'requestID: ' . $requestId,
            'x-api-key: ' . $clientConfig['x-api-key'],
            'aggregatorKeyAlias: ' . $clientConfig['aggregator_key_alias'],
        ];

        // Add optional signKeyAlias if available
        if (!empty($clientConfig['sign_key_alias'])) {
            $headers[] = 'signKeyAlias: ' . $clientConfig['sign_key_alias'];
        }

        // Use cURL to make HEAD request and follow redirects
        $ch = curl_init();
        
        // Build the full URL with query string
        $fullUrl = $url . '?' . $requestParamsString;
        
        // Set the URL - cURL will validate it
        curl_setopt($ch, CURLOPT_URL, $fullUrl);
        curl_setopt($ch, CURLOPT_HEADER, true); // Get header
        curl_setopt($ch, CURLOPT_NOBODY, true); // HEAD request (do not include response body)
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); // Return response instead of outputting
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true); // Follow redirects
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        
        // Set SSL certificate and key for mutual TLS
        // curl_setopt($ch, CURLOPT_SSLCERT, storage_path('app/certs/uobuat_sivren_org.crt'));
        // curl_setopt($ch, CURLOPT_SSLKEY, storage_path('app/certs/uobuat_sivren_org.pem'));
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);

        curl_exec($ch);
        
        // Check for cURL errors
        if (curl_errno($ch)) {
            $error = curl_error($ch);
            curl_close($ch);
            return response()->json([
                'errors' => [
                    [
                        'errorCode' => 'AG5001',
                        'errorMessage' => 'cURL request failed: ' . $error,
                    ],
                ],
                'request_data' => [
                    'url' => $fullUrl,
                    'request_params_string' => $requestParamsString,
                    'timestamp' => now()->format('Y-m-d H:i:s'),
                ],
            ], 500);
        }

        // Get HTTP status code
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        
        // Get the effective URL after following redirects
        $effectiveUrl = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
        
        curl_close($ch);

        // Check if request failed
        if ($httpCode >= 400) {
            return response()->json([
                'errors' => [
                    [
                        'errorCode' => 'AG' . str_pad($httpCode, 4, '0', STR_PAD_LEFT),
                        'errorMessage' => 'Request failed with HTTP status ' . $httpCode,
                    ],
                ],
                'request_data' => [
                    'url' => $fullUrl,
                    'request_params_string' => $requestParamsString,
                    'timestamp' => now()->format('Y-m-d H:i:s'),
                ],
                'response_data' => [
                    'status' => $httpCode,
                    'effective_url' => $effectiveUrl,
                ],
            ], $httpCode);
        }

        // Redirect to the authorization URL
        return Redirect::to($effectiveUrl);
    }

    /**
     * Encode URI component with special character handling
     * Similar to JavaScript's encodeURIComponent but with specific reverts
     */
    private function encodeURIComponent(string $query_param): string
    {
        $revert = [
            '%21' => '!',
            '%2A' => '*',
            '%27' => "'",
            '%28' => '( ',
            '%29' => ' )',
        ];

        return strtr(rawurlencode($query_param), $revert);
    }
}
