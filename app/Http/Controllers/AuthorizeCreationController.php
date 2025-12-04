<?php

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use App\Services\GpgService;

class AuthorizeCreationController extends Controller
{
    public function createAuthorize(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'client_slug' => 'required|string',
            'applicantBankCode' => 'nullable|string|min:1|max:35',
            'boName' => 'required|string|max:140',
            'boTransactionRefNo' => 'nullable|string|min:35|max:35',
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
            return response()->json([
                'message' => 'Validation failed',
                'errors' => $validator->errors(),
            ], 422);
        }

        $clientSlug = $request->string('client_slug');
        $clientConfig = config('clients.' . $clientSlug);
        if (!is_array($clientConfig) || empty($clientConfig[env('APP_ENV')])) {
            return response()->json([
                'message' => 'Invalid client configuration',
            ], 422);
        }
        $clientConfig = $clientConfig[env('APP_ENV')];

        // Set backend-generated values
        $clientID = $request->input('clientID') ?: $clientConfig['client_id'];
        $requestType = $request->input('requestType') ?: 'Creation';
        
        // Generate boTransactionRefNo if not provided
        // Format: {clientID}{year_last_3_digits} {timestamp}{sequence}
        // Example: BOSIN1992001COR202 10303101010123456 (35 chars total)
        // clientID (15) + year (3) + space (1) + timestamp+sequence (16) = 35
        $boTransactionRefNo = $request->input('boTransactionRefNo');
        if (empty($boTransactionRefNo)) {
            $now = now();
            $yearLast3 = substr($now->format('Y'), -3); // Last 3 digits of year (e.g., 202 from 2024)
            $timestamp = $now->format('His'); // HHMMSS (6 chars)
            $microseconds = str_pad((string) $now->micro, 3, '0', STR_PAD_LEFT); // 3 chars
            $sequence = str_pad((string) rand(1000000, 9999999), 7, '0', STR_PAD_LEFT); // 7 chars
            // Total: clientID (15) + year (3) + space (1) + timestamp (6) + microseconds (3) + sequence (7) = 35
            $boTransactionRefNo = $clientID . $yearLast3 . ' ' . $timestamp . $microseconds . $sequence;
        }

        $pgpConfig = $clientConfig['pgp'] ?? [];
        if (empty($pgpConfig)) {
            return response()->json([
                'message' => 'Missing PGP configuration for client',
            ], 422);
        }

        $privateKeyPath = $pgpConfig['private_key'] ?? null;
        $passphrase = $pgpConfig['passphrase'] ?? '';
        $issuerFingerprint = $pgpConfig['fingerprint'] ?? null;

        if (!$privateKeyPath || !file_exists($privateKeyPath)) {
            return response()->json([
                'message' => 'Issuer private key not found',
            ], 422);
        }

        // Generate values if not provided in request
        $requestId = $request->input('requestID') ?: Str::uuid()->toString();
        $nonce = $request->input('nonce') ?: Str::random(20);
        $timestamp = $request->input('Timestamp') ?: (string) (time() * 1000);
        $signKeyAlias = $request->input('signKeyAlias') ?: ($clientConfig['sign_key_alias'] ?? '');

        // Build signature parameters in correct order, excluding empty optional fields
        $signatureParams = $this->buildSignatureParams($request, $requestId, $nonce, $timestamp, $signKeyAlias, $clientID, $boTransactionRefNo, $requestType);

        // Generate signature
        $signature = $this->generateSignature($signatureParams, $privateKeyPath, $passphrase, $issuerFingerprint);
        if ($signature === false) {
            return response()->json(['message' => 'Signature generation failed'], 500);
        }

        // Prepare request parameters for API call
        $requestParams = $this->buildRequestParams($request, $requestId, $nonce, $timestamp, $signKeyAlias, $signature, $clientID, $boTransactionRefNo, $requestType);

        // Make API request
        return $this->makeApiRequest($requestParams, $clientConfig, $requestId);
    }

    /**
     * Build signature parameters in correct order, excluding empty optional fields
     */
    private function buildSignatureParams(Request $request, string $requestId, string $nonce, string $timestamp, string $signKeyAlias, string $clientID, string $boTransactionRefNo, string $requestType): string
    {
        $params = [
            'clientID' => $clientID,
            'requestID' => $requestId,
            'nonce' => $nonce,
            'timestamp' => $timestamp,
            'signKeyAlias' => $signKeyAlias,
        ];

        // Add backend-set required parameters
        $params['boTransactionRefNo'] = $boTransactionRefNo;
        $params['requestType'] = $requestType;

        // Add optional parameters if not empty
        $optionalParams = ['applicantBankCode', 'boName', 'purpose', 'segment'];
        foreach ($optionalParams as $param) {
            $value = $request->input($param);
            if (!empty($value)) {
                $params[$param] = $value;
            }
        }

        return http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * Generate SHA256 signature using GPG service
     */
    private function generateSignature(string $signatureParams, string $privateKeyPath, string $passphrase, ?string $issuerFingerprint): string|false
    {
        try {
            $gpgService = new GpgService();

            $signature = $gpgService->signWithSHA256(
                $signatureParams,
                $privateKeyPath,
                $passphrase,
                $issuerFingerprint
            );

            return $signature;

        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * Build request parameters for API call
     */
    private function buildRequestParams(Request $request, string $requestId, string $nonce, string $timestamp, string $signKeyAlias, string $signature, string $clientID, string $boTransactionRefNo, string $requestType): array
    {
        $params = [
            'clientID' => $clientID,
            'requestID' => $requestId,
            'nonce' => $nonce,
            'timestamp' => $timestamp,
            'signKeyAlias' => $signKeyAlias,
            'signature' => $signature,
        ];

        // Add backend-set required parameters
        $params['boTransactionRefNo'] = $boTransactionRefNo;
        $params['requestType'] = $requestType;

        // Add optional parameters if provided
        $optionalParams = ['applicantBankCode', 'boName', 'purpose', 'segment'];
        foreach ($optionalParams as $param) {
            $value = $request->input($param);
            if (!empty($value)) {
                $params[$param] = $value;
            }
        }

        return $params;
    }

    /**
     * Make HTTP request to authorize creation API
     */
    private function makeApiRequest(array $requestParams, array $clientConfig, string $requestId): JsonResponse
    {
        $url = config('abs.' . env('APP_ENV') . '.authorizeCreation.api_url');

        $headers = [
            'Content-Type' => 'application/json',
            'clientID' => $clientConfig['client_id'],
            'requestID' => $requestId,
            'x-api-key' => $clientConfig['x-api-key'],
            'signKeyAlias' => $clientConfig['sign_key_alias'] ?? '',
            'aggregatorKeyAlias' => $clientConfig['aggregator_key_alias'],
        ];

        $http = Http::withOptions([
            'cert' => storage_path('app/certs/uobuat_sivren_org.crt'),
            'ssl_key' => storage_path('app/certs/uobuat_sivren_org.pem'),
        ])->withHeaders($headers);

        $response = $http->get($url, $requestParams);

        if ($response->failed()) {
            return response()->json([
                'request_data' => [
                    'url' => $url,
                    'headers' => $headers,
                    'request_params' => $requestParams,
                    'timestamp' => now()->format('Y-m-d H:i:s'),
                ],
                'response_data' => [
                    'status' => $response->status(),
                    'body' => $response->body(),
                ],
            ], $response->status() ?: 502);
        }

        return response()->json([
            'message' => 'Authorize creation successful',
            'data' => $response->json(),
        ]);
    }
}
