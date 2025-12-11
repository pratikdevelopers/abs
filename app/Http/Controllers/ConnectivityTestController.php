<?php

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use App\Services\GpgService;

class ConnectivityTestController extends Controller
{
    public function index(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'client_slug' => 'required|string',
        ]);
        if ($validator->fails()) {
            return response()->json([
                'message' => 'Validation failed',
                'errors' => $validator->errors(),
            ], 422);
        }
        $clientSlug = $request->string('client_slug');
        $clientConfig = config('egiro_clients.' . $clientSlug);
        if (!is_array($clientConfig) || empty($clientConfig[env('APP_ENV')])) {
            return response()->json([
                'message' => 'Invalid client configuration',
            ], 422);
        }
        $clientConfig = $clientConfig[env('APP_ENV')];
        $requestId = Str::uuid()->toString();
        $url = config('abs.' . env('APP_ENV') . '.connectivityTest.api_url');

        $headers = [
            'Content-Type' => 'text/plain',
            // 'Accept' => 'application/json',
            'clientID' => $clientConfig['client_id'],
            'requestID' => $requestId,
            'x-api-key' => $clientConfig['x-api-key'],
            'signKeyAlias' => $clientConfig['sign_key_alias'] ?? '',
            'aggregatorKeyAlias' => $clientConfig['aggregator_key_alias'],
        ];

        $requestBody = [
            'message' => 'This is a test message',
        ];

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

        $gpgService = new GpgService();
        // The actual JSON payload as per eGIRO API specifications
        $unsignedPayload = json_encode($requestBody, JSON_UNESCAPED_SLASHES);

        $ciphertext = null;

        try {
            $aggregatorPublicKeyPath = storage_path('app/pgp/aggregator_public.asc');

            if (!file_exists($aggregatorPublicKeyPath)) {
                return response()->json([
                    'message' => 'Aggregator public key not found',
                ], 422);
            }

            // One pass operation: Sign the payload first using Private Key, then encrypt using eGIRO public key
            // This follows the PGP encryption method requirement: "One pass operation to be performed for sign and encrypt"
            $ciphertext = $gpgService->signAndEncrypt(
                $unsignedPayload,
                $privateKeyPath,
                $aggregatorPublicKeyPath,
                $passphrase,
                $issuerFingerprint
            );

        } catch (\Throwable $e) {
            return response()->json([
                'message' => 'Failed to sign and encrypt request body',
                'error' => $e->getMessage(),
            ], 500);
        }

        $http = Http::withOptions([
            'cert' => storage_path('app/certs/uobuat_sivren_org.crt'),
            'ssl_key' => storage_path('app/certs/uobuat_sivren_org.pem'),
        ])->withHeaders($headers);

        $response = $http->withBody($ciphertext, 'text/plain')->post($url);
        if ($response->failed()) {
            return response()->json([
                'request_data' => [
                    'url' => $url,
                    'headers' => $headers,
                    'original_request_body' => $requestBody,
                    'encrypted_signed_request_body' => $ciphertext,
                    'timestamp' => now()->format('Y-m-d H:i:s'),
                ],
                'response_data' => [
                    'status' => $response->status(),
                    'body' => $response->body(),
                ],
            ], $response->status() ?: 502);
        }
        return response()->json([
            'message' => 'Connectivity test',
            'data' => $response->json(),
        ]);
    }

    public function encodeURIComponent($query_param)
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