<?php

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

class EddaStatusController extends Controller
{
    /**
     * Get the status of an eDDA by Transaction Reference Number
     */
    public function getStatus(Request $request): JsonResponse
    {
        // Validate query parameters
        $validator = Validator::make($request->all(), [
            'client_slug' => 'required|string',
            'boTransactionRefNo' => 'required|string|min:35|max:35',
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
        $requestId = Str::uuid()->toString();
        $url = config('abs.' . env('APP_ENV') . '.eddaStatus.api_url');

        // Build headers as per API specification
        $headers = [
            'Accept' => 'application/json',
            'clientID' => $clientConfig['client_id'],
            'requestID' => $requestId,
            'x-api-key' => $clientConfig['x-api-key'],
            'aggregatorKeyAlias' => $clientConfig['aggregator_key_alias'],
        ];

        // Add optional signKeyAlias if available
        if (!empty($clientConfig['sign_key_alias'])) {
            $headers['signKeyAlias'] = $clientConfig['sign_key_alias'];
        }

        // Prepare query parameters
        $queryParams = [
            'boTransactionRefNo' => $request->input('boTransactionRefNo'),
        ];

        // Make GET request with mutual TLS
        $http = Http::withOptions([
            'cert' => storage_path('app/certs/uobuat_sivren_org.crt'),
            'ssl_key' => storage_path('app/certs/uobuat_sivren_org.pem'),
        ])->withHeaders($headers);

        $response = $http->get($url, $queryParams);

        if ($response->failed()) {
            return response()->json([
                'request_data' => [
                    'url' => $url,
                    'headers' => $headers,
                    'query_params' => $queryParams,
                    'timestamp' => now()->format('Y-m-d H:i:s'),
                ],
                'response_data' => [
                    'status' => $response->status(),
                    'body' => $response->body(),
                ],
            ], $response->status() ?: 502);
        }

        return response()->json([
            'message' => 'eDDA status retrieved successfully',
            'data' => $response->json(),
        ]);
    }
}


