<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use App\Services\GpgService;

class BankController extends Controller
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
        $clientConfig = config('clients.' . $clientSlug);
        if (!is_array($clientConfig) || empty($clientConfig[env('APP_ENV')])) {
            return response()->json([
                'message' => 'Invalid client configuration',
            ], 422);
        }
        $clientConfig = $clientConfig[env('APP_ENV')];

        $requestId = Str::uuid()->toString();
        $nonce = Str::random(20);
        $timestamp = (string) (strtotime('2024-01-01 00:00:00') * 1000);

        $input_array_obj = [
            'clientID' => $clientConfig['client_id'],
            'requestID' => $requestId,
            'nonce' => $nonce,
            'timestamp' => $timestamp,
        ];

        $gpgService = new GpgService();
        $requestParams = http_build_query($input_array_obj, '', '&', PHP_QUERY_RFC3986);

        try {
            $privateKeyPath = config('clients.' . $clientSlug . '.' . env('APP_ENV') . '.pgp.private_key');
            $passphrase = config('clients.' . $clientSlug . '.' . env('APP_ENV') . '.pgp.passphrase');
            $keyFingerprint = config('clients.' . $clientSlug . '.' . env('APP_ENV') . '.pgp.fingerprint');

            $signature = $this->encodeURIComponent(
                $gpgService->sign($requestParams, $privateKeyPath, $passphrase, $keyFingerprint)
            );
            $signature = str_replace('%25', '%', $signature);
            $requestParams .= '&signature=' . $signature;

        } catch (\Throwable $e) {
            return response()->json([
                'message' => 'Signature generation failed',
            ], 500);
        }

        $response = Http::get(config('abs.' . env('APP_ENV') . '.banks.api_url'), $requestParams);

        if ($response->failed()) {
            return response()->json([
                'message' => 'Upstream request failed',
                'error' => $response->body(),
            ], $response->status() ?: 502);
        }

        return response()->json([
            'message' => 'Bank list',
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
