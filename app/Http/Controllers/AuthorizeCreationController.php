<?php

namespace App\Http\Controllers;

use App\Services\EgiroService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use App\Services\GpgService;
use Crypt_GPG;

class AuthorizeCreationController extends Controller
{
    public function createAuthorize(Request $request)
    {
        $egiroService = new EgiroService();
        $gpgService = new GpgService();
        $input_array = $egiroService->createAuthorize(
            $request->client_slug,
            'Creation',
            'Retail',
            $request->all()
        );
        $input_url_encoded_string = http_build_query($input_array, null, null, PHP_QUERY_RFC3986);
        $input_url_encoded_string = str_replace('%25', '%', $input_url_encoded_string);
        $input_url_encoded_string = str_replace('%20', ' ', $input_url_encoded_string);
        $signature = $egiroService->encodeURIComponent(
            $this->sign($input_url_encoded_string, $request->client_slug)
        );
        $signature = str_replace('%25', '%', $signature);
        $input_url_encoded_string .= '&signature=' . $signature;
        $apiUrl = config('abs.' . env('APP_ENV') . '.authorizeCreation.api_url');
        $fullUrl = $apiUrl . '?' . $input_url_encoded_string;

        $response = Http::get($apiUrl . '?' . $input_url_encoded_string);

        // Build comprehensive response
        $responseData = [
            'success' => $response->successful(),
            'status_code' => $response->status(),
            'message' => $response->successful() ? 'Authorization request processed successfully' : 'Authorization request failed',
            'timestamp' => now()->toIso8601String(),
            'request' => [
                'url' => $apiUrl,
                'full_url' => $fullUrl,
                'method' => 'GET',
                'parameters' => $input_array,
                'query_string' => $input_url_encoded_string,
            ],
            'response' => [
                'headers' => $response->headers(),
                'body' => $response->json() ?? $response->body(),
                'status' => $response->status(),
            ],
        ];

        // Add redirect information if it's a 302 redirect
        if ($response->status() === 302) {
            $location = $response->header('Location');
            $responseData['redirect'] = [
                'status' => 302,
                'location' => $location,
                'redirect_url' => $location,
            ];
            $responseData['message'] = 'Authorization redirect received';
        }

        // Add error information if request failed
        if ($response->failed()) {
            $responseData['errors'] = [
                [
                    'errorCode' => 'AG' . str_pad($response->status(), 4, '0', STR_PAD_LEFT),
                    'errorMessage' => 'Authorization request failed',
                    'details' => $response->body(),
                ],
            ];
        }

        return response()->json($responseData, $response->status() ?: 200);
    }

    public function sign($query_param, $client_slug)
    {
        try {
            // Create temporary isolated keyring directory
            $tempHome = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'gpg-' . bin2hex(random_bytes(6));
            if (!mkdir($tempHome, 0700, true) && !is_dir($tempHome)) {
                throw new \RuntimeException('Failed to create temp GNUPGHOME');
            }
            
            // Ensure the directory is writable
            if (!is_writable($tempHome)) {
                throw new \RuntimeException('Temp GNUPGHOME directory is not writable');
            }

            try {
                // Create Crypt_GPG instance with temporary keyring
                $gpg = new Crypt_GPG([
                    'homedir' => $tempHome,
                    'armor' => true  // Enable ASCII armor output
                ]);
                
                // Get configuration
                $privateKeyPath = config('clients.' . $client_slug . '.' . env('APP_ENV') . '.pgp.private_key');
                $passphrase = config('clients.' . $client_slug . '.' . env('APP_ENV') . '.pgp.passphrase');
                $keyFingerprint = config('clients.' . $client_slug . '.' . env('APP_ENV') . '.pgp.fingerprint');
                
                // Import the private key
                if (!is_readable($privateKeyPath)) {
                    throw new \RuntimeException('Private key not readable at ' . $privateKeyPath);
                }
                
                $armoredKey = file_get_contents($privateKeyPath);
                
                // Import the key using the public method
                $importResult = $gpg->importKey($armoredKey);
                
                if (empty($importResult['fingerprint'])) {
                    throw new \RuntimeException('Failed to import private key');
                }
                
                // Use provided fingerprint or the one from import
                $keyFingerprint = $keyFingerprint ?: $importResult['fingerprint'];
                
                // Add the signing key
                $gpg->addSignKey($keyFingerprint, $passphrase);
                
                // Sign the message with detached signature
                $signature = $gpg->sign($query_param, Crypt_GPG::SIGN_MODE_DETACHED);
                
                if (!$signature || stripos($signature, 'BEGIN PGP SIGNATURE') === false) {
                    throw new \RuntimeException('Signing returned invalid signature');
                }
                
                // Remove newlines and control characters from signature
                $signature = preg_replace('/[\r\n\t]/', '', $signature);
                $signature = preg_replace('/[\x00-\x1F\x7F]/', '', $signature);
                
                return $signature;
                
            } finally {
                // Cleanup temporary keyring
                try {
                    array_map('unlink', glob($tempHome . DIRECTORY_SEPARATOR . '*') ?: []);
                    @rmdir($tempHome);
                } catch (\Throwable $e) {
                    // Ignore cleanup errors
                }
            }
            
        } catch (\Exception $e) {
            throw new \RuntimeException('PGP signing failed: ' . $e->getMessage());
        }
    }
}
