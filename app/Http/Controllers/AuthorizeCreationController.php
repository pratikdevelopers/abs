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
use Redirect;

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
        // Build query string - do NOT encode for signature generation (as per PDF spec)
        // Build manually to maintain exact parameter order and avoid encoding issues
        $queryParts = [];
        foreach ($input_array as $key => $value) {
            $queryParts[] = $key . '=' . $value;
        }
        $input_url_encoded_string = implode('&', $queryParts);
        
        // Note: No URL encoding is required for Query Parameters to create the Signature (per PDF spec)
        // $signature = $egiroService->encodeURIComponent(
        //     $egiroService->encodeURIComponent(
        //         $gpgService->sign($input_url_encoded_string, config('clients.' . $request->client_slug . '.' . env('APP_ENV') . '.pgp.private_key'), config('clients.' . $request->client_slug . '.' . env('APP_ENV') . '.pgp.passphrase'))
        //     )
        // );
        // Generate signature on unencoded query string
        $signature = $egiroService->encodeURIComponent(
            $gpgService->sign($input_url_encoded_string, config('clients.' . $request->client_slug . '.' . env('APP_ENV') . '.pgp.private_key'), config('clients.' . $request->client_slug . '.' . env('APP_ENV') . '.pgp.passphrase'))
        );
        $signature = str_replace('%25', '%', $signature);
        
        // Build final URL with properly encoded parameters
        // First, encode all parameters except signature
        $encodedParams = http_build_query($input_array, '', '&', PHP_QUERY_RFC3986);
        
        // Add signature (already encoded, so append directly)
        $finalQueryString = $encodedParams . '&signature=' . $signature;
        
        // Apply special encoding rules as per API specification
        // Replace %25 (encoded %) with actual %
        $finalQueryString = str_replace('%25', '%', $finalQueryString);
        // Replace %20 (encoded space) with actual space  
        $finalQueryString = str_replace('%20', ' ', $finalQueryString);
        
        $apiUrl = config('abs.' . env('APP_ENV') . '.authorizeCreation.api_url');
        $fullUrl = $apiUrl . '?' . $finalQueryString;

        $response_url = $this->cURL_eDDA_Create($fullUrl);

        return $response_url;

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

    public function cURL_eDDA_Create($url)
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url); // set url
        curl_setopt($ch, CURLOPT_HEADER, true); // get header
        curl_setopt($ch, CURLOPT_NOBODY, true); // do not include response body
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); // do not show in browser the response
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true); // follow any redirects
        curl_exec($ch);
        $new_url = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL); // extract the url from the header response

        return $new_url;
    }

    public function sign($query_param, $client_slug)
    {
        $gpg = new Crypt_GPG([
            'homedir' => sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'gpg-' . bin2hex(random_bytes(6)),
            'armor' => true,
        ]);
        $egiroService = new EgiroService();
        $gpg->addSignKey(config('clients.' . $client_slug . '.' . env('APP_ENV') . '.pgp.fingerprint'), config('clients.' . $client_slug . '.' . env('APP_ENV') . '.pgp.passphrase'));
        $signature = $egiroService->encodeURIComponent(
            $gpg->sign($query_param, config('clients.' . $client_slug . '.' . env('APP_ENV') . '.pgp.private_key'), config('clients.' . $client_slug . '.' . env('APP_ENV') . '.pgp.passphrase'))
        );

        return $signature;
    }
}
