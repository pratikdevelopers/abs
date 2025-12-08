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
        $input_url_encoded_string = http_build_query($input_array, null, null, PHP_QUERY_RFC3986);
        $input_url_encoded_string = str_replace('%25', '%', $input_url_encoded_string);
        $input_url_encoded_string = str_replace('%20', ' ', $input_url_encoded_string);

        $privateKeyPath = config('clients.' . $request->client_slug . '.' . env('APP_ENV') . '.pgp.private_key');
        $passphrase = config('clients.' . $request->client_slug . '.' . env('APP_ENV') . '.pgp.passphrase');
        $keyFingerprint = config('clients.' . $request->client_slug . '.' . env('APP_ENV') . '.pgp.fingerprint');

        $signature = $egiroService->encodeURIComponent(
            $egiroService->encodeURIComponent(
                $gpgService->sign($input_url_encoded_string, $privateKeyPath, $passphrase, $keyFingerprint)
            )
        );
        // $signature = $egiroService->encodeURIComponent(
        //     $gpgService->sign($input_url_encoded_string, config('clients.' . $request->client_slug . '.' . env('APP_ENV') . '.pgp.private_key'), config('clients.' . $request->client_slug . '.' . env('APP_ENV') . '.pgp.passphrase'))
        // );
        // $signature = $gpgService->sign($input_url_encoded_string, config('clients.' . $request->client_slug . '.' . env('APP_ENV') . '.pgp.private_key'), config('clients.' . $request->client_slug . '.' . env('APP_ENV') . '.pgp.passphrase'));

        $signature = str_replace('%25', '%', $signature);
        $input_url_encoded_string .= '&signature=' . $signature;
        $apiUrl = config('abs.' . env('APP_ENV') . '.authorizeCreation.api_url');
        $fullUrl = $apiUrl . '?' . $input_url_encoded_string;

        return Redirect::to($fullUrl);
    }
}
