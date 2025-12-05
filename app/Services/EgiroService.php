<?php

namespace App\Services;

use DateTime;
use Str;

class EgiroService
{
    public function createAuthorize($client_slug, $requestType, $segment, $input_array = [])
    {
        $input_array_obj = [
            'applicantBankCode' => config('clients.' . $client_slug . '.' . env('APP_ENV') . '.applicant_bank_code'),
            'boDDARefNo' => $this->createboDDARefNo(),
            // 'boDDARefNo' => $input_array['boDDARefNo'],
            'boName' => config('clients.' . $client_slug . '.' . env('APP_ENV') . '.bo_name'),
            'boTransactionRefNo' => $this->createTransactionReference($client_slug),
            // 'boTransactionRefNo' => $input_array['boTransactionRefNo'],
            'clientID' => config('clients.' . $client_slug . '.' . env('APP_ENV') . '.client_id'),
            'purpose' => 'LOAN',
            'requestID' => $this->createRequestID(),
            'requestType' => $requestType,
            'segment' => $segment,
            'nonce' => $this->createNonce(),
            'timestamp' => $this->createTimestamp(),
        ];

        return $input_array_obj;
    }

    public function createTransactionReference($client_slug)
    {
        $edda_client_id = config('clients.' . $client_slug . '.' . env('APP_ENV') . '.client_id');
        $date = new DateTime();
        $date_output_transref = $date->format('YmdHis');
        $six_digit_random_number = random_int(100000, 999999);
        $result = $edda_client_id . $date_output_transref . $six_digit_random_number;

        // FORMAT = id 15 chars + DateTime 14 chars + 6 digits
        return $result;
    }

    public function createRequestID()
    {
        return Str::uuid()->toString();
    }

    public function createNonce()
    {
        $number = '';
        for ($i = 0; $i < 20; $i++) {
            $min = $i == 0 ? 1 : 0;
            $number .= mt_rand($min, 9);
        }
        return $number;
    }

    public function createTimestamp()
    {
        return floor(microtime(true) * 1000);
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

    public function createboDDARefNo()
    {
        return str_replace('.', '', uniqid('eDDA', true));
    }

    public function getTimestamp()
    {
        $microtime = floatval(substr((string) microtime(), 1, 8));
        $rounded = round($microtime, 3);

        return date('Y-m-d\TH:i:s') .
            substr((string) $rounded, 1, strlen($rounded));
    }
}