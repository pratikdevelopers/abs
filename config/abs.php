<?php

return [
    'uat' => [
        'connectivityTest' => [
            'api_url' => 'https://uat-api-secure.eddanow.sg/api/v1/util/connectivityTest',
            'method' => 'POST',
        ],
        'banks' => [
            'api_url' => 'https://uat-api.eddanow.sg/api/v1/bank/banks',
            'method' => 'GET',
        ],
        'authorizeCreation' => [
            'api_url' => 'https://uat-api.eddanow.sg/api/v1/edda/authorize/creation',
            'method' => 'GET',
        ],
        'eddaStatus' => [
            'api_url' => 'https://uat-api-secure.eddanow.sg/api/v1/edda/status',
            'method' => 'GET',
        ],
    ],
    'production' => [
        'connectivityTest' => [
            'api_url' => 'https://api-secure.eddanow.sg/api/v1/util/connectivityTest',
            'method' => 'POST',
        ],
        'banks' => [
            'api_url' => 'https://api.eddanow.sg/api/v1/bank/banks',
            'method' => 'GET',
        ],
        'authorizeCreation' => [
            'api_url' => 'https://api.eddanow.sg/api/v1/edda/authorize/creation',
            'method' => 'GET',
        ],
        'eddaStatus' => [
            'api_url' => 'https://api-secure.eddanow.sg/api/v1/edda/status',
            'method' => 'GET',
        ],
    ],
];