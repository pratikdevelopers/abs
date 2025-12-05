<?php

return [
    'soonsengcredit' => [
        'uat' => [
            'applicant_bank_code' => 'UOVBSGSGXXX',
            'bo_name' => 'SOON SENG CREDIT PTE LTD',
            'client_id' => 'BOSOO1887G01SOO',
            'x-api-key' => '1135a09c-b0db-4c95-93e7-b8eb8f3e63e2',
            'aggregator_key_alias' => 'AGGREGATOR5_UAT_PGP_PRIMARY',
            'sign_key_alias' => 'BOSOO201901887G_BU01_UAT_PGP_PUBLICKEY_PRIMARY_570832',
            'pgp' => [
                'issuer_id' => 'uobuat@sivren.com',
                'passphrase' => 'pgpss2025',
                'fingerprint' => '4CA8AD8EAA3A29E33765A659326E636F574ACFDA',
                'issuer_key_id' => '326E636F574ACFDA',
                'public_key' => storage_path('app/pgp/public.asc'),
                'private_key' => storage_path('app/pgp/private.asc'),
            ]
        ],
        'production' => [
            'applicant_bank_code' => '',
            'bo_name' => '',
            'client_id' => '',
            'x-api-key' => '',
            'aggregator_key_alias' => '',
            'sign_key_alias' => '',
            'pgp' => [
                'issuer_id' => '',
                'passphrase' => '',
                'fingerprint' => '',
                'issuer_key_id' => '',
                'public_key' => storage_path('app/pgp/public.asc'),
                'private_key' => storage_path('app/pgp/private.asc'),
            ]
        ],
    ],
    'galaxycredit' => [
        'uat' => [
            'applicant_bank_code' => 'BOGAL',
            'bo_name' => 'GALAXY CREDIT PTE. LTD.',
            'client_id' => 'BOGAL0194M01GAL',
            'x-api-key' => '9523ef31-107d-4242-9139-6360337bd8d2',
            'aggregator_key_alias' => 'AGGREGATOR5_UAT_PGP_PRIMARY',
            'sign_key_alias' => '',
            'pgp' => [
                'issuer_id' => 'uobuat@sivren.com',
                'passphrase' => 'uatuob2025',
                'fingerprint' => '40044FCBD111BD3ADEBA4447BF7AC39F6DC6A2A2',
                'issuer_key_id' => 'BF7AC39F6DC6A2A2',
                'public_key' => storage_path('app/pgp/public.asc'),
                'private_key' => storage_path('app/pgp/private.asc'),
            ]
        ],
        'production' => [
            'applicant_bank_code' => '',
            'bo_name' => '',
            'client_id' => '',
            'x-api-key' => '',
            'aggregator_key_alias' => '',
            'sign_key_alias' => '',
            'pgp' => [
                'issuer_id' => '',
                'passphrase' => '',
                'fingerprint' => '',
                'issuer_key_id' => '',
                'public_key' => storage_path('app/pgp/public.asc'),
                'private_key' => storage_path('app/pgp/private.asc'),
            ]
        ],
    ],
    '96bmcredit' => [
        'uat' => [
            'applicant_bank_code' => 'UOVBSGS0XXX',
            'bo_name' => '96BM CREDIT PTE LTD',
            'client_id' => 'BO96B2532M0196B',
            'x-api-key' => 'c11287ac-1ca3-445b-a9ae-1bae619fc987',
            'aggregator_key_alias' => 'AGGREGATOR5_UAT_PGP_PRIMARY',
            'sign_key_alias' => 'BO96B201832532M_BU01_UAT_PGP_PUBLICKEY_PRIMARY_219015',
            'pgp' => [
                'issuer_id' => 'uobuat@sivren.com',
                'passphrase' => 'pgpss2025',
                'fingerprint' => '4CA8AD8EAA3A29E33765A659326E636F574ACFDA',
                'issuer_key_id' => '326E636F574ACFDA',
                'public_key' => storage_path('app/pgp/public.asc'),
                'private_key' => storage_path('app/pgp/private.asc'),
            ]
        ],
        'production' => [
            'applicant_bank_code' => '',
            'bo_name' => '',
            'client_id' => '',
            'x-api-key' => '',
            'aggregator_key_alias' => '',
            'sign_key_alias' => '',
            'pgp' => [
                'issuer_id' => '',
                'passphrase' => '',
                'fingerprint' => '',
                'issuer_key_id' => '',
                'public_key' => storage_path('app/pgp/public.asc'),
                'private_key' => storage_path('app/pgp/private.asc'),
            ]
        ],
    ],
    'moneywise-credit' => [
        'uat' => [
            'applicant_bank_code' => 'BOMON',
            'bo_name' => 'MONEYWISE CREDIT PTE. LTD.',
            'client_id' => 'BOMON8326M01MON',
            'x-api-key' => 'b972e3f5-afe5-4669-981c-17040a5f19a9',
            'aggregator_key_alias' => 'AGGREGATOR5_UAT_PGP_PRIMARY',
            'sign_key_alias' => 'BOMON201838326M_BU01_UAT_PGP_PUBLICKEY_PRIMARY_607963',
            'pgp' => [
                'issuer_id' => 'uobuat@sivren.com',
                'passphrase' => 'pgpss2025',
                'fingerprint' => '4CA8AD8EAA3A29E33765A659326E636F574ACFDA',
                'issuer_key_id' => '326E636F574ACFDA',
                'public_key' => storage_path('app/pgp/public.asc'),
                'private_key' => storage_path('app/pgp/private.asc'),
            ]
        ],
        'production' => [
            'applicant_bank_code' => '',
            'bo_name' => 'MONEYWISE CREDIT PTE. LTD.',
            'client_id' => '',
            'x-api-key' => '',
            'aggregator_key_alias' => '',
            'sign_key_alias' => '',
            'pgp' => [
                'issuer_id' => '',
                'passphrase' => '',
                'fingerprint' => '',
                'issuer_key_id' => '',
                'public_key' => storage_path('app/pgp/public.asc'),
                'private_key' => storage_path('app/pgp/private.asc'),
            ]
        ],
    ],
];