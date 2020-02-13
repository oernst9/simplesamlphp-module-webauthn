<?php

$config = [		'store' => [
			'webauthn:Database',
			'database.dsn' => 'mysql:host=localhost;dbname=fido2',
			'database.username' => 'webauthn',
			'database.password' => 'password',
			],

        'attrib_username' => 'urn:oid:0.9.2342.19200300.100.1.1',
        'attrib_displayname' => 'urn:oid:2.16.840.1.113730.3.1.241',
		'scope' => 'ip-78-128-251-71.flt.cloud.muni.cz',
		'request_tokenmodel' => true,
		'default_enable' => false,
		'force' => false,
		'attrib_toggle' => 'toggle',
		'use_database' => false,
        'use_inflow_registration' => false,
		];
