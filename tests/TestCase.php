<?php

declare(strict_types=1);

namespace Ronu\AppContext\Tests;

use Ronu\AppContext\AppContextServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    protected function setUp(): void
    {
        parent::setUp();
    }

    protected function getPackageProviders($app): array
    {
        return [
            AppContextServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp($app): void
    {
        // Setup default database
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        // Setup app-context config
        $app['config']->set('app-context.deny_by_default', true);
        $app['config']->set('app-context.domain', 'example.com');
        $app['config']->set('app-context.detection_strategy', 'auto');

        $app['config']->set('app-context.channels', [
            'mobile' => [
                'subdomains' => ['mobile', 'm'],
                'path_prefixes' => ['/mobile'],
                'auth_mode' => 'jwt',
                'allowed_scopes' => ['mobile:*'],
            ],
            'admin' => [
                'subdomains' => ['admin'],
                'path_prefixes' => ['/api'],
                'auth_mode' => 'jwt',
                'allowed_scopes' => ['admin:*'],
            ],
            'site' => [
                'subdomains' => ['www', null],
                'path_prefixes' => ['/site'],
                'auth_mode' => 'jwt_or_anonymous',
                'allowed_scopes' => ['site:*'],
            ],
            'partner' => [
                'subdomains' => ['partners'],
                'path_prefixes' => ['/partner'],
                'auth_mode' => 'api_key',
                'allowed_capabilities' => ['partner:*'],
            ],
        ]);

        $app['config']->set('app-context.jwt', [
            'algorithm' => 'HS256',
            'allowed_algorithms' => ['HS256', 'RS256'],
            'verify_iss' => false,
            'verify_aud' => true,
            'blacklist_enabled' => true,
        ]);

        $app['config']->set('app-context.api_key', [
            'hash_algorithm' => 'bcrypt',
            'headers' => [
                'client_id' => 'X-Client-Id',
                'api_key' => 'X-Api-Key',
            ],
        ]);
    }
}
