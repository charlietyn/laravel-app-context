<?php

declare(strict_types=1);

namespace Ronu\AppContext\Tests\Unit;

use Ronu\AppContext\Context\ContextResolver;
use Ronu\AppContext\Tests\TestCase;
use Illuminate\Http\Request;

class ContextResolverTest extends TestCase
{
    private array $channelsConfig;

    protected function setUp(): void
    {
        parent::setUp();

        $this->channelsConfig = [
            'mobile' => [
                'subdomains' => ['mobile', 'm'],
                'path_prefixes' => ['/mobile'],
                'auth_mode' => 'jwt',
            ],
            'admin' => [
                'subdomains' => ['admin'],
                'path_prefixes' => ['/api'],
                'auth_mode' => 'jwt',
            ],
            'site' => [
                'subdomains' => ['www', null],
                'path_prefixes' => ['/site'],
                'auth_mode' => 'jwt_or_anonymous',
            ],
            'partner' => [
                'subdomains' => ['partners'],
                'path_prefixes' => ['/partner'],
                'auth_mode' => 'api_key',
            ],
        ];
    }

    private function createResolver(array $overrides = []): ContextResolver
    {
        $config = array_merge([
            'channels' => $this->channelsConfig,
            'domain' => 'example.com',
            'detection_strategy' => 'path',
            'deny_by_default' => true,
        ], $overrides);

        return new ContextResolver($config);
    }

    private function createRequest(string $host, string $path): Request
    {
        $request = Request::create("http://{$host}/{$path}");
        $request->server->set('HTTP_HOST', $host);

        return $request;
    }

    public function test_resolves_by_path(): void
    {
        $resolver = $this->createResolver();
        $request = $this->createRequest('localhost', '/mobile/orders');

        $context = $resolver->resolve($request);

        $this->assertEquals('mobile', $context?->getAppId());
        $this->assertEquals('jwt', $context?->getAuthMode());
    }

    public function test_resolves_admin_by_path(): void
    {
        $resolver = $this->createResolver();
        $request = $this->createRequest('localhost', '/api/users');

        $context = $resolver->resolve($request);

        $this->assertEquals('admin', $context?->getAppId());
    }

    public function test_resolves_partner_by_path(): void
    {
        $resolver = $this->createResolver();
        $request = $this->createRequest('localhost', '/partner/orders');

        $context = $resolver->resolve($request);

        $this->assertEquals('partner', $context?->getAppId());
        $this->assertEquals('api_key', $context?->getAuthMode());
    }

    public function test_get_channel_config_returns_null_for_unknown(): void
    {
        $resolver = $this->createResolver();

        $this->assertNull($resolver->getChannelConfig('unknown'));
    }

    public function test_get_channels(): void
    {
        $resolver = $this->createResolver();

        $channels = $resolver->getChannels();

        $this->assertArrayHasKey('mobile', $channels);
        $this->assertArrayHasKey('admin', $channels);
        $this->assertArrayHasKey('site', $channels);
        $this->assertArrayHasKey('partner', $channels);
    }

    public function test_returns_null_for_unknown_channel(): void
    {
        $resolver = $this->createResolver();
        $request = $this->createRequest('localhost', '/unknown/path');

        $context = $resolver->resolve($request);

        $this->assertNull($context);
    }
}
