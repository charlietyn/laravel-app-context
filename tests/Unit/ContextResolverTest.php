<?php

declare(strict_types=1);

namespace Ronu\AppContext\Tests\Unit;

use Ronu\AppContext\Context\ContextResolver;
use Illuminate\Http\Request;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpKernel\Exception\HttpException;

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

    private function createResolver(bool $denyByDefault = true): ContextResolver
    {
        return new ContextResolver(
            channelsConfig: $this->channelsConfig,
            baseDomain: 'example.com',
            denyByDefault: $denyByDefault
        );
    }

    private function createRequest(string $host, string $path): Request
    {
        $request = Request::create("http://{$host}/{$path}");
        $request->server->set('HTTP_HOST', $host);
        return $request;
    }

    public function test_resolves_by_path_on_localhost(): void
    {
        $resolver = $this->createResolver();
        $request = $this->createRequest('localhost', '/mobile/orders');

        // Mock app environment
        app()->detectEnvironment(fn () => 'local');

        $context = $resolver->resolve($request);

        $this->assertEquals('mobile', $context->appId);
        $this->assertEquals('jwt', $context->authMode);
    }

    public function test_resolves_admin_by_path(): void
    {
        $resolver = $this->createResolver();
        $request = $this->createRequest('localhost', '/api/users');

        app()->detectEnvironment(fn () => 'local');

        $context = $resolver->resolve($request);

        $this->assertEquals('admin', $context->appId);
    }

    public function test_resolves_partner_by_path(): void
    {
        $resolver = $this->createResolver();
        $request = $this->createRequest('localhost', '/partner/orders');

        app()->detectEnvironment(fn () => 'local');

        $context = $resolver->resolve($request);

        $this->assertEquals('partner', $context->appId);
        $this->assertEquals('api_key', $context->authMode);
    }

    public function test_has_channel(): void
    {
        $resolver = $this->createResolver();

        $this->assertTrue($resolver->hasChannel('mobile'));
        $this->assertTrue($resolver->hasChannel('admin'));
        $this->assertFalse($resolver->hasChannel('unknown'));
    }

    public function test_get_channel_config(): void
    {
        $resolver = $this->createResolver();

        $config = $resolver->getChannelConfig('mobile');

        $this->assertIsArray($config);
        $this->assertEquals('jwt', $config['auth_mode']);
        $this->assertContains('mobile', $config['subdomains']);
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

    public function test_throws_on_unknown_channel_when_deny_by_default(): void
    {
        $resolver = $this->createResolver(denyByDefault: true);
        $request = $this->createRequest('localhost', '/unknown/path');

        app()->detectEnvironment(fn () => 'local');

        $this->expectException(HttpException::class);
        $this->expectExceptionMessage('No valid channel detected');

        $resolver->resolve($request);
    }

    public function test_returns_fallback_when_not_deny_by_default(): void
    {
        $resolver = $this->createResolver(denyByDefault: false);
        $request = $this->createRequest('localhost', '/unknown/path');

        app()->detectEnvironment(fn () => 'local');

        $context = $resolver->resolve($request);

        $this->assertEquals('site', $context->appId);
        $this->assertEquals('anonymous', $context->authMode);
        $this->assertTrue($context->getMeta('fallback'));
    }
}
