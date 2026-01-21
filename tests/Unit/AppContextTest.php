<?php

declare(strict_types=1);

namespace Ronu\AppContext\Tests\Unit;

use Ronu\AppContext\Context\AppContext;
use PHPUnit\Framework\TestCase;

class AppContextTest extends TestCase
{
    public function test_can_create_from_channel(): void
    {
        $context = AppContext::fromChannel('mobile', 'jwt');

        $this->assertEquals('mobile', $context->appId);
        $this->assertEquals('jwt', $context->authMode);
        $this->assertNull($context->userId);
        $this->assertFalse($context->isAuthenticated());
    }

    public function test_can_create_from_jwt(): void
    {
        $context = AppContext::fromJwt('admin', [
            'sub' => '123',
            'aud' => 'admin',
            'scp' => ['admin:*', 'reports:read'],
            'tid' => 'tenant_1',
        ]);

        $this->assertEquals('admin', $context->appId);
        $this->assertEquals('jwt', $context->authMode);
        $this->assertEquals('123', $context->userId);
        $this->assertEquals('tenant_1', $context->tenantId);
        $this->assertTrue($context->isAuthenticated());
    }

    public function test_can_create_from_api_key(): void
    {
        $context = AppContext::fromApiKey(
            'partner',
            'client_123',
            ['partner:*', 'webhooks:send']
        );

        $this->assertEquals('partner', $context->appId);
        $this->assertEquals('api_key', $context->authMode);
        $this->assertEquals('client_123', $context->clientId);
        $this->assertTrue($context->isAuthenticated());
    }

    public function test_can_create_anonymous(): void
    {
        $context = AppContext::anonymous('site', ['public:read']);

        $this->assertEquals('site', $context->appId);
        $this->assertEquals('anonymous', $context->authMode);
        $this->assertFalse($context->isAuthenticated());
        $this->assertTrue($context->isAnonymous());
    }

    public function test_has_scope_exact_match(): void
    {
        $context = AppContext::fromJwt('admin', [
            'sub' => '1',
            'scp' => ['admin:users:read', 'admin:users:write'],
        ]);

        $this->assertTrue($context->hasScope('admin:users:read'));
        $this->assertTrue($context->hasScope('admin:users:write'));
        $this->assertFalse($context->hasScope('admin:users:delete'));
    }

    public function test_has_scope_wildcard_match(): void
    {
        $context = AppContext::fromJwt('admin', [
            'sub' => '1',
            'scp' => ['admin:*'],
        ]);

        $this->assertTrue($context->hasScope('admin:users:read'));
        $this->assertTrue($context->hasScope('admin:reports:export'));
        $this->assertFalse($context->hasScope('mobile:profile'));
    }

    public function test_has_capability_exact_match(): void
    {
        $context = AppContext::fromApiKey(
            'partner',
            'client_1',
            ['partner:orders:create', 'partner:orders:read']
        );

        $this->assertTrue($context->hasCapability('partner:orders:create'));
        $this->assertTrue($context->hasCapability('partner:orders:read'));
        $this->assertFalse($context->hasCapability('partner:orders:delete'));
    }

    public function test_has_capability_wildcard_match(): void
    {
        $context = AppContext::fromApiKey(
            'partner',
            'client_1',
            ['partner:*']
        );

        $this->assertTrue($context->hasCapability('partner:orders:create'));
        $this->assertTrue($context->hasCapability('partner:inventory:read'));
        $this->assertFalse($context->hasCapability('admin:users:read'));
    }

    public function test_has_capability_superadmin(): void
    {
        $context = AppContext::fromApiKey(
            'partner',
            'client_1',
            ['*']
        );

        $this->assertTrue($context->hasCapability('anything'));
        $this->assertTrue($context->hasCapability('admin:users:delete'));
    }

    public function test_has_all_scopes(): void
    {
        $context = AppContext::fromJwt('admin', [
            'sub' => '1',
            'scp' => ['admin:users:read', 'admin:users:write', 'admin:users:delete'],
        ]);

        $this->assertTrue($context->hasAllScopes(['admin:users:read', 'admin:users:write']));
        $this->assertFalse($context->hasAllScopes(['admin:users:read', 'admin:reports:export']));
    }

    public function test_has_any_scope(): void
    {
        $context = AppContext::fromJwt('admin', [
            'sub' => '1',
            'scp' => ['admin:users:read'],
        ]);

        $this->assertTrue($context->hasAnyScope(['admin:users:read', 'admin:reports:export']));
        $this->assertFalse($context->hasAnyScope(['admin:reports:export', 'admin:settings:write']));
    }

    public function test_requires_delegates_to_correct_method(): void
    {
        $jwtContext = AppContext::fromJwt('admin', [
            'sub' => '1',
            'scp' => ['admin:users:read'],
        ]);

        $apiKeyContext = AppContext::fromApiKey(
            'partner',
            'client_1',
            ['partner:orders:create']
        );

        $this->assertTrue($jwtContext->requires('admin:users:read'));
        $this->assertFalse($jwtContext->requires('admin:users:write'));

        $this->assertTrue($apiKeyContext->requires('partner:orders:create'));
        $this->assertFalse($apiKeyContext->requires('partner:orders:delete'));
    }

    public function test_get_identifier(): void
    {
        $jwtContext = AppContext::fromJwt('admin', ['sub' => 'user_123']);
        $apiKeyContext = AppContext::fromApiKey('partner', 'client_123', []);
        $anonContext = AppContext::anonymous('site');

        $this->assertEquals('user_123', $jwtContext->getIdentifier());
        $this->assertEquals('client_123', $apiKeyContext->getIdentifier());
        $this->assertNull($anonContext->getIdentifier());
    }

    public function test_get_rate_limit_key(): void
    {
        $jwtContext = (AppContext::fromJwt('admin', ['sub' => '123']))->withIpAddress('1.2.3.4');
        $apiKeyContext = (AppContext::fromApiKey('partner', 'client_1', []))->withIpAddress('1.2.3.4');
        $anonContext = (AppContext::anonymous('site'))->withIpAddress('1.2.3.4');

        $this->assertEquals('admin|user:123', $jwtContext->getRateLimitKey());
        $this->assertEquals('partner|client:client_1', $apiKeyContext->getRateLimitKey());
        $this->assertEquals('site|ip:1.2.3.4', $anonContext->getRateLimitKey());
    }

    public function test_to_array(): void
    {
        $context = AppContext::fromJwt('admin', [
            'sub' => '123',
            'scp' => ['admin:*'],
            'tid' => 'tenant_1',
        ]);

        $array = $context->toArray();

        $this->assertArrayHasKey('request_id', $array);
        $this->assertEquals('admin', $array['app_id']);
        $this->assertEquals('jwt', $array['auth_mode']);
        $this->assertEquals('123', $array['user_id']);
        $this->assertEquals('tenant_1', $array['tenant_id']);
        $this->assertEquals(['admin:*'], $array['scopes']);
        $this->assertTrue($array['is_authenticated']);
    }

    public function test_to_log_context(): void
    {
        $context = (AppContext::fromJwt('admin', [
            'sub' => '123',
            'tid' => 'tenant_1',
        ]))->withIpAddress('1.2.3.4');

        $logContext = $context->toLogContext();

        $this->assertArrayHasKey('request_id', $logContext);
        $this->assertEquals('admin', $logContext['app_id']);
        $this->assertEquals('123', $logContext['user_id']);
        $this->assertEquals('tenant_1', $logContext['tenant_id']);
        $this->assertEquals('1.2.3.4', $logContext['ip']);
        // Should NOT have scopes (compact format)
        $this->assertArrayNotHasKey('scopes', $logContext);
    }

    public function test_with_meta(): void
    {
        $context = AppContext::fromChannel('mobile', 'jwt');
        $newContext = $context->withMeta(['custom_key' => 'custom_value']);

        // Original unchanged
        $this->assertNull($context->getMeta('custom_key'));

        // New has value
        $this->assertEquals('custom_value', $newContext->getMeta('custom_key'));
    }

    public function test_request_id_is_ulid(): void
    {
        $context = AppContext::fromChannel('mobile', 'jwt');

        // ULID is 26 characters
        $this->assertEquals(26, strlen($context->requestId));
    }
}
