<?php

declare(strict_types=1);

namespace Ronu\AppContext\Tests\Unit;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Mockery;
use PHPOpenSourceSaver\JWTAuth\Contracts\JWTSubject;
use PHPOpenSourceSaver\JWTAuth\Factory;
use PHPOpenSourceSaver\JWTAuth\JWTAuth;
use PHPOpenSourceSaver\JWTAuth\Payload;
use Ronu\AppContext\Auth\Issuers\ContextTokenIssuer;
use Ronu\AppContext\Context\AppContext;
use Ronu\AppContext\Exceptions\AppContextException;
use Ronu\AppContext\Tests\TestCase;

class ContextTokenIssuerTest extends TestCase
{
    /**
     * Claims captured from each ->claims() call, in order: [0] access, [1] refresh.
     *
     * @var array<int, array<string, mixed>>
     */
    private array $capturedClaims = [];

    /**
     * TTL values pushed into the factory, in order.
     *
     * @var array<int, int>
     */
    private array $ttlWrites = [];

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    public function test_access_claims_bind_issuer_audience_tenant_and_device(): void
    {
        config()->set('app-context.jwt.issuer', 'https://api.example.com/');

        $issuer = new ContextTokenIssuer(Mockery::mock(JWTAuth::class));

        $context = AppContext::fromChannel('mobile', 'jwt')->withTenantId('tenant-7');
        $request = Request::create('http://example.com/mobile/login');
        $request->headers->set('X-Device-Id', 'device-abc');

        $claims = $issuer->accessClaims($context, $this->user(), $request);

        // Trailing slash is stripped so the value matches what JwtVerifier compares against.
        $this->assertSame('https://api.example.com', $claims['iss']);
        $this->assertSame('mobile', $claims['aud']);
        $this->assertSame('tenant-7', $claims['tid']);
        $this->assertSame('device-abc', $claims['did']);
    }

    public function test_device_id_falls_back_to_request_header_during_login(): void
    {
        $issuer = new ContextTokenIssuer(Mockery::mock(JWTAuth::class));

        // A login request carries no token, so AppContext::fromJwt() never ran and
        // the context has no device. The header is the only source available.
        $context = AppContext::fromChannel('mobile', 'jwt');
        $this->assertNull($context->getDeviceId());

        $request = Request::create('http://example.com/mobile/login');
        $request->headers->set('X-Device-Id', 'device-from-header');

        $claims = $issuer->accessClaims($context, $this->user(), $request);

        $this->assertSame('device-from-header', $claims['did']);
    }

    public function test_context_device_id_wins_over_header(): void
    {
        $issuer = new ContextTokenIssuer(Mockery::mock(JWTAuth::class));

        $context = AppContext::fromChannel('mobile', 'jwt')->withDeviceId('device-from-token');
        $request = Request::create('http://example.com/mobile/refresh');
        $request->headers->set('X-Device-Id', 'device-spoofed');

        $claims = $issuer->accessClaims($context, $this->user(), $request);

        $this->assertSame('device-from-token', $claims['did']);
    }

    public function test_tenant_resolution_prefers_context_then_header_then_user(): void
    {
        $issuer = new ContextTokenIssuer(Mockery::mock(JWTAuth::class));
        $request = Request::create('http://example.com/mobile/login');

        $fromContext = $issuer->accessClaims(
            AppContext::fromChannel('mobile', 'jwt')->withTenantId('ctx'),
            $this->user('user-tenant'),
            tap($request, fn (Request $r) => $r->headers->set('X-Tenant-Id', 'header'))
        );
        $this->assertSame('ctx', $fromContext['tid']);

        $fromHeader = $issuer->accessClaims(
            AppContext::fromChannel('mobile', 'jwt'),
            $this->user('user-tenant'),
            $request
        );
        $this->assertSame('header', $fromHeader['tid']);

        $bare = Request::create('http://example.com/mobile/login');
        $fromUser = $issuer->accessClaims(
            AppContext::fromChannel('mobile', 'jwt'),
            $this->user('user-tenant'),
            $bare
        );
        $this->assertSame('user-tenant', $fromUser['tid']);
    }

    public function test_issue_for_emits_both_token_and_access_token_with_the_same_value(): void
    {
        $issuer = new ContextTokenIssuer($this->jwt());

        $tokens = $issuer->issueFor($this->user(), $this->context(), $this->request());

        $this->assertSame('access.jwt', $tokens['token']);
        $this->assertSame('access.jwt', $tokens['access_token']);
        $this->assertSame('refresh.jwt', $tokens['refresh_token']);
        $this->assertSame('bearer', $tokens['token_type']);
    }

    /**
     * Regression guard: the refresh token used to be minted with a TTL five
     * times longer than the `refresh_expires_in` advertised to the client, so a
     * token the client discarded after 14 days stayed redeemable for 70. The
     * minted lifetime and the advertised one must be the same number.
     */
    public function test_refresh_token_lifetime_matches_the_advertised_value(): void
    {
        config()->set('app-context.jwt.refresh_ttl', 20160 * 60); // seconds

        $issuer = new ContextTokenIssuer($this->jwt());

        $tokens = $issuer->issueFor($this->user(), $this->context(), $this->request());

        // The TTL raised on the factory to mint the refresh token, in minutes.
        $mintedTtlMinutes = $this->ttlWrites[0];

        $this->assertSame(20160, $mintedTtlMinutes);
        $this->assertSame($mintedTtlMinutes * 60, $tokens['refresh_expires_in']);
    }

    public function test_refresh_ttl_is_converted_from_seconds_to_minutes(): void
    {
        config()->set('app-context.jwt.refresh_ttl', 3600); // 1 hour in seconds

        $issuer = new ContextTokenIssuer($this->jwt());
        $issuer->issueFor($this->user(), $this->context(), $this->request());

        $this->assertSame(60, $this->ttlWrites[0]);
    }

    public function test_factory_ttl_is_restored_after_minting(): void
    {
        config()->set('app-context.jwt.refresh_ttl', 20160 * 60);

        $issuer = new ContextTokenIssuer($this->jwt());
        $tokens = $issuer->issueFor($this->user(), $this->context(), $this->request());

        // Raised to the refresh TTL, then put back to the access TTL, so a later
        // caller on the same shared factory does not inherit the long lifetime.
        $this->assertSame([20160, 60], $this->ttlWrites);
        $this->assertSame(60 * 60, $tokens['expires_in']);
    }

    public function test_refresh_token_carries_the_binding_claims_of_the_access_token(): void
    {
        $issuer = new ContextTokenIssuer($this->jwt());
        $issuer->issueFor($this->user(), $this->context(), $this->request());

        $refreshClaims = $this->capturedClaims[1];

        $this->assertTrue($refreshClaims['refresh']);
        $this->assertSame('mobile', $refreshClaims['aud']);
        $this->assertSame('tenant-7', $refreshClaims['tid']);
        $this->assertSame('device-abc', $refreshClaims['did']);
    }

    public function test_a_user_model_that_is_not_a_jwt_subject_fails_with_an_actionable_error(): void
    {
        $issuer = new ContextTokenIssuer($this->jwt());

        $plainUser = new class implements Authenticatable
        {
            public function getAuthIdentifierName(): string
            {
                return 'id';
            }

            public function getAuthIdentifier(): int
            {
                return 1;
            }

            public function getAuthPasswordName(): string
            {
                return 'password';
            }

            public function getAuthPassword(): string
            {
                return 'secret';
            }

            public function getRememberToken(): string
            {
                return '';
            }

            public function setRememberToken($value): void {}

            public function getRememberTokenName(): string
            {
                return 'remember_token';
            }
        };

        $this->expectException(AppContextException::class);
        $this->expectExceptionMessageMatches('/must implement .*JWTSubject/');

        $issuer->issueFor($plainUser, $this->context(), $this->request());
    }

    /**
     * A JWTAuth double that records the claims it is handed and the TTLs written
     * to its factory, and returns a distinct token per fromUser() call.
     */
    private function jwt(): JWTAuth
    {
        $this->capturedClaims = [];
        $this->ttlWrites = [];

        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('get')->with('aud')->andReturn('mobile');
        $payload->shouldReceive('get')->with('tid')->andReturn('tenant-7');
        $payload->shouldReceive('get')->with('did')->andReturn('device-abc');

        $factory = Mockery::mock(Factory::class);
        $factory->shouldReceive('getTTL')->andReturn(60);
        $factory->shouldReceive('setTTL')->andReturnUsing(function (int $ttl) use ($factory) {
            $this->ttlWrites[] = $ttl;

            return $factory;
        });

        $jwt = Mockery::mock(JWTAuth::class);
        $jwt->shouldReceive('claims')->andReturnUsing(function (array $claims) use ($jwt) {
            $this->capturedClaims[] = $claims;

            return $jwt;
        });
        $jwt->shouldReceive('fromUser')->andReturn('access.jwt', 'refresh.jwt');
        $jwt->shouldReceive('setToken')->andReturn($jwt);
        $jwt->shouldReceive('getPayload')->andReturn($payload);
        $jwt->shouldReceive('factory')->andReturn($factory);

        return $jwt;
    }

    private function context(): AppContext
    {
        return AppContext::fromChannel('mobile', 'jwt')->withTenantId('tenant-7');
    }

    private function request(): Request
    {
        $request = Request::create('http://example.com/mobile/login');
        $request->headers->set('X-Device-Id', 'device-abc');

        return $request;
    }

    private function user(?string $tenantId = null): Authenticatable
    {
        return new class($tenantId) implements Authenticatable, JWTSubject
        {
            public function __construct(public ?string $tenant_id = null) {}

            public function getJWTIdentifier(): int
            {
                return 1;
            }

            /**
             * @return array<string, mixed>
             */
            public function getJWTCustomClaims(): array
            {
                return [];
            }

            public function getAuthIdentifierName(): string
            {
                return 'id';
            }

            public function getAuthIdentifier(): int
            {
                return 1;
            }

            public function getAuthPasswordName(): string
            {
                return 'password';
            }

            public function getAuthPassword(): string
            {
                return 'secret';
            }

            public function getRememberToken(): string
            {
                return '';
            }

            public function setRememberToken($value): void {}

            public function getRememberTokenName(): string
            {
                return 'remember_token';
            }
        };
    }
}
