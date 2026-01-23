<?php

declare(strict_types=1);

namespace Ronu\AppContext\Tests\Unit;

use Ronu\AppContext\Auth\Authenticators\JwtAuthenticator;
use Ronu\AppContext\Auth\Verifiers\JwtVerifier;
use Ronu\AppContext\Context\AppContext;
use Ronu\AppContext\Exceptions\AuthenticationException;
use Ronu\AppContext\Tests\TestCase;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Http\Request;
use Mockery;
use PHPOpenSourceSaver\JWTAuth\JWTAuth;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenInvalidException;

class JwtAuthenticatorTest extends TestCase
{
    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    public function test_jwt_or_anonymous_without_token_uses_public_scopes(): void
    {
        $jwtAuth = Mockery::mock(JWTAuth::class);
        $cache = Mockery::mock(CacheRepository::class);

        $verifier = new JwtVerifier($jwtAuth, $cache, [
            'allowed_algorithms' => ['HS256'],
            'verify_iss' => false,
            'verify_aud' => false,
            'token_sources' => ['header'],
        ]);

        $authenticator = new JwtAuthenticator($verifier, [
            'public_routes' => [],
            'channels' => [
                'site' => [
                    'public_scopes' => ['public:read', 'catalog:browse'],
                    'features' => [
                        'allow_anonymous' => true,
                    ],
                ],
            ],
        ]);

        $request = Request::create('http://example.com/site');
        $context = AppContext::fromChannel('site', 'jwt_or_anonymous');

        $enriched = $authenticator->authenticate($request, $context);

        $this->assertEquals(['public:read', 'catalog:browse'], $enriched->getScopes());
    }

    public function test_invalid_token_throws_when_anonymous_fallback_disabled(): void
    {
        $jwtAuth = Mockery::mock(JWTAuth::class);
        $jwtAuth->shouldReceive('setToken')->andReturnSelf();
        $jwtAuth->shouldReceive('getPayload')->andThrow(new TokenInvalidException('invalid'));

        $cache = Mockery::mock(CacheRepository::class);

        $verifier = new JwtVerifier($jwtAuth, $cache, [
            'allowed_algorithms' => ['HS256'],
            'verify_iss' => false,
            'verify_aud' => false,
            'token_sources' => ['header'],
        ]);

        $authenticator = new JwtAuthenticator($verifier, [
            'public_routes' => [],
            'channels' => [
                'site' => [
                    'anonymous_on_invalid_token' => false,
                    'features' => [
                        'allow_anonymous' => true,
                    ],
                ],
            ],
        ]);

        $request = Request::create('http://example.com/site');
        $request->headers->set('Authorization', 'Bearer ' . $this->makeToken());
        $context = AppContext::fromChannel('site', 'jwt_or_anonymous');

        $this->expectException(AuthenticationException::class);

        $authenticator->authenticate($request, $context);
    }

    public function test_invalid_token_can_fall_back_to_anonymous_when_enabled(): void
    {
        $jwtAuth = Mockery::mock(JWTAuth::class);
        $jwtAuth->shouldReceive('setToken')->andReturnSelf();
        $jwtAuth->shouldReceive('getPayload')->andThrow(new TokenInvalidException('invalid'));

        $cache = Mockery::mock(CacheRepository::class);

        $verifier = new JwtVerifier($jwtAuth, $cache, [
            'allowed_algorithms' => ['HS256'],
            'verify_iss' => false,
            'verify_aud' => false,
            'token_sources' => ['header'],
        ]);

        $authenticator = new JwtAuthenticator($verifier, [
            'public_routes' => [],
            'channels' => [
                'site' => [
                    'public_scopes' => ['public:read'],
                    'anonymous_on_invalid_token' => true,
                    'features' => [
                        'allow_anonymous' => true,
                    ],
                ],
            ],
        ]);

        $request = Request::create('http://example.com/site');
        $request->headers->set('Authorization', 'Bearer ' . $this->makeToken());
        $context = AppContext::fromChannel('site', 'jwt_or_anonymous');

        $enriched = $authenticator->authenticate($request, $context);

        $this->assertEquals(['public:read'], $enriched->getScopes());
        $this->assertEquals('anonymous', $enriched->getAuthMode());
    }

    private function makeToken(): string
    {
        $header = base64_encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
        $payload = base64_encode(json_encode(['sub' => '1']));

        return "{$header}.{$payload}.signature";
    }
}
