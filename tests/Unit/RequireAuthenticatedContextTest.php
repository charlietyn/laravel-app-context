<?php

declare(strict_types=1);

namespace Ronu\AppContext\Tests\Unit;

use Ronu\AppContext\Context\AppContext;
use Ronu\AppContext\Exceptions\AuthenticationException;
use Ronu\AppContext\Middleware\RequireAuthenticatedContext;
use Ronu\AppContext\Tests\TestCase;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class RequireAuthenticatedContextTest extends TestCase
{
    public function test_allows_any_mode_for_jwt_context(): void
    {
        $context = AppContext::fromJwt('site', ['sub' => '1']);
        $request = Request::create('http://example.com/site/orders');
        $request->attributes->set('app_context', $context);

        $middleware = new RequireAuthenticatedContext();
        $response = $middleware->handle($request, fn () => new Response('ok'));

        $this->assertInstanceOf(Response::class, $response);
    }

    public function test_blocks_anonymous_when_authentication_is_required(): void
    {
        $context = AppContext::anonymous('site');
        $request = Request::create('http://example.com/site/orders');
        $request->attributes->set('app_context', $context);

        $middleware = new RequireAuthenticatedContext();

        $this->expectException(AuthenticationException::class);
        $middleware->handle($request, fn () => new Response('ok'));
    }

    public function test_requires_jwt_mode_for_sensitive_route(): void
    {
        $context = AppContext::fromApiKey('partner', 'client-1', ['partner:*']);
        $request = Request::create('http://example.com/site/checkout');
        $request->attributes->set('app_context', $context);

        $middleware = new RequireAuthenticatedContext();

        $this->expectException(AuthenticationException::class);
        $middleware->handle($request, fn () => new Response('ok'), 'jwt');
    }

    public function test_requires_api_key_mode_for_machine_endpoints(): void
    {
        $context = AppContext::fromJwt('site', ['sub' => '7']);
        $request = Request::create('http://example.com/partner/orders');
        $request->attributes->set('app_context', $context);

        $middleware = new RequireAuthenticatedContext();

        $this->expectException(AuthenticationException::class);
        $middleware->handle($request, fn () => new Response('ok'), 'api_key');
    }

    public function test_rejects_invalid_mode_parameter(): void
    {
        $context = AppContext::fromJwt('site', ['sub' => '1']);
        $request = Request::create('http://example.com/site/orders');
        $request->attributes->set('app_context', $context);

        $middleware = new RequireAuthenticatedContext();

        $this->expectException(\InvalidArgumentException::class);
        $middleware->handle($request, fn () => new Response('ok'), 'bearer');
    }
}
