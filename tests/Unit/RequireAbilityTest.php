<?php

declare(strict_types=1);

namespace Ronu\AppContext\Tests\Unit;

use Ronu\AppContext\Context\AppContext;
use Ronu\AppContext\Middleware\RequireAbility;
use Ronu\AppContext\Middleware\RequireAllAbilities;
use Ronu\AppContext\Tests\TestCase;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class RequireAbilityTest extends TestCase
{
    public function test_requires_allows_jwt_scope(): void
    {
        $context = AppContext::fromJwt('admin', [
            'sub' => '1',
            'scp' => ['admin:users:manage'],
        ]);

        $request = Request::create('http://example.com/api/users');
        $request->attributes->set('app_context', $context);

        $middleware = new RequireAbility();
        $response = $middleware->handle($request, fn () => new Response('ok'), 'admin:users:manage');

        $this->assertInstanceOf(Response::class, $response);
    }

    public function test_requires_allows_api_key_capability(): void
    {
        $context = AppContext::fromApiKey('partner', 'client-1', ['partner:*']);
        $request = Request::create('http://example.com/partner/orders');
        $request->attributes->set('app_context', $context);

        $middleware = new RequireAbility();
        $response = $middleware->handle($request, fn () => new Response('ok'), 'partner:orders:read');

        $this->assertInstanceOf(Response::class, $response);
    }

    public function test_requires_allows_anonymous_public_scope(): void
    {
        $context = AppContext::anonymous('site')->withScopes(['catalog:browse']);
        $request = Request::create('http://example.com/site/catalog');
        $request->attributes->set('app_context', $context);

        $middleware = new RequireAbility();
        $response = $middleware->handle($request, fn () => new Response('ok'), 'catalog:browse');

        $this->assertInstanceOf(Response::class, $response);
    }

    public function test_requires_all_validates_all_abilities(): void
    {
        $context = AppContext::fromApiKey('partner', 'client-1', ['partner:orders:read', 'partner:orders:write']);
        $request = Request::create('http://example.com/partner/orders');
        $request->attributes->set('app_context', $context);

        $middleware = new RequireAllAbilities();
        $response = $middleware->handle(
            $request,
            fn () => new Response('ok'),
            'partner:orders:read',
            'partner:orders:write'
        );

        $this->assertInstanceOf(Response::class, $response);
    }
}
