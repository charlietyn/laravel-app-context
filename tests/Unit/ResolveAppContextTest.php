<?php

declare(strict_types=1);

namespace Ronu\AppContext\Tests\Unit;

use Ronu\AppContext\Context\ContextResolver;
use Ronu\AppContext\Middleware\ResolveAppContext;
use Ronu\AppContext\Tests\TestCase;
use Ronu\AppContext\Exceptions\ContextBindingException;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class ResolveAppContextTest extends TestCase
{
    private function makeResolver(bool $denyByDefault): ContextResolver
    {
        return new ContextResolver([
            'channels' => [
                'site' => [
                    'subdomains' => ['www', null],
                    'path_prefixes' => ['/site'],
                    'auth_mode' => 'jwt_or_anonymous',
                ],
            ],
            'domain' => 'example.com',
            'detection_strategy' => 'path',
            'deny_by_default' => $denyByDefault,
        ]);
    }

    public function test_fallbacks_to_default_channel_when_not_deny_by_default(): void
    {
        config(['app-context.default_channel' => 'site']);

        $request = Request::create('http://example.com/unknown');
        $resolver = $this->makeResolver(false);
        $middleware = new ResolveAppContext($resolver);

        $response = $middleware->handle($request, fn () => new Response('ok'));

        $this->assertInstanceOf(Response::class, $response);
        $context = $request->attributes->get('app_context');

        $this->assertEquals('site', $context?->getAppId());
        $this->assertEquals('anonymous', $context?->getAuthMode());
    }

    public function test_denies_when_deny_by_default_enabled(): void
    {
        $request = Request::create('http://example.com/unknown');
        $resolver = $this->makeResolver(true);
        $middleware = new ResolveAppContext($resolver);

        $this->expectException(ContextBindingException::class);

        $middleware->handle($request, fn () => new Response('ok'));
    }
}
