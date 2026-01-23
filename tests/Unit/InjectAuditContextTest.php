<?php

declare(strict_types=1);

namespace Ronu\AppContext\Tests\Unit;

use Ronu\AppContext\Context\AppContext;
use Ronu\AppContext\Middleware\InjectAuditContext;
use Ronu\AppContext\Tests\TestCase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

class InjectAuditContextTest extends TestCase
{
    public function test_audit_disabled_for_channel_skips_logging_context(): void
    {
        config([
            'app-context.audit.enabled' => true,
            'app-context.channels.site.audit.enabled' => false,
        ]);

        $context = AppContext::fromChannel('site', 'jwt');
        $request = Request::create('http://example.com/site');
        $request->attributes->set('app_context', $context);

        Log::spy();

        $middleware = new InjectAuditContext();
        $middleware->handle($request, fn () => new Response('ok'));

        Log::shouldHaveReceived('shareContext')->never();
    }

    public function test_audit_enabled_for_channel_shares_context(): void
    {
        config([
            'app-context.audit.enabled' => false,
            'app-context.channels.admin.audit.enabled' => true,
        ]);

        $context = AppContext::fromChannel('admin', 'jwt');
        $request = Request::create('http://example.com/api/users');
        $request->attributes->set('app_context', $context);

        Log::spy();

        $middleware = new InjectAuditContext();
        $middleware->handle($request, fn () => new Response('ok'));

        Log::shouldHaveReceived('shareContext')->once();
    }
}
