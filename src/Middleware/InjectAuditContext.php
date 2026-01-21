<?php

declare(strict_types=1);

namespace Charlietyn\AppContext\Middleware;

use Charlietyn\AppContext\Context\AppContext;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

/**
 * Middleware that injects AppContext into all logs.
 *
 * This ensures that all log entries include:
 * - app_id (channel)
 * - user_id or client_id
 * - tenant_id
 * - request_id
 * - ip_address
 */
class InjectAuditContext
{
    protected bool $enabled;
    protected bool $logAllRequests;
    protected bool $includeRequestBody;
    protected bool $includeResponseBody;
    protected array $sensitiveHeaders;

    public function __construct()
    {
        $config = config('app-context.audit', []);
        $this->enabled = $config['enabled'] ?? true;
        $this->logAllRequests = $config['log_all_requests'] ?? false;
        $this->includeRequestBody = $config['include_request_body'] ?? false;
        $this->includeResponseBody = $config['include_response_body'] ?? false;
        $this->sensitiveHeaders = $config['sensitive_headers'] ?? [
            'authorization',
            'x-api-key',
            'cookie',
            'x-csrf-token',
        ];
    }

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (! $this->enabled) {
            return $next($request);
        }

        /** @var AppContext|null $context */
        $context = $request->attributes->get('app_context');

        if ($context !== null) {
            // Share context with all log entries
            Log::shareContext($context->toLogContext());
        }

        // Log request if enabled
        if ($this->logAllRequests) {
            $this->logRequest($request, $context);
        }

        $response = $next($request);

        // Log response if enabled
        if ($this->logAllRequests && $this->includeResponseBody) {
            $this->logResponse($response, $context);
        }

        return $response;
    }

    /**
     * Log the incoming request.
     */
    protected function logRequest(Request $request, ?AppContext $context): void
    {
        $data = [
            'method' => $request->method(),
            'path' => $request->path(),
            'query' => $request->query(),
            'headers' => $this->filterHeaders($request->headers->all()),
        ];

        if ($this->includeRequestBody && $request->isJson()) {
            $data['body'] = $request->json()->all();
        }

        Log::info('HTTP Request', $data);
    }

    /**
     * Log the outgoing response.
     */
    protected function logResponse(Response $response, ?AppContext $context): void
    {
        $data = [
            'status' => $response->getStatusCode(),
            'headers' => $this->filterHeaders($response->headers->all()),
        ];

        if ($this->includeResponseBody) {
            $content = $response->getContent();
            if ($content !== false && strlen($content) < 10000) {
                $data['body'] = json_decode($content, true) ?? $content;
            }
        }

        Log::info('HTTP Response', $data);
    }

    /**
     * Filter sensitive headers from logs.
     */
    protected function filterHeaders(array $headers): array
    {
        $filtered = [];

        foreach ($headers as $name => $values) {
            $lowerName = strtolower($name);

            if (in_array($lowerName, $this->sensitiveHeaders, true)) {
                $filtered[$name] = ['[REDACTED]'];
            } else {
                $filtered[$name] = $values;
            }
        }

        return $filtered;
    }
}
