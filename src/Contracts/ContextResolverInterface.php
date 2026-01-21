<?php

declare(strict_types=1);

namespace Ronu\AppContext\Contracts;

use Ronu\AppContext\Context\AppContext;
use Illuminate\Http\Request;

interface ContextResolverInterface
{
    /**
     * Resolve the application context from the request.
     *
     * @param Request $request The incoming HTTP request
     * @return AppContext|null The resolved context or null if no channel matched
     */
    public function resolve(Request $request): ?AppContext;

    /**
     * Resolve context using path-based detection only.
     */
    public function resolveByPath(Request $request): ?AppContext;

    /**
     * Resolve context using subdomain-based detection only.
     */
    public function resolveBySubdomain(Request $request): ?AppContext;

    /**
     * Resolve context using strict mode (both path and subdomain must match).
     */
    public function resolveStrict(Request $request): ?AppContext;

    /**
     * Resolve context using auto-detection based on host rules.
     */
    public function resolveAuto(Request $request): ?AppContext;

    /**
     * Get the detection strategy for a given host.
     */
    public function getDetectionStrategy(string $host): string;

    /**
     * Extract subdomain from host.
     */
    public function extractSubdomain(string $host): ?string;

    /**
     * Match path prefix to channel.
     */
    public function matchPathPrefix(string $path): ?string;
}
