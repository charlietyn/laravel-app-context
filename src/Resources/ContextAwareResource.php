<?php

declare(strict_types=1);

namespace Charlietyn\AppContext\Resources;

use Charlietyn\AppContext\Context\AppContext;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

/**
 * Context Aware Resource
 *
 * Base resource that filters fields based on context (channel).
 * Admin sees all fields, Mobile sees basic fields, Partner sees aggregated data.
 *
 * Usage:
 * class UserResource extends ContextAwareResource
 * {
 *     protected function toPublicArray(Request $request): array
 *     {
 *         return ['id' => $this->id, 'name' => $this->name];
 *     }
 *
 *     protected function toFullArray(Request $request): array
 *     {
 *         return [...$this->toPublicArray($request), 'email' => $this->email, 'created_at' => $this->created_at];
 *     }
 * }
 */
abstract class ContextAwareResource extends JsonResource
{
    /**
     * Transform the resource into an array.
     */
    public function toArray(Request $request): array
    {
        /** @var AppContext|null $context */
        $context = $request->attributes->get('app_context');

        if (!$context) {
            return $this->toPublicArray($request);
        }

        return match ($context->appId) {
            'admin' => $this->toAdminArray($request),
            'mobile' => $this->toMobileArray($request),
            'site' => $this->toSiteArray($request),
            'partner' => $this->toPartnerArray($request),
            default => $this->toPublicArray($request),
        };
    }

    /**
     * Admin: all fields + sensitive metadata.
     */
    protected function toAdminArray(Request $request): array
    {
        return $this->toFullArray($request);
    }

    /**
     * Mobile: basic fields for app.
     */
    protected function toMobileArray(Request $request): array
    {
        return $this->toPublicArray($request);
    }

    /**
     * Site: public fields for web.
     */
    protected function toSiteArray(Request $request): array
    {
        return $this->toPublicArray($request);
    }

    /**
     * Partner: aggregated data, without sensitive details.
     */
    protected function toPartnerArray(Request $request): array
    {
        return $this->toPublicArray($request);
    }

    /**
     * Public fields (default).
     * Subclasses MUST implement.
     */
    abstract protected function toPublicArray(Request $request): array;

    /**
     * All fields (admin).
     * Subclasses CAN override.
     */
    protected function toFullArray(Request $request): array
    {
        return $this->toPublicArray($request);
    }

    /**
     * Get the current context.
     */
    protected function getContext(Request $request): ?AppContext
    {
        return $request->attributes->get('app_context');
    }

    /**
     * Helper: check if context is admin.
     */
    protected function isAdmin(Request $request): bool
    {
        $context = $this->getContext($request);
        return $context && $context->appId === 'admin';
    }

    /**
     * Helper: check if context is mobile.
     */
    protected function isMobile(Request $request): bool
    {
        $context = $this->getContext($request);
        return $context && $context->appId === 'mobile';
    }

    /**
     * Helper: check if context is site.
     */
    protected function isSite(Request $request): bool
    {
        $context = $this->getContext($request);
        return $context && $context->appId === 'site';
    }

    /**
     * Helper: check if context is partner.
     */
    protected function isPartner(Request $request): bool
    {
        $context = $this->getContext($request);
        return $context && $context->appId === 'partner';
    }

    /**
     * Helper: check if user is authenticated.
     */
    protected function isAuthenticated(Request $request): bool
    {
        $context = $this->getContext($request);
        return $context && $context->isAuthenticated();
    }

    /**
     * Helper: conditional value based on scope.
     */
    protected function whenHasScope(Request $request, string $scope, mixed $value, mixed $default = null): mixed
    {
        $context = $this->getContext($request);
        return $context && $context->hasScope($scope) ? value($value) : value($default);
    }

    /**
     * Helper: conditional value based on capability.
     */
    protected function whenHasCapability(Request $request, string $capability, mixed $value, mixed $default = null): mixed
    {
        $context = $this->getContext($request);
        return $context && $context->hasCapability($capability) ? value($value) : value($default);
    }

    /**
     * Helper: conditional value based on channel.
     */
    protected function whenChannel(Request $request, string|array $channels, mixed $value, mixed $default = null): mixed
    {
        $context = $this->getContext($request);
        $channels = is_array($channels) ? $channels : [$channels];

        return $context && in_array($context->appId, $channels, true) ? value($value) : value($default);
    }
}
