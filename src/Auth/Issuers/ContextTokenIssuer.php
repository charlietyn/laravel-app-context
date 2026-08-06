<?php

declare(strict_types=1);

namespace Ronu\AppContext\Auth\Issuers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use PHPOpenSourceSaver\JWTAuth\Contracts\JWTSubject;
use PHPOpenSourceSaver\JWTAuth\JWTAuth;
use Ronu\AppContext\Context\AppContext;
use Ronu\AppContext\Contracts\ContextTokenIssuerInterface;
use Ronu\AppContext\Exceptions\AppContextException;

/**
 * Default context-bound token issuer backed by php-open-source-saver/jwt-auth.
 *
 * Mints the claim set this package verifies on the way in, so a token produced
 * here is accepted by AuthenticateChannel (`aud`) and EnforceContextBinding
 * (`tid`, `did`) without further work from the host application.
 */
class ContextTokenIssuer implements ContextTokenIssuerInterface
{
    public function __construct(private readonly JWTAuth $jwt) {}

    /**
     * {@inheritDoc}
     */
    public function issueFor(Authenticatable $user, AppContext $context, ?Request $request = null): array
    {
        $request ??= request();

        $this->assertJwtSubject($user);

        $accessToken = $this->jwt
            ->claims($this->accessClaims($context, $user, $request))
            ->fromUser($user);

        $payload = $this->jwt->setToken($accessToken)->getPayload();

        $factory = $this->jwt->factory();
        $accessTtl = $factory->getTTL();
        $refreshTtl = $this->refreshTtlMinutes();

        // The factory TTL is global state on a shared singleton: raise it to mint
        // the refresh token, then restore it in a finally so a later caller does
        // not silently inherit the longer lifetime.
        try {
            $factory->setTTL($refreshTtl);

            $refreshToken = $this->jwt->claims([
                'iss' => $this->issuer(),
                'refresh' => true,
                'aud' => $payload->get('aud'),
                'tid' => $payload->get('tid'),
                'did' => $payload->get('did'),
            ])->fromUser($user);
        } finally {
            $factory->setTTL($accessTtl);
        }

        return [
            'token' => $accessToken,
            'access_token' => $accessToken,
            'token_type' => 'bearer',
            'expires_in' => $accessTtl * 60,
            'refresh_token' => $refreshToken,
            'refresh_expires_in' => $refreshTtl * 60,
        ];
    }

    /**
     * {@inheritDoc}
     */
    public function accessClaims(AppContext $context, Authenticatable $user, ?Request $request = null): array
    {
        $request ??= request();

        return [
            'iss' => $this->issuer(),
            'aud' => $context->getAppId(),
            'tid' => $this->resolveTenantId($context, $user, $request),
            'did' => $this->resolveDeviceId($context, $request),
        ];
    }

    /**
     * The contract takes an Authenticatable so it stays interchangeable with the
     * generic token-issuer contracts hosts already implement, but jwt-auth can
     * only mint from a JWTSubject. Check it here so a misconfigured user model
     * fails with an actionable message instead of a TypeError raised from inside
     * the JWT package.
     *
     * @throws AppContextException
     */
    protected function assertJwtSubject(Authenticatable $user): void
    {
        if ($user instanceof JWTSubject) {
            return;
        }

        throw new AppContextException(
            sprintf(
                'Cannot issue a context-bound token for [%s]: the user model must implement %s.',
                $user::class,
                JWTSubject::class
            ),
            'app-context.token-issuer'
        );
    }

    /**
     * Refresh-token lifetime in minutes.
     *
     * `app-context.jwt.refresh_ttl` is expressed in seconds (this package's
     * convention) while the JWT factory works in minutes, so it is converted
     * here. Falls back to config/jwt.php, which is already in minutes.
     */
    protected function refreshTtlMinutes(): int
    {
        $seconds = config('app-context.jwt.refresh_ttl');

        if ($seconds !== null) {
            return (int) round((int) $seconds / 60);
        }

        return (int) config('jwt.refresh_ttl', 20160);
    }

    /**
     * Tenant bound to the token.
     *
     * The resolved context wins; a header or the user's own tenant is only a
     * fallback for the login request, where no token has been presented yet and
     * the context therefore carries no tenant.
     */
    protected function resolveTenantId(AppContext $context, Authenticatable $user, Request $request): ?string
    {
        $tenantId = $context->getTenantId()
            ?? $request->header($this->tenantHeader())
            ?? ($user->tenant_id ?? null)
            ?? $request->query('tenant_id');

        return $tenantId !== null ? (string) $tenantId : null;
    }

    /**
     * Device bound to the token.
     *
     * AppContext::fromJwt() reads `did` off the token being verified, so during
     * login — where there is no token yet — the context has no device and the
     * request header is the only source.
     */
    protected function resolveDeviceId(AppContext $context, Request $request): ?string
    {
        return $context->getDeviceId() ?? $request->header($this->deviceHeader());
    }

    protected function issuer(): string
    {
        $issuer = (string) config('app-context.jwt.issuer', config('app.url', 'http://localhost'));

        return rtrim($issuer, '/');
    }

    protected function deviceHeader(): string
    {
        return (string) config('app-context.jwt.device_header', 'X-Device-Id');
    }

    protected function tenantHeader(): string
    {
        return (string) config('app-context.jwt.tenant_header', 'X-Tenant-Id');
    }
}
