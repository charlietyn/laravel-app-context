<?php

declare(strict_types=1);

namespace Ronu\AppContext\Auth\Verifiers;

use Ronu\AppContext\Contracts\VerifierInterface;
use Ronu\AppContext\Exceptions\AuthenticationException;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use PHPOpenSourceSaver\JWTAuth\JWTAuth;
use PHPOpenSourceSaver\JWTAuth\Exceptions\JWTException;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenBlacklistedException;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenExpiredException;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenInvalidException;

/**
 * JWT Token Verifier with enhanced security validations.
 *
 * Security Features:
 * - Algorithm whitelist (rejects 'none' algorithm - CVE-2015-9235)
 * - Structure validation before signature verification
 * - Blacklist support with Redis
 * - Issuer and audience validation
 */
final class JwtVerifier implements VerifierInterface
{
    /**
     * Allowed algorithms for JWT verification.
     * CRITICAL: Never include 'none' in this list.
     */
    private const ALLOWED_ALGORITHMS = ['HS256', 'RS256', 'RS384', 'RS512'];

    private readonly array $allowedAlgorithms;
    private readonly bool $blacklistEnabled;
    private readonly bool $verifyIssuer;
    private readonly bool $verifyAudience;
    private readonly ?string $expectedIssuer;
    private readonly array $tokenSources;

    public function __construct(
        private readonly JWTAuth $jwtAuth,
        private readonly CacheRepository $cache,
        array $config,
    ) {
        $this->allowedAlgorithms = $config['allowed_algorithms'] ?? self::ALLOWED_ALGORITHMS;
        $this->blacklistEnabled = $config['blacklist_enabled'] ?? true;
        $this->verifyIssuer = $config['verify_iss'] ?? true;
        $this->verifyAudience = $config['verify_aud'] ?? true;
        $this->expectedIssuer = $config['issuer'] ?? null;
        $this->tokenSources = $config['token_sources'] ?? ['header', 'query', 'cookie'];
    }

    /**
     * Verify JWT token from request.
     *
     * @return array{
     *     sub: int|string,
     *     aud: string|null,
     *     iss: string|null,
     *     exp: int,
     *     iat: int,
     *     jti: string|null,
     *     tid: string|null,
     *     scp: array,
     *     did: string|null
     * }
     *
     * @throws AuthenticationException
     */
    public function verify(Request $request): array
    {
        $token = $this->extractToken($request);

        if ($token === null) {
            throw AuthenticationException::missingToken();
        }

        // Pre-verification: Structure and algorithm check
        $this->preVerify($token);

        // Main verification with JWTAuth
        try {
            $payload = $this->jwtAuth->setToken($token)->getPayload();
        } catch (TokenExpiredException) {
            throw AuthenticationException::invalidToken('Token has expired');
        } catch (TokenBlacklistedException) {
            throw AuthenticationException::blacklistedToken();
        } catch (TokenInvalidException $e) {
            throw AuthenticationException::invalidToken($e->getMessage());
        } catch (JWTException $e) {
            throw AuthenticationException::invalidToken($e->getMessage());
        }

        // Post-verification: Custom validations
        $claims = $payload->toArray();
        $this->postVerify($claims, $token);

        return $claims;
    }

    /**
     * Check if verifier can handle the request.
     */
    public function canHandle(Request $request): bool
    {
        return $this->extractToken($request) !== null;
    }

    /**
     * Get the credential type.
     */
    public function getCredentialType(): string
    {
        return 'jwt';
    }

    /**
     * Blacklist a token.
     */
    public function blacklist(string $token): void
    {
        try {
            $payload = $this->jwtAuth->setToken($token)->getPayload();
            $jti = $payload->get('jti');
            $exp = $payload->get('exp');

            if ($jti && $exp) {
                $ttl = $exp - time();
                if ($ttl > 0) {
                    $this->cache->put("jwt_blacklist:{$jti}", true, $ttl);
                }
            }

            // Also use JWTAuth's built-in blacklist
            $this->jwtAuth->invalidate();
        } catch (JWTException) {
            // Token might already be invalid, ignore
        }
    }

    /**
     * Invalidate the current token.
     */
    public function invalidateToken(): void
    {
        try {
            $this->jwtAuth->invalidate();
        } catch (JWTException) {
            // Ignore if already invalid
        }
    }

    /**
     * Refresh the current token.
     */
    public function refreshToken(): ?string
    {
        try {
            return $this->jwtAuth->refresh();
        } catch (JWTException) {
            return null;
        }
    }

    /**
     * Check if token can be refreshed.
     */
    public function canRefresh(): bool
    {
        try {
            $payload = $this->jwtAuth->getPayload();
            $iat = $payload->get('iat');
            $refreshTtl = config('app-context.jwt.refresh_ttl', 1209600);

            return ($iat + $refreshTtl) > time();
        } catch (JWTException) {
            return false;
        }
    }

    /**
     * Extract token from request.
     */
    private function extractToken(Request $request): ?string
    {
        $sources = array_map('strtolower', $this->tokenSources);

        if (in_array('header', $sources, true)) {
            $header = $request->header('Authorization', '');
            if (str_starts_with($header, 'Bearer ')) {
                return substr($header, 7);
            }
        }

        if (in_array('query', $sources, true)) {
            if ($token = $request->query('token')) {
                return $token;
            }
        }

        if (in_array('cookie', $sources, true)) {
            if ($token = $request->cookie('token')) {
                return $token;
            }
        }

        return null;
    }

    /**
     * Pre-verification: Structure and algorithm validation.
     *
     * @throws AuthenticationException
     */
    private function preVerify(string $token): void
    {
        // Validate structure (must have 3 parts)
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw AuthenticationException::invalidToken('Invalid token structure');
        }

        [$headerB64, , ] = $parts;

        // Decode header
        $headerJson = base64_decode(strtr($headerB64, '-_', '+/'), true);
        if ($headerJson === false) {
            throw AuthenticationException::invalidToken('Invalid token header encoding');
        }

        $header = json_decode($headerJson, true);
        if (! is_array($header) || ! isset($header['alg'])) {
            throw AuthenticationException::invalidToken('Invalid token header');
        }

        $algorithm = strtoupper($header['alg']);

        // CRITICAL: Reject 'none' algorithm (CVE-2015-9235)
        if ($algorithm === 'NONE') {
            Log::warning('JWT algorithm confusion attack attempted', [
                'algorithm' => $header['alg'],
                'ip' => request()->ip(),
            ]);
            throw AuthenticationException::algorithmMismatch('none');
        }

        // Validate algorithm is in whitelist
        if (! in_array($algorithm, $this->allowedAlgorithms, true)) {
            Log::warning('JWT with disallowed algorithm', [
                'algorithm' => $header['alg'],
                'allowed' => $this->allowedAlgorithms,
                'ip' => request()->ip(),
            ]);
            throw AuthenticationException::algorithmMismatch($header['alg']);
        }
    }

    /**
     * Post-verification: Custom validations after signature verification.
     *
     * @throws AuthenticationException
     */
    private function postVerify(array $claims, string $token): void
    {
        // Check custom blacklist
        if ($this->blacklistEnabled && isset($claims['jti'])) {
            if ($this->cache->has("jwt_blacklist:{$claims['jti']}")) {
                throw AuthenticationException::blacklistedToken();
            }
        }

        // Verify audience claim exists when required
        if ($this->verifyAudience && empty($claims['aud'])) {
            throw AuthenticationException::invalidToken('Token missing audience claim');
        }

        // Verify issuer
        if ($this->verifyIssuer && $this->expectedIssuer !== null) {
            $issuer = $claims['iss'] ?? null;
            if (! $this->issuerMatches($issuer)) {
                throw AuthenticationException::invalidToken(
                    "Invalid issuer. Expected '{$this->expectedIssuer}', got '{$issuer}'"
                );
            }
        }

        // Verify subject exists
        if (empty($claims['sub'])) {
            throw AuthenticationException::invalidToken('Token missing subject claim');
        }
    }

    /**
     * Get the JWTAuth instance.
     */
    public function getJwtAuth(): JWTAuth
    {
        return $this->jwtAuth;
    }

    private function issuerMatches(?string $issuer): bool
    {
        if ($issuer === null) {
            return false;
        }

        $expected = rtrim((string) $this->expectedIssuer, '/');
        $actual = rtrim($issuer, '/');

        if ($actual === $expected) {
            return true;
        }

        if (! str_starts_with($actual, $expected)) {
            return false;
        }

        $nextChar = substr($actual, strlen($expected), 1);

        return $nextChar === '' || $nextChar === '/' || $nextChar === '?' || $nextChar === '#';
    }
}
