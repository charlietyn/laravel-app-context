<?php

declare(strict_types=1);

namespace Ronu\AppContext;

use Ronu\AppContext\Auth\Authenticators\AnonymousAuthenticator;
use Ronu\AppContext\Auth\Authenticators\ApiKeyAuthenticator;
use Ronu\AppContext\Auth\Authenticators\JwtAuthenticator;
use Ronu\AppContext\Auth\Guards\AppContextGuard;
use Ronu\AppContext\Auth\Verifiers\ApiKeyVerifier;
use Ronu\AppContext\Auth\Verifiers\JwtVerifier;
use Ronu\AppContext\Commands\GenerateApiKeyCommand;
use Ronu\AppContext\Commands\ListApiClientsCommand;
use Ronu\AppContext\Commands\RevokeApiKeyCommand;
use Ronu\AppContext\Context\AppContext;
use Ronu\AppContext\Context\ContextResolver;
use Ronu\AppContext\Contracts\AuthenticatorInterface;
use Ronu\AppContext\Contracts\ClientRepositoryInterface;
use Ronu\AppContext\Contracts\ContextResolverInterface;
use Ronu\AppContext\Middleware\AuthenticateChannel;
use Ronu\AppContext\Middleware\EnforceContextBinding;
use Ronu\AppContext\Middleware\InjectAuditContext;
use Ronu\AppContext\Middleware\RateLimitByContext;
use Ronu\AppContext\Middleware\RequireScope;
use Ronu\AppContext\Middleware\ResolveAppContext;
use Ronu\AppContext\Repositories\ConfigClientRepository;
use Ronu\AppContext\Repositories\EloquentClientRepository;
use Ronu\AppContext\Support\ScopeChecker;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\ServiceProvider;

class AppContextServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/app-context.php', 'app-context');

        $this->configureJwtFallback();

        $this->registerContextResolver();
        $this->registerClientRepository();
        $this->registerVerifiers();
        $this->registerAuthenticators();
        $this->registerScopeChecker();
        $this->registerAppContext();
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        $this->publishConfig();
        $this->publishMigrations();
        $this->registerMiddleware();
        $this->registerCommands();
        $this->registerAuthGuard();
    }

    /**
     * Register the context resolver.
     */
    protected function registerContextResolver(): void
    {
        $this->app->singleton(ContextResolverInterface::class, function (Application $app) {
            return new ContextResolver(
                config: $app['config']->get('app-context'),
            );
        });

        $this->app->alias(ContextResolverInterface::class, 'app-context.resolver');
    }

    /**
     * Register the client repository based on configuration.
     *
     * The repository can be:
     * - 'config': Config-based clients (no database required)
     * - 'eloquent': Database-based clients
     * - Custom class: Any class implementing ClientRepositoryInterface
     */
    protected function registerClientRepository(): void
    {
        $this->app->singleton(ClientRepositoryInterface::class, function (Application $app) {
            $config = $app['config']->get('app-context.client_repository', []);
            $driver = $config['driver'] ?? 'config';

            return match ($driver) {
                'config' => new ConfigClientRepository($config['config'] ?? []),
                'eloquent' => new EloquentClientRepository($config['eloquent'] ?? []),
                default => $this->resolveCustomRepository($app, $driver, $config),
            };
        });

        $this->app->alias(ClientRepositoryInterface::class, 'app-context.client-repository');
    }

    /**
     * Resolve a custom repository class.
     *
     * @param Application $app
     * @param string $driver Custom repository class name
     * @param array<string, mixed> $config Full configuration
     * @return ClientRepositoryInterface
     */
    protected function resolveCustomRepository(Application $app, string $driver, array $config): ClientRepositoryInterface
    {
        if (!class_exists($driver)) {
            throw new \InvalidArgumentException(
                "Client repository driver '{$driver}' not found. " .
                "Use 'config', 'eloquent', or a fully qualified class name."
            );
        }

        $repository = $app->make($driver, ['config' => $config[$driver] ?? $config['custom'] ?? []]);

        if (!$repository instanceof ClientRepositoryInterface) {
            throw new \InvalidArgumentException(
                "Client repository '{$driver}' must implement " . ClientRepositoryInterface::class
            );
        }

        return $repository;
    }

    /**
     * Register JWT and API Key verifiers.
     */
    protected function registerVerifiers(): void
    {
        $this->app->singleton(JwtVerifier::class, function (Application $app) {
            return new JwtVerifier(
                jwtAuth: $app['tymon.jwt.auth'],
                cache: $app['cache']->store(),
                config: $app['config']->get('app-context.jwt'),
            );
        });

        $this->app->singleton(ApiKeyVerifier::class, function (Application $app) {
            return new ApiKeyVerifier(
                clientRepository: $app->make(ClientRepositoryInterface::class),
                config: $app['config']->get('app-context'),
            );
        });
    }

    /**
     * Register authenticators for each auth mode.
     */
    protected function registerAuthenticators(): void
    {
        $this->app->singleton(JwtAuthenticator::class, function (Application $app) {
            return new JwtAuthenticator(
                verifier: $app->make(JwtVerifier::class),
                config: $app['config']->get('app-context'),
            );
        });

        $this->app->singleton(ApiKeyAuthenticator::class, function (Application $app) {
            return new ApiKeyAuthenticator(
                verifier: $app->make(ApiKeyVerifier::class),
                config: $app['config']->get('app-context'),
            );
        });

        $this->app->singleton(AnonymousAuthenticator::class, function (Application $app) {
            return new AnonymousAuthenticator(
                config: $app['config']->get('app-context'),
            );
        });

        // Register authenticator factory
        $this->app->singleton('app-context.authenticator', function (Application $app) {
            return function (string $authMode): AuthenticatorInterface {
                return match ($authMode) {
                    'jwt', 'jwt_or_anonymous' => app(JwtAuthenticator::class),
                    'api_key' => app(ApiKeyAuthenticator::class),
                    'anonymous' => app(AnonymousAuthenticator::class),
                    default => throw new \InvalidArgumentException("Unknown auth mode: {$authMode}"),
                };
            };
        });
    }

    /**
     * Register the scope checker.
     */
    protected function registerScopeChecker(): void
    {
        $this->app->singleton(ScopeChecker::class, function () {
            return new ScopeChecker();
        });
    }

    /**
     * Register the AppContext singleton.
     */
    protected function registerAppContext(): void
    {
        $this->app->singleton(AppContext::class, function () {
            // Returns null until resolved by middleware
            return null;
        });

        $this->app->alias(AppContext::class, 'app-context');
    }

    /**
     * Publish configuration file.
     */
    protected function publishConfig(): void
    {
        $this->publishes([
            __DIR__ . '/../config/app-context.php' => config_path('app-context.php'),
        ], 'app-context-config');
    }

    /**
     * Publish migrations.
     *
     * Migrations are now optional and only needed if using 'eloquent' driver.
     */
    protected function publishMigrations(): void
    {
        $this->publishes([
            __DIR__ . '/../database/migrations/' => database_path('migrations'),
        ], 'app-context-migrations');

        // Only auto-load migrations if using eloquent driver
        $driver = config('app-context.client_repository.driver', 'config');
        if ($driver === 'eloquent') {
            $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');
        }
    }

    /**
     * Register middleware aliases.
     */
    protected function registerMiddleware(): void
    {
        /** @var Router $router */
        $router = $this->app['router'];

        $router->aliasMiddleware('app.context', ResolveAppContext::class);
        $router->aliasMiddleware('app.auth', AuthenticateChannel::class);
        $router->aliasMiddleware('app.binding', EnforceContextBinding::class);
        $router->aliasMiddleware('app.scope', RequireScope::class);
        $router->aliasMiddleware('app.throttle', RateLimitByContext::class);
        $router->aliasMiddleware('app.audit', InjectAuditContext::class);

        // Middleware group for full context pipeline
        $router->middlewareGroup('app-context', [
            ResolveAppContext::class,
            AuthenticateChannel::class,
            EnforceContextBinding::class,
            RateLimitByContext::class,
            InjectAuditContext::class,
        ]);
    }

    /**
     * Register artisan commands.
     */
    protected function registerCommands(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([
                GenerateApiKeyCommand::class,
                ListApiClientsCommand::class,
                RevokeApiKeyCommand::class,
            ]);
        }
    }

    /**
     * Register custom auth guard.
     */
    protected function registerAuthGuard(): void
    {
        Auth::extend('app-context', function (Application $app, string $name, array $config) {
            return new AppContextGuard(
                name: $name,
                provider: Auth::createUserProvider($config['provider'] ?? null),
                request: $app['request'],
            );
        });
    }

    /**
     * Get the services provided by the provider.
     *
     * @return array<string>
     */
    public function provides(): array
    {
        return [
            AppContext::class,
            'app-context',
            'app-context.resolver',
            'app-context.authenticator',
            'app-context.client-repository',
            ContextResolverInterface::class,
            ClientRepositoryInterface::class,
            JwtVerifier::class,
            ApiKeyVerifier::class,
            JwtAuthenticator::class,
            ApiKeyAuthenticator::class,
            AnonymousAuthenticator::class,
            ScopeChecker::class,
        ];
    }

    /**
     * Configure JWT fallback for development environments when RSA keys are missing.
     */
    protected function configureJwtFallback(): void
    {
        $config = $this->app['config']->get('app-context');
        $jwtConfig = $config['jwt'] ?? [];
        $fallbackConfig = $jwtConfig['dev_fallback'] ?? [];

        $devEnvironments = $config['app_context_dev'] ?? ['local'];

        if (! $this->app->environment($devEnvironments)) {
            return;
        }

        if (! ($fallbackConfig['enabled'] ?? true)) {
            return;
        }

        $algorithm = strtoupper((string) ($jwtConfig['algorithm'] ?? 'HS256'));
        if (! str_starts_with($algorithm, 'RS')) {
            return;
        }

        $publicKeyPath = $jwtConfig['public_key_path'] ?? null;
        $privateKeyPath = $jwtConfig['private_key_path'] ?? null;

        $publicExists = $publicKeyPath ? file_exists($publicKeyPath) : false;
        $privateExists = $privateKeyPath ? file_exists($privateKeyPath) : false;

        if ($publicExists && $privateExists) {
            return;
        }

        $fallbackAlgorithm = $fallbackConfig['algorithm'] ?? 'HS256';
        $fallbackSecret = $fallbackConfig['secret'] ?? $this->app['config']->get('app.key');
        if (empty($fallbackSecret)) {
            $fallbackSecret = 'dev-secret';
        }

        $this->app['config']->set('jwt.algo', $fallbackAlgorithm);
        $this->app['config']->set('jwt.secret', $fallbackSecret);
        $this->app['config']->set('app-context.jwt.algorithm', $fallbackAlgorithm);

        Log::warning('JWT RSA keys missing in dev environment. Falling back to symmetric signing.', [
            'algorithm' => $fallbackAlgorithm,
            'public_key_path' => $publicKeyPath,
            'private_key_path' => $privateKeyPath,
        ]);
    }
}
