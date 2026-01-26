<?php

namespace Ronu\AppContext\Commands;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Route;
use Illuminate\Routing\Route as LaravelRoute;
class RoutesByChannel extends Command
{
    protected $signature = 'route:channel
        {channel : admin|site|mobile|partner}
        {--orphans : Show routes that do not belong to any channel}
        {--json : Output as JSON}';

    protected $description = 'List routes for a given channel (admin/site/mobile/partner) or show orphan routes.';

    public function handle(): int
    {
        $channels = ['admin', 'site', 'mobile', 'partner'];

        if ($this->option('orphans')) {
            $routes = collect(Route::getRoutes()->getRoutes())
                ->filter(fn (LaravelRoute $r) => !$this->belongsToAnyChannel($r, $channels))
                ->values();

            return $this->render($routes, 'ORPHANS');
        }

        $channel = (string) $this->argument('channel');

        if (!in_array($channel, $channels, true)) {
            $this->error("Invalid channel. Allowed: " . implode(', ', $channels));
            return self::FAILURE;
        }

        $routes = collect(Route::getRoutes()->getRoutes())
            ->filter(fn (LaravelRoute $r) => $this->belongsToChannel($r, $channel))
            ->values();

        return $this->render($routes, strtoupper($channel));
    }

    private function belongsToChannel(LaravelRoute $r, string $channel): bool
    {
        $uri = ltrim($r->uri(), '/');

        // Matches "admin/..." exactly (not "administrator/...").
        return $uri === $channel || str_starts_with($uri, $channel . '/');
    }

    private function belongsToAnyChannel(LaravelRoute $r, array $channels): bool
    {
        foreach ($channels as $c) {
            if ($this->belongsToChannel($r, $c)) return true;
        }
        return false;
    }

    private function render($routes, string $title): int
    {
        if ($this->option('json')) {
            $payload = $routes->map(fn (LaravelRoute $r) => [
                'methods' => $r->methods(),
                'uri' => $r->uri(),
                'name' => $r->getName(),
                'action' => $r->getActionName(),
                'middleware' => $r->gatherMiddleware(),
            ])->all();

            $this->line(json_encode([
                'title' => $title,
                'count' => count($payload),
                'routes' => $payload,
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

            return self::SUCCESS;
        }

        $this->info($title . " ROUTES: " . $routes->count());

        $this->table(
            ['Methods', 'URI', 'Name', 'Action'],
            $routes->map(fn (LaravelRoute $r) => [
                implode('|', $r->methods()),
                '/' . $r->uri(),
                $r->getName() ?: '',
                $r->getActionName(),
            ])->all()
        );

        return self::SUCCESS;
    }
}