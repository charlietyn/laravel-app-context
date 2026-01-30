<?php

namespace Ronu\AppContext\Helpers;

use Illuminate\Support\Facades\Route;

class HelpersRouting
{
    /**
     * Dynamically loads module route files and automatically applies their namespace.
     *
     * @param string $filePattern The glob pattern to find the route files (e.g., `modules/{*}/Routes/api.php`)
     * @param string $channel The channel/prefix for the routes (default 'admin')
     * @return void
     */
    public static function loadModuleRoutes(string $filePattern,string $channel='admin'): void
    {
        // Find all files matching the pattern
        foreach (glob(base_path($filePattern)) as $filePath) {

            // Extract the module directory name (e.g., 'audit' from '/modules/audit/Routes/api.php')
            $moduleDir = basename(dirname(dirname($filePath)));

            if ($moduleDir && $moduleDir !== 'Modules') {
                // Construct the fully qualified namespace (e.g., 'Modules\Audit\Http\Controllers')
                // Using ucfirst() assumes module directory name matches the module's namespace casing
                $moduleNamespace = 'Modules\\' . ucfirst($moduleDir) . '\\Http\\Controllers';

                // Wrap the file requirement within a Route group that applies the namespace
                Route::group([
                    'namespace' => $moduleNamespace,
                    'as' => $channel . '.',
                ], function () use ($filePath) {
                    require $filePath;
                });
            }
        }
    }
}