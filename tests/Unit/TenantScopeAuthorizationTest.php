<?php

declare(strict_types=1);

namespace Ronu\AppContext\Tests\Unit;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Auth;
use Ronu\AppContext\Scopes\TenantScope;
use Ronu\AppContext\Tests\TestCase;

class TenantScopeAuthorizationTest extends TestCase
{
    public function test_it_denies_cross_tenant_access_when_user_has_no_superuser_flag(): void
    {
        Auth::shouldReceive('user')->once()->andReturn((object) ['id' => 15]);

        $this->assertFalse($this->invokeHasSuperuserPrivileges(new TenantScope()));
    }

    public function test_it_allows_resolver_callback_for_custom_user_schema(): void
    {
        config()->set('tenancy.authorization.superuser_resolver', static fn (object $user): bool => $user->role === 'root');

        Auth::shouldReceive('user')->once()->andReturn((object) ['id' => 10, 'role' => 'root']);

        $this->assertTrue($this->invokeHasSuperuserPrivileges(new TenantScope()));
    }

    public function test_it_reads_superuser_flag_from_user_attributes(): void
    {
        $user = new class () extends Model {
            protected $guarded = [];
        };

        $user->forceFill(['is_superuser' => 1]);

        Auth::shouldReceive('user')->once()->andReturn($user);

        $this->assertTrue($this->invokeHasSuperuserPrivileges(new TenantScope()));
    }

    private function invokeHasSuperuserPrivileges(TenantScope $scope): bool
    {
        $method = new \ReflectionMethod(TenantScope::class, 'hasSuperuserPrivileges');
        $method->setAccessible(true);

        return (bool) $method->invoke($scope);
    }
}
