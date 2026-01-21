<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('api_clients', function (Blueprint $table) {
            $table->uuid('id')->primary();

            // Client identification
            $table->string('name');
            $table->string('app_code')->unique()->comment('Used as X-Client-Id header');
            $table->string('key_hash')->comment('Argon2id or Bcrypt hash of API key');
            $table->string('key_prefix', 20)->nullable()->comment('First chars of key for identification');

            // Authorization
            $table->string('channel')->default('partner')->comment('Authorized channel');
            $table->string('tenant_id')->nullable()->index()->comment('Tenant restriction');
            $table->json('config')->comment('Capabilities, rate limits, webhook URL, etc.');
            $table->json('ip_allowlist')->nullable()->comment('IP allowlist with CIDR support');

            // Status
            $table->boolean('is_active')->default(true)->index();
            $table->boolean('is_revoked')->default(false)->index();
            $table->timestamp('expires_at')->nullable()->index();

            // Usage tracking
            $table->timestamp('last_used_at')->nullable();
            $table->string('last_used_ip', 45)->nullable();
            $table->unsignedBigInteger('usage_count')->default(0);

            // Timestamps
            $table->timestamps();
            $table->softDeletes();

            // Indexes
            $table->index(['channel', 'is_active']);
            $table->index(['tenant_id', 'is_active']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('api_clients');
    }
};
