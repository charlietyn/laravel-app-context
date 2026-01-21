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
            $table->id();

            // Client identification
            $table->string('app_code', 64)->unique()->comment('Unique client identifier');
            $table->string('app_name')->comment('Human-readable client name');
            $table->text('description')->nullable();

            // Channel assignment
            $table->string('channel', 32)->default('partner')->comment('Channel: partner, admin, mobile, site');

            // Authentication
            $table->text('key_hash')->comment('Hashed API key (Argon2id)');
            $table->string('key_prefix', 16)->nullable()->index()->comment('Key prefix for fast lookup');

            // Authorization
            $table->json('config')->nullable()->comment('Capabilities, rate limits, etc.');

            // Multi-tenant
            $table->string('tenant_id', 64)->nullable()->index();

            // Status
            $table->boolean('is_active')->default(true)->index();
            $table->timestamp('expires_at')->nullable()->index();
            $table->timestamp('revoked_at')->nullable();

            // Contact
            $table->string('owner_email')->nullable();

            // Audit
            $table->json('metadata')->nullable()->comment('last_used_at, last_used_ip, etc.');
            $table->timestamps();
            $table->softDeletes();

            // Indexes
            $table->index(['is_active', 'channel']);
            $table->index(['app_code', 'is_active']);
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
