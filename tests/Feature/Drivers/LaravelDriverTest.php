<?php

namespace Tests\Feature\Drivers;

use Illuminate\Http\Request;
use Laravel\Sentinel\Drivers\Laravel;
use Laravel\Sentinel\Sentinel;
use Symfony\Component\HttpFoundation\Request as SymfonyRequest;
use Tests\TestCase;

class LaravelDriverTest extends TestCase
{
    /** {@inheritdoc} */
    protected function defineEnvironment($app): void
    {
        $app['env'] = 'local';
    }

    public function test_it_authorizes_direct_localhost_connection(): void
    {
        $request = Request::create('/', 'GET', [], [], [], [
            'REMOTE_ADDR' => '127.0.0.1',
        ]);

        $this->assertTrue(Sentinel::driver('laravel')->authorize($request));
    }

    public function test_it_authorizes_valet_or_herd_request_when_trust_all_proxies_is_set(): void
    {
        // Simulates TrustProxies = '*', which is common for apps behind Cloudflare or
        // a load balancer. Valet and Herd inject X-Forwarded-For through their nginx
        // layer, causing $request->ip() to resolve to a non-private IP. Without the
        // REMOTE_ADDR check, this combination silently returns 401 on /telescope and
        // similar developer tool routes.
        Request::setTrustedProxies(['REMOTE_ADDR'], SymfonyRequest::HEADER_X_FORWARDED_FOR);

        $request = Request::create('/', 'GET', [], [], [], [
            'REMOTE_ADDR'          => '127.0.0.1',
            'HTTP_X_FORWARDED_FOR' => '203.0.113.42', // public IP injected by Valet/Herd nginx
        ]);

        $this->assertTrue(Sentinel::driver('laravel')->authorize($request));
    }

public function test_it_always_authorizes_in_non_local_environments(): void
    {
        $this->app['env'] = 'production';

        $request = Request::create('/', 'GET', [], [], [], [
            'REMOTE_ADDR' => '203.0.113.42', // public IP, no proxies
        ]);

        $this->assertTrue(Sentinel::driver('laravel')->authorize($request));
    }
}
