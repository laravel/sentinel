<?php

namespace Tests\Feature\Drivers;

use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Http\Request;
use Laravel\Sentinel\Drivers\Driver;
use Laravel\Sentinel\Sentinel;
use Laravel\Sentinel\SentinelManager;
use Orchestra\Testbench\Concerns\InteractsWithPublishedFiles;
use Symfony\Component\HttpFoundation\Request as SymfonyRequest;
use Tests\TestCase;

class DriverTest extends TestCase
{
    use InteractsWithPublishedFiles;

    /**
     * List of published files to be deleted after the test.
     */
    protected $files = [
        '.dockerenv',
    ];

    protected function tearDown(): void
    {
        unset($_ENV['SENTINEL_LOCAL_IP'], $_SERVER['SENTINEL_LOCAL_IP']);

        parent::tearDown();
    }

    /** {@inheritdoc} */
    protected function defineEnvironment($app): void
    {
        Request::setTrustedProxies(['127.0.0.1'], SymfonyRequest::HEADER_X_FORWARDED_FOR | SymfonyRequest::HEADER_X_FORWARDED_HOST | SymfonyRequest::HEADER_X_FORWARDED_PORT | SymfonyRequest::HEADER_X_FORWARDED_PROTO);

        $manager = $app->make(SentinelManager::class);

        $manager->extend('testing', function ($app) {
            return new class(fn () => $app) extends Driver
            {
                public function authorize(Request $request): bool
                {
                    return $this->authorizeAccessingViaReverseProxies($request);
                }
            };
        });

        $manager->extend('testing-docker', function ($app) {
            return new class(fn () => $app) extends Driver
            {
                public function authorize(Request $request): bool
                {
                    return $this->isRunningOnDockerLocally($request);
                }
            };
        });

        $manager->extend('testing-valet', function ($app) {
            return new class(fn () => $app) extends Driver
            {
                public function authorize(Request $request): bool
                {
                    return $this->isRunningOnValetLocally($request);
                }
            };
        });

        $manager->extend('testing-herd', function ($app) {
            return new class(fn () => $app) extends Driver
            {
                public function authorize(Request $request): bool
                {
                    return $this->isRunningOnHerdLocally($request);
                }
            };
        });
    }

    public function test_it_can_authorize_local_request()
    {
        $request = Request::create('GET', '/', [
            'REMOTE_ADDR' => '127.0.0.1',
        ]);

        tap(Sentinel::driver('testing'), function ($driver) use ($request) {
            $this->assertTrue($driver->authorize($request));
        });
    }

    public function test_it_can_authorize_reverse_proxy_request()
    {
        $request = Request::create('GET', '/', [
            'REMOTE_ADDR' => '127.0.0.1',
            'HOST' => 'laravel.ngrok.io',
            'X-FORWARDED-FOR' => '127.0.0.1',
            'X-FORWARDED-HOST' => 'laravel.ngrok.io',
            'X-FORWARDED-PROTO' => 'https',
        ]);

        tap(Sentinel::driver('testing'), function ($driver) use ($request) {
            $this->assertTrue($driver->authorize($request));
        });
    }

    public function test_it_can_authorize_reverse_proxy_request_when_forwarding_for_public_ips()
    {
        $request = Request::create('/', 'GET', [], [], [], $this->transformHeadersToServerVars([
            'REMOTE_ADDR' => '127.0.0.1',
            'HOST' => 'laravel.ngrok.io',
            'X-FORWARDED-FOR' => '202.168.65.217',
            'X-FORWARDED-HOST' => 'laravel.ngrok.io',
            'X-FORWARDED-PROTO' => 'https',
        ]));

        tap(Sentinel::driver('testing'), function ($driver) use ($request) {
            $this->assertFalse($driver->authorize($request));
        });
    }

    public function test_it_can_authorize_or_fail_reverse_proxy_request_when_forwarding_for_public_ips()
    {
        $this->expectException(AuthorizationException::class);
        $this->expectExceptionMessage('This action is unauthorized.');

        $request = Request::create('/', 'GET', [], [], [], $this->transformHeadersToServerVars([
            'REMOTE_ADDR' => '127.0.0.1',
            'HOST' => 'laravel.ngrok.io',
            'X-FORWARDED-FOR' => '202.168.65.217',
            'X-FORWARDED-HOST' => 'laravel.ngrok.io',
            'X-FORWARDED-PROTO' => 'https',
        ]));

        Sentinel::driver('testing')->authorizeOrFail($request);
    }

    public function test_it_can_authorize_docker_local_request()
    {
        $request = Request::create('GET', '/', [
            'REMOTE_ADDR' => '127.0.0.1',
        ]);

        tap(Sentinel::driver('testing-docker'), function ($driver) use ($request) {
            $this->assertFalse($driver->authorize($request));
        });

        $files = new Filesystem;
        $files->put(base_path('.dockerenv'), '');

        tap(Sentinel::driver('testing-docker'), function ($driver) use ($request) {
            $this->assertTrue($driver->authorize($request));
        });
    }

    public function test_it_can_authorize_docker_local_request_with_custom_local_ip()
    {
        $_ENV['SENTINEL_LOCAL_IP'] = '192.168.65.1';

        $files = new Filesystem;
        $files->put(base_path('.dockerenv'), '');

        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '127.0.0.1']);

        tap(Sentinel::driver('testing-docker'), function ($driver) use ($request) {
            $this->assertFalse($driver->authorize($request));
        });

        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '192.168.65.1']);

        tap(Sentinel::driver('testing-docker'), function ($driver) use ($request) {
            $this->assertTrue($driver->authorize($request));
        });
    }

    public function test_it_can_authorize_valet_local_request_via_server_var()
    {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '127.0.0.1']);

        tap(Sentinel::driver('testing-valet'), function ($driver) use ($request) {
            $this->assertFalse($driver->authorize($request));
        });

        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '127.0.0.1', 'IS_VALET' => '1']);

        tap(Sentinel::driver('testing-valet'), function ($driver) use ($request) {
            $this->assertTrue($driver->authorize($request));
        });
    }

    public function test_it_rejects_valet_request_from_non_local_remote_addr()
    {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.0.5', 'IS_VALET' => '1']);

        tap(Sentinel::driver('testing-valet'), function ($driver) use ($request) {
            $this->assertFalse($driver->authorize($request));
        });
    }

    public function test_it_can_authorize_herd_local_request()
    {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '127.0.0.1']);

        tap(Sentinel::driver('testing-herd'), function ($driver) use ($request) {
            $this->assertFalse($driver->authorize($request));
        });

        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '127.0.0.1', 'SERVER_SOFTWARE' => 'nginx/1.25.3 (herd)']);

        tap(Sentinel::driver('testing-herd'), function ($driver) use ($request) {
            $this->assertTrue($driver->authorize($request));
        });
    }

    public function test_it_rejects_herd_request_from_non_local_remote_addr()
    {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.0.5', 'SERVER_SOFTWARE' => 'nginx/1.25.3 (herd)']);

        tap(Sentinel::driver('testing-herd'), function ($driver) use ($request) {
            $this->assertFalse($driver->authorize($request));
        });
    }
}
