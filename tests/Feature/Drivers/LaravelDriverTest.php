<?php

namespace Tests\Feature\Drivers;

use Illuminate\Http\Request;
use Laravel\Sentinel\Sentinel;
use RuntimeException;
use Symfony\Component\HttpFoundation\Request as SymfonyRequest;
use Tests\TestCase;

class LaravelDriverTest extends TestCase
{
    /** {@inheritdoc} */
    protected function resolveApplicationCore($app): void
    {
        parent::resolveApplicationCore($app);

        $app->detectEnvironment(fn () => 'local');
    }

    protected function createRequest(
        string $remoteAddr = '127.0.0.1',
        string $host = 'localhost',
        array $trustedProxies = [],
        ?string $forwardedFor = null,
    ): Request {
        $server = [
            'REMOTE_ADDR' => $remoteAddr,
            'HTTP_HOST' => $host,
            'SERVER_NAME' => $host,
        ];

        if ($forwardedFor !== null) {
            $server['HTTP_X_FORWARDED_FOR'] = $forwardedFor;
        }

        if (! empty($trustedProxies)) {
            Request::setTrustedProxies($trustedProxies, Request::HEADER_X_FORWARDED_FOR);
        }

        return Request::createFromBase(new SymfonyRequest(
            query: [], request: [], attributes: [], cookies: [], files: [], server: $server,
        ));
    }

    /** {@inheritdoc} */
    protected function tearDown(): void
    {
        Request::setTrustedProxies([], Request::HEADER_X_FORWARDED_FOR);

        parent::tearDown();
    }

    public function test_docker_bridge_allowed_via_trusted_proxy(): void
    {
        $request = $this->createRequest(
            remoteAddr: '172.18.0.1',
            trustedProxies: ['172.18.0.1'],
            forwardedFor: '203.0.113.50',
        );

        $this->assertTrue(Sentinel::driver()->authorize($request));
    }

    public function test_docker_10_network_allowed(): void
    {
        $request = $this->createRequest(
            remoteAddr: '10.0.0.1',
            trustedProxies: ['10.0.0.1'],
            forwardedFor: '203.0.113.50',
        );

        $this->assertTrue(Sentinel::driver()->authorize($request));
    }

    public function test_sail_default_network_allowed(): void
    {
        $request = $this->createRequest(
            remoteAddr: '172.20.0.1',
            trustedProxies: ['172.20.0.1'],
            forwardedFor: '192.168.65.1',
        );

        $this->assertTrue(Sentinel::driver()->authorize($request));
    }

    public function test_wildcard_trusted_proxies_with_docker(): void
    {
        $request = $this->createRequest(
            remoteAddr: '172.18.0.1',
            trustedProxies: ['0.0.0.0/0'],
            forwardedFor: '172.67.152.165',
        );

        $this->assertTrue(Sentinel::driver()->authorize($request));
    }

    public function test_loopback_not_allowed_via_trusted_proxy(): void
    {
        $request = $this->createRequest(
            remoteAddr: '127.0.0.1',
            host: 'myapp.example.com',
            trustedProxies: ['127.0.0.1'],
            forwardedFor: '203.0.113.50',
        );

        $this->assertFalse(Sentinel::driver()->authorize($request));
    }

    public function test_ipv4_mapped_loopback_blocked(): void
    {
        $request = $this->createRequest(
            remoteAddr: '::ffff:127.0.0.1',
            host: 'myapp.example.com',
            trustedProxies: ['::ffff:127.0.0.1'],
            forwardedFor: '203.0.113.50',
        );

        $this->assertFalse(Sentinel::driver()->authorize($request));
    }

    public function test_expose_tunnel_throws_without_trusted_proxy(): void
    {
        $request = $this->createRequest('127.0.0.1', 'myapp.sharedwithexpose.com');

        $this->expectException(RuntimeException::class);
        Sentinel::driver()->authorize($request);
    }

    public function test_expose_tunnel_blocked_with_trusted_proxy(): void
    {
        $request = $this->createRequest(
            remoteAddr: '127.0.0.1',
            host: 'myapp.sharedwithexpose.com',
            trustedProxies: ['127.0.0.1'],
            forwardedFor: '203.0.113.50',
        );

        $this->assertFalse(Sentinel::driver()->authorize($request));
    }

    public function test_ngrok_tunnel_blocked_with_trusted_proxy(): void
    {
        $request = $this->createRequest(
            remoteAddr: '127.0.0.1',
            host: 'abc123.ngrok-free.app',
            trustedProxies: ['127.0.0.1'],
            forwardedFor: '203.0.113.50',
        );

        $this->assertFalse(Sentinel::driver()->authorize($request));
    }

    public function test_tunnel_blocked_even_without_forwarded_headers(): void
    {
        $request = $this->createRequest(
            remoteAddr: '127.0.0.1',
            host: 'myapp.sharedwithexpose.com',
            trustedProxies: ['127.0.0.1'],
        );

        $this->assertFalse(Sentinel::driver()->authorize($request));
    }

    public function test_docker_192_168_network_allowed(): void
    {
        $request = $this->createRequest(
            remoteAddr: '192.168.1.1',
            trustedProxies: ['192.168.1.1'],
            forwardedFor: '203.0.113.50',
        );

        $this->assertTrue(Sentinel::driver()->authorize($request));
    }

    public function test_ipv6_ula_docker_network_allowed(): void
    {
        $request = $this->createRequest(
            remoteAddr: 'fd12:3456:789a::1',
            trustedProxies: ['fd12:3456:789a::1'],
            forwardedFor: '2001:db8::1',
        );

        $this->assertTrue(Sentinel::driver()->authorize($request));
    }

    public function test_ipv4_mapped_ipv6_docker_allowed(): void
    {
        $request = $this->createRequest(
            remoteAddr: '::ffff:172.18.0.1',
            trustedProxies: ['::ffff:172.18.0.1'],
            forwardedFor: '203.0.113.50',
        );

        $this->assertTrue(Sentinel::driver()->authorize($request));
    }

    public function test_ipv6_loopback_blocked_with_trusted_proxy(): void
    {
        $request = $this->createRequest(
            remoteAddr: '::1',
            host: 'myapp.example.com',
            trustedProxies: ['::1'],
            forwardedFor: '203.0.113.50',
        );

        $this->assertFalse(Sentinel::driver()->authorize($request));
    }

    public function test_ngrok_io_tunnel_blocked_with_trusted_proxy(): void
    {
        $request = $this->createRequest(
            remoteAddr: '127.0.0.1',
            host: 'abc123.ngrok.io',
            trustedProxies: ['127.0.0.1'],
            forwardedFor: '203.0.113.50',
        );

        $this->assertFalse(Sentinel::driver()->authorize($request));
    }

    public function test_herd_test_domain_allowed(): void
    {
        $request = $this->createRequest('127.0.0.1', 'myapp.test');
        $this->assertTrue(Sentinel::driver()->authorize($request));
    }

    public function test_forwarded_for_chain(): void
    {
        $request = $this->createRequest(
            remoteAddr: '172.18.0.1',
            trustedProxies: ['172.18.0.1'],
            forwardedFor: '203.0.113.50, 10.0.0.1',
        );

        $this->assertTrue(Sentinel::driver()->authorize($request));
    }

    public function test_public_remote_addr_blocked(): void
    {
        $request = $this->createRequest(
            remoteAddr: '203.0.113.1',
            host: 'myapp.com',
            trustedProxies: ['203.0.113.1'],
            forwardedFor: '198.51.100.50',
        );

        $this->assertFalse(Sentinel::driver()->authorize($request));
    }

    public function test_expose_tunnel_via_docker_proxy_blocked(): void
    {
        // Expose running on host, traffic routes through Docker proxy.
        // The tunnel hostname check in Laravel.php fires first and blocks it.
        $request = $this->createRequest(
            remoteAddr: '172.18.0.1',
            host: 'myapp.sharedwithexpose.com',
            trustedProxies: ['172.18.0.1'],
            forwardedFor: '203.0.113.50',
        );

        $this->assertFalse(Sentinel::driver()->authorize($request));
    }

    public function test_non_local_environment_allows_access(): void
    {
        $this->app->detectEnvironment(fn () => 'production');

        $request = $this->createRequest('203.0.113.50', 'myapp.com');
        $this->assertTrue(Sentinel::driver()->authorize($request));
    }
}
