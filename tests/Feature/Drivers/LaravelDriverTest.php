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

        $symfonyRequest = new SymfonyRequest(
            query: [],
            request: [],
            attributes: [],
            cookies: [],
            files: [],
            server: $server,
        );

        if (! empty($trustedProxies)) {
            Request::setTrustedProxies($trustedProxies, Request::HEADER_X_FORWARDED_FOR);
        }

        return Request::createFromBase($symfonyRequest);
    }

    /** {@inheritdoc} */
    protected function tearDown(): void
    {
        Request::setTrustedProxies([], Request::HEADER_X_FORWARDED_FOR);

        parent::tearDown();
    }

    // ---------------------------------------------------------------
    // Non-local environment — always allowed
    // ---------------------------------------------------------------

    public function test_non_local_environment_allows_access(): void
    {
        $this->app->detectEnvironment(fn () => 'production');
        $driver = Sentinel::driver();

        $request = $this->createRequest('203.0.113.50', 'myapp.com');
        $this->assertTrue($driver->authorize($request));
    }

    // ---------------------------------------------------------------
    // Normal local development — allowed
    // ---------------------------------------------------------------

    public function test_localhost_access_allowed(): void
    {
        $driver = Sentinel::driver();

        $request = $this->createRequest('127.0.0.1', 'localhost');
        $this->assertTrue($driver->authorize($request));
    }

    public function test_ipv6_loopback_access_allowed(): void
    {
        $driver = Sentinel::driver();

        $request = $this->createRequest('::1', 'localhost');
        $this->assertTrue($driver->authorize($request));
    }

    // ---------------------------------------------------------------
    // Docker / reverse proxy — the bug fix
    // ---------------------------------------------------------------

    public function test_docker_bridge_gateway_allowed_via_trusted_proxy(): void
    {
        $driver = Sentinel::driver();

        // Docker default bridge: REMOTE_ADDR=172.17.0.1, forwarded to non-private IP
        $request = $this->createRequest(
            remoteAddr: '172.17.0.1',
            host: 'localhost',
            trustedProxies: ['172.17.0.1'],
            forwardedFor: '203.0.113.50',
        );

        $this->assertTrue($driver->authorize($request));
    }

    public function test_docker_custom_bridge_allowed(): void
    {
        $driver = Sentinel::driver();

        // Docker Compose custom bridge: 172.18.0.1
        $request = $this->createRequest(
            remoteAddr: '172.18.0.1',
            host: 'localhost',
            trustedProxies: ['172.18.0.1'],
            forwardedFor: '172.67.152.165',
        );

        $this->assertTrue($driver->authorize($request));
    }

    public function test_docker_10_network_allowed(): void
    {
        $driver = Sentinel::driver();

        $request = $this->createRequest(
            remoteAddr: '10.0.0.1',
            host: 'localhost',
            trustedProxies: ['10.0.0.1'],
            forwardedFor: '203.0.113.50',
        );

        $this->assertTrue($driver->authorize($request));
    }

    public function test_docker_192_168_network_allowed(): void
    {
        $driver = Sentinel::driver();

        $request = $this->createRequest(
            remoteAddr: '192.168.1.1',
            host: 'localhost',
            trustedProxies: ['192.168.1.1'],
            forwardedFor: '203.0.113.50',
        );

        $this->assertTrue($driver->authorize($request));
    }

    public function test_docker_desktop_mac_nat_translation_allowed(): void
    {
        $driver = Sentinel::driver();

        // Docker Desktop for Mac: gateway 172.18.0.1, NAT resolves to
        // Cloudflare IP 172.67.x (outside 172.16.0.0/12 private range)
        $request = $this->createRequest(
            remoteAddr: '172.18.0.1',
            host: 'localhost',
            trustedProxies: ['172.18.0.1'],
            forwardedFor: '172.67.152.165',
        );

        $this->assertTrue($driver->authorize($request));
    }

    public function test_laravel_sail_default_network_allowed(): void
    {
        $driver = Sentinel::driver();

        $request = $this->createRequest(
            remoteAddr: '172.20.0.1',
            host: 'localhost',
            trustedProxies: ['172.20.0.1'],
            forwardedFor: '192.168.65.1',
        );

        $this->assertTrue($driver->authorize($request));
    }

    public function test_wildcard_trusted_proxies_with_docker(): void
    {
        $driver = Sentinel::driver();

        // TRUSTED_PROXIES=* (common in Sail)
        $request = $this->createRequest(
            remoteAddr: '172.18.0.1',
            host: 'localhost',
            trustedProxies: ['0.0.0.0/0'],
            forwardedFor: '172.67.152.165',
        );

        $this->assertTrue($driver->authorize($request));
    }

    public function test_ipv6_docker_network_allowed(): void
    {
        $driver = Sentinel::driver();

        // Docker with IPv6 ULA networking
        $request = $this->createRequest(
            remoteAddr: 'fd12:3456:789a::1',
            host: 'localhost',
            trustedProxies: ['fd12:3456:789a::1'],
            forwardedFor: '2001:db8::1',
        );

        $this->assertTrue($driver->authorize($request));
    }

    // ---------------------------------------------------------------
    // Tunnel services — must remain blocked
    // ---------------------------------------------------------------

    public function test_expose_tunnel_throws_without_trusted_proxy(): void
    {
        $driver = Sentinel::driver();

        $request = $this->createRequest('127.0.0.1', 'myapp.sharedwithexpose.com');

        $this->expectException(RuntimeException::class);
        $driver->authorize($request);
    }

    public function test_expose_tunnel_blocked_with_trusted_proxy(): void
    {
        $driver = Sentinel::driver();

        // Expose: REMOTE_ADDR=127.0.0.1 (loopback), public forwarded IP
        $request = $this->createRequest(
            remoteAddr: '127.0.0.1',
            host: 'myapp.sharedwithexpose.com',
            trustedProxies: ['127.0.0.1'],
            forwardedFor: '203.0.113.50',
        );

        // Loopback is excluded from the Docker allowance, so falls through
        // to the resolved IP check — non-private → blocked
        $this->assertFalse($driver->authorize($request));
    }

    public function test_ngrok_free_tunnel_throws_without_trusted_proxy(): void
    {
        $driver = Sentinel::driver();

        $request = $this->createRequest('127.0.0.1', 'abc123.ngrok-free.app');

        $this->expectException(RuntimeException::class);
        $driver->authorize($request);
    }

    public function test_ngrok_free_tunnel_blocked_with_trusted_proxy(): void
    {
        $driver = Sentinel::driver();

        $request = $this->createRequest(
            remoteAddr: '127.0.0.1',
            host: 'abc123.ngrok-free.app',
            trustedProxies: ['127.0.0.1'],
            forwardedFor: '203.0.113.50',
        );

        $this->assertFalse($driver->authorize($request));
    }

    public function test_ngrok_io_tunnel_throws_without_trusted_proxy(): void
    {
        $driver = Sentinel::driver();

        $request = $this->createRequest('127.0.0.1', 'abc123.ngrok.io');

        $this->expectException(RuntimeException::class);
        $driver->authorize($request);
    }

    public function test_ngrok_io_tunnel_blocked_with_trusted_proxy(): void
    {
        $driver = Sentinel::driver();

        $request = $this->createRequest(
            remoteAddr: '127.0.0.1',
            host: 'abc123.ngrok.io',
            trustedProxies: ['127.0.0.1'],
            forwardedFor: '203.0.113.50',
        );

        $this->assertFalse($driver->authorize($request));
    }

    public function test_cloudflare_tunnel_loopback_blocked(): void
    {
        $driver = Sentinel::driver();

        // Cloudflare Tunnel (cloudflared) connects from 127.0.0.1 with custom domain
        $request = $this->createRequest(
            remoteAddr: '127.0.0.1',
            host: 'myapp.example.com',
            trustedProxies: ['127.0.0.1'],
            forwardedFor: '203.0.113.50',
        );

        $this->assertFalse($driver->authorize($request));
    }

    public function test_ipv6_loopback_blocked_with_trusted_proxy(): void
    {
        $driver = Sentinel::driver();

        // IPv6 loopback is also excluded from the Docker allowance
        $request = $this->createRequest(
            remoteAddr: '::1',
            host: 'myapp.sharedwithexpose.com',
            trustedProxies: ['::1'],
            forwardedFor: '2001:db8::1',
        );

        $this->assertFalse($driver->authorize($request));
    }

    // ---------------------------------------------------------------
    // Public REMOTE_ADDR — blocked
    // ---------------------------------------------------------------

    public function test_public_remote_addr_via_trusted_proxy_blocked(): void
    {
        $driver = Sentinel::driver();

        $request = $this->createRequest(
            remoteAddr: '203.0.113.1',
            host: 'myapp.com',
            trustedProxies: ['203.0.113.1'],
            forwardedFor: '198.51.100.50',
        );

        $this->assertFalse($driver->authorize($request));
    }

    public function test_cloudflare_edge_public_ip_blocked(): void
    {
        $driver = Sentinel::driver();

        $request = $this->createRequest(
            remoteAddr: '104.16.0.1',
            host: 'myapp.com',
            trustedProxies: ['104.16.0.0/12'],
            forwardedFor: '203.0.113.50',
        );

        $this->assertFalse($driver->authorize($request));
    }

    // ---------------------------------------------------------------
    // Edge cases
    // ---------------------------------------------------------------

    public function test_trusted_proxy_with_private_forwarded_ip_allowed(): void
    {
        $driver = Sentinel::driver();

        // Docker proxy forwarding to another private IP — both are private
        $request = $this->createRequest(
            remoteAddr: '172.18.0.1',
            host: 'localhost',
            trustedProxies: ['172.18.0.1'],
            forwardedFor: '192.168.1.100',
        );

        $this->assertTrue($driver->authorize($request));
    }

    public function test_forwarded_for_chain(): void
    {
        $driver = Sentinel::driver();

        // Multiple proxies in chain
        $request = $this->createRequest(
            remoteAddr: '172.18.0.1',
            host: 'localhost',
            trustedProxies: ['172.18.0.1'],
            forwardedFor: '203.0.113.50, 10.0.0.1',
        );

        $this->assertTrue($driver->authorize($request));
    }

    public function test_herd_test_domain_without_proxy(): void
    {
        $driver = Sentinel::driver();

        $request = $this->createRequest('127.0.0.1', 'myapp.test');
        $this->assertTrue($driver->authorize($request));
    }

    public function test_kubernetes_pod_network(): void
    {
        $driver = Sentinel::driver();

        $request = $this->createRequest(
            remoteAddr: '10.244.0.1',
            host: 'myservice.default.svc.cluster.local',
            trustedProxies: ['10.244.0.1'],
            forwardedFor: '10.0.0.50',
        );

        $this->assertTrue($driver->authorize($request));
    }
}
