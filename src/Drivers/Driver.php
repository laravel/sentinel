<?php

namespace Laravel\Sentinel\Drivers;

use Closure;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\IpUtils;

abstract class Driver
{
    /**
     * Construct a new driver.
     *
     * @param  Closure(): Application  $applicationResolver
     */
    public function __construct(protected Closure $applicationResolver)
    {
        //
    }

    /**
     * Authorize access for the request.
     */
    abstract public function authorize(Request $request): bool;

    /**
     * Authorize access for the request or throw an exception.
     *
     * @throws AuthorizationException
     */
    public function authorizeOrFail(Request $request): void
    {
        if ($this->authorize($request) === false) {
            throw new AuthorizationException;
        }
    }

    /**
     * Authorize accessing via reverse proxies.
     */
    protected function authorizeAccessingViaReverseProxies(Request $request): bool
    {
        if (! $this->isPrivateIp($request->ip()) && $request->isFromTrustedProxy()) {
            return false;
        }

        return true;
    }

    /**
     * Determine if the application is running on Docker locally.
     */
    protected function isRunningOnDockerLocally(Request $request): bool
    {
        return $request->server->get('REMOTE_ADDR') === '127.0.0.1' && file_exists(base_path('.dockerenv'));
    }

    /**
     * Checks if an IPv4 or IPv6 address is contained in the list of private IP subnets.
     */
    protected function isPrivateIp(string $requestIp): bool
    {
        return IpUtils::isPrivateIp($requestIp);
    }

    /**
     * Get the application instance.
     */
    protected function app(): Application
    {
        return ($this->applicationResolver)();
    }
}
