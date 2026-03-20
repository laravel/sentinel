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
     * @param  \Closure(): \Illuminate\Contracts\Foundation\Application  $applicationResolver
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
     * @throws \Illuminate\Auth\Access\AuthorizationException
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
        if ($request->isFromTrustedProxy()) {
            $remoteAddr = $request->server->get('REMOTE_ADDR', '');

            // If the direct connecting IP is from a private network (RFC1918/ULA),
            // this is a legitimate reverse proxy such as Docker or a local load
            // balancer. Loopback addresses (127.x, ::1, and their IPv4-mapped
            // IPv6 equivalents) are excluded because tunnel services like Expose
            // and ngrok connect from loopback.
            if ($remoteAddr !== ''
                && $this->isPrivateIp($remoteAddr)
                && ! IpUtils::checkIp($remoteAddr, ['127.0.0.0/8', '::1/128', '::ffff:127.0.0.0/104'])) {
                return true;
            }

            if (! $this->isPrivateIp($request->ip())) {
                return false;
            }
        }

        return true;
    }

    /**
     * Checks if an IPv4 or IPv6 address is contained in the list of private IP subnets.
     */
    protected function isPrivateIp(string $requestIp): bool
    {
        /** @phpstan-ignore function.alreadyNarrowedType */
        if (method_exists(IpUtils::class, 'isPrivateIp')) {
            return IpUtils::isPrivateIp($requestIp);
        }

        return IpUtils::checkIp($requestIp, [
            '127.0.0.0/8',    // RFC1700 (Loopback)
            '10.0.0.0/8',     // RFC1918
            '192.168.0.0/16', // RFC1918
            '172.16.0.0/12',  // RFC1918
            '169.254.0.0/16', // RFC3927
            '0.0.0.0/8',      // RFC5735
            '240.0.0.0/4',    // RFC1112
            '::1/128',        // Loopback
            'fc00::/7',       // Unique Local Address
            'fe80::/10',      // Link Local Address
            '::ffff:0:0/96',  // IPv4 translations
            '::/128',         // Unspecified address
        ]);
    }

    /**
     * Get the application instance.
     */
    protected function app(): Application
    {
        return ($this->applicationResolver)();
    }
}
