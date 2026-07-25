<?php
class Helper
{
    public static function buildKey(string $domain, string $alias, string $publishDate = ''): string
    {
        $domain = trim($domain, '/');
        $alias  = trim($alias, '/');

        // Hapus ekstensi .json jika alias sudah mengandungnya (hindari double .json)
        if (substr($alias, -5) === '.json') {
            $alias = substr($alias, 0, -5);
        }

        return "{$domain}/{$alias}.json";
    }

    public static function memoryUsage(bool $peak = false): string
    {
        $bytes = $peak ? memory_get_peak_usage(true) : memory_get_usage(true);
        return self::formatBytes($bytes);
    }

    public static function formatBytes(int $bytes, int $precision = 2): string
    {
        $units = ['B', 'KB', 'MB', 'GB'];
        $i     = 0;
        while ($bytes >= 1024 && $i < count($units) - 1) {
            $bytes /= 1024;
            $i++;
        }
        return round($bytes, $precision) . ' ' . $units[$i];
    }

    public static function formatDuration(float $seconds): string
    {
        $h = (int)($seconds / 3600);
        $m = (int)(($seconds % 3600) / 60);
        $s = (int)($seconds % 60);

        $parts = [];
        if ($h > 0) $parts[] = "{$h}h";
        if ($m > 0) $parts[] = "{$m}m";
        $parts[] = "{$s}s";

        return implode(' ', $parts);
    }

    public static function sanitizeDomain(string $domain): string
    {
        $domain = preg_replace('#^https?://#', '', $domain);
        return trim($domain, '/');
    }

    public static function getParam(int $argvIndex, string $getKey, string $default = ''): string
    {
        if (PHP_SAPI === 'cli' && isset($_SERVER['argv'][$argvIndex])) {
            return (string)$_SERVER['argv'][$argvIndex];
        }
        if (isset($_GET[$getKey]) && $_GET[$getKey] !== '') {
            return (string)$_GET[$getKey];
        }
        return $default;
    }
}
