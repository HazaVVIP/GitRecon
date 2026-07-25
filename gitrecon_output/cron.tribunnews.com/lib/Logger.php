<?php
class Logger
{
    const DEBUG   = 10;
    const INFO    = 20;
    const WARNING = 30;
    const ERROR   = 40;

    private $logFile;

    private $minLevel;

    private $handle = null;

    private static $levelMap = [
        'debug'   => self::DEBUG,
        'info'    => self::INFO,
        'warning' => self::WARNING,
        'error'   => self::ERROR,
    ];

    public function __construct(string $logDir, string $prefix = 'cron', string $minLevel = 'info')
    {
        if (!is_dir($logDir)) {
            mkdir($logDir, 0775, true);
        }

        $this->logFile  = rtrim($logDir, '/') . '/' . $prefix . '_' . date('Y-m-d') . '.log';
        $this->minLevel = self::$levelMap[strtolower($minLevel)] ?? self::INFO;

        $this->handle = fopen($this->logFile, 'a');
    }

    public function debug(string $msg, array $ctx = []): void   { $this->write(self::DEBUG,   'DEBUG',   $msg, $ctx); }
    public function info(string $msg, array $ctx = []): void    { $this->write(self::INFO,    'INFO',    $msg, $ctx); }
    public function warning(string $msg, array $ctx = []): void { $this->write(self::WARNING, 'WARNING', $msg, $ctx); }
    public function error(string $msg, array $ctx = []): void   { $this->write(self::ERROR,   'ERROR',   $msg, $ctx); }

    private function write(int $level, string $label, string $msg, array $ctx): void
    {
        if ($level < $this->minLevel || !$this->handle) {
            return;
        }

        $ts      = date('Y-m-d H:i:s');
        $ctxStr  = empty($ctx) ? '' : ' ' . json_encode($ctx, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        $line    = "[{$ts}] [{$label}] {$msg}{$ctxStr}" . PHP_EOL;

        fwrite($this->handle, $line);

        echo $line."\n<br>";
    }

    public function __destruct()
    {
        if ($this->handle) {
            fclose($this->handle);
        }
    }
}
