<?php

declare(strict_types=1);

spl_autoload_register(function ($class) {
    $prefix = 'EidCloud\\AgentBlackbox\\';
    $baseDir = __DIR__ . '/../src/';

    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return;
    }

    $relativeClass = substr($class, $len);
    $file = $baseDir . str_replace('\\', '/', $relativeClass) . '.php';

    if (file_exists($file)) {
        require_once $file;
    }
});

require_once __DIR__ . '/BlackboxTest.php';

use EidCloud\AgentBlackbox\Tests\BlackboxTest;

echo "=========================================================\n";
echo " Running EidCloud Agent Black Box Test Suite (Pure PHP)\n";
echo "=========================================================\n";

$testSuite = new BlackboxTest();
$methods = get_class_methods($testSuite);
$testMethods = array_filter($methods, fn($m) => str_starts_with($m, 'test'));

$passed = 0;
$failed = 0;

foreach ($testMethods as $test) {
    echo "• Running {$test}... ";
    try {
        $testSuite->$test();
        echo "OK\n";
        $passed++;
    } catch (\Throwable $e) {
        echo "FAILED\n";
        echo "  " . $e->getMessage() . "\n";
        $failed++;
    }
}

echo "---------------------------------------------------------\n";
echo sprintf("Summary: %d tests, %d assertions, %d passed, %d failed.\n", count($testMethods), $testSuite->getAssertionsCount(), $passed, $failed);
echo "=========================================================\n";

if ($failed > 0) {
    exit(1);
}

exit(0);
