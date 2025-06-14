<?php

namespace App\Console;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;

class Kernel extends ConsoleKernel
{
    /**
     * Define the application's command schedule.
     */
    protected function schedule(Schedule $schedule): void
    {
        // $schedule->command('inspire')->hourly();

        /* 
        Задача для удаления всех записей об истекших токенах в базе данных, 
        которые были истекшие как минимум 24 часа.
        */
        $schedule->command('sanctum:prune-expired --hours=24')->daily();
        // Schedule::command('sanctum:prune-expired --hours=24')->daily();
    }

    /**
     * Register the commands for the application.
     */
    protected function commands(): void
    {
        $this->load(__DIR__ . '/Commands');

        require base_path('routes/console.php');
    }
}
