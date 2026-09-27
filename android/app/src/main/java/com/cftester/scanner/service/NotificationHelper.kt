package com.cftester.scanner.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import com.cftester.scanner.core.model.ScanProgress
import com.cftester.scanner.ui.MainActivity
import java.util.Locale

class NotificationHelper {

    companion object {
        const val CHANNEL_ID = "cf_tester_scan_channel"
        const val CHANNEL_NAME = "Cloudflare Scanner Service"
        const val CHANNEL_DESC = "Cloudflare IP reachability and clean latency scanning active notification"
        const val NOTIFICATION_ID = 13335 // Named after Cloudflare ASN AS13335

        const val REQUEST_CODE_ACTIVITY = 100
        const val REQUEST_CODE_STOP = 101
        const val REQUEST_CODE_PAUSE = 102
        const val REQUEST_CODE_RESUME = 103
    }

    fun createNotificationChannel(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            if (notificationManager?.getNotificationChannel(CHANNEL_ID) == null) {
                val channel = NotificationChannel(
                    CHANNEL_ID,
                    CHANNEL_NAME,
                    NotificationManager.IMPORTANCE_LOW
                ).apply {
                    description = CHANNEL_DESC
                    setShowBadge(false)
                    enableVibration(false)
                    enableLights(false)
                    setSound(null, null)
                    lockscreenVisibility = Notification.VISIBILITY_PUBLIC
                }
                notificationManager?.createNotificationChannel(channel)
            }
        }
    }

    fun buildProgressNotification(
        context: Context,
        progress: ScanProgress,
        isPaused: Boolean = false
    ): Notification {
        // Tap action: Return to MainActivity
        val activityIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val contentPendingIntent = PendingIntent.getActivity(
            context,
            REQUEST_CODE_ACTIVITY,
            activityIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        // Action: Stop Scan
        val stopIntent = Intent(context, ScanForegroundService::class.java).apply {
            action = ScanForegroundService.ACTION_STOP
        }
        val stopPendingIntent = PendingIntent.getService(
            context,
            REQUEST_CODE_STOP,
            stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        // Action: Pause / Resume
        val toggleActionIntent = Intent(context, ScanForegroundService::class.java).apply {
            action = if (isPaused) ScanForegroundService.ACTION_RESUME else ScanForegroundService.ACTION_PAUSE
        }
        val togglePendingIntent = PendingIntent.getService(
            context,
            if (isPaused) REQUEST_CODE_RESUME else REQUEST_CODE_PAUSE,
            toggleActionIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val toggleTitle = if (isPaused) "Resume" else "Pause"
        val toggleIcon = if (isPaused) android.R.drawable.ic_media_play else android.R.drawable.ic_media_pause

        val title = if (isPaused) "Cloudflare Scan (Paused)" else "Cloudflare Scan Running"
        val speedStr = String.format(Locale.US, "%.1f", progress.speed)
        val contentText = "Tested: ${progress.tested}/${progress.total} | Clean: ${progress.working} | $speedStr IP/s"

        val subText = if (progress.latestIp.isNotEmpty()) {
            val lat = if (progress.latestLatency > 0) "${progress.latestLatency.toInt()}ms" else progress.latestStatus
            "${progress.latestIp} ($lat)"
        } else {
            "Scanning clean IPs..."
        }

        val total = progress.total.coerceAtLeast(1)
        val isIndeterminate = progress.total == 0

        return NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentTitle(title)
            .setContentText(contentText)
            .setSubText(subText)
            .setContentIntent(contentPendingIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_PROGRESS)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .setProgress(total, progress.tested, isIndeterminate)
            .addAction(toggleIcon, toggleTitle, togglePendingIntent)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Stop Scan", stopPendingIntent)
            .build()
    }

    fun buildCompletedNotification(
        context: Context,
        total: Int,
        working: Int,
        elapsedSec: Float
    ): Notification {
        val activityIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val contentPendingIntent = PendingIntent.getActivity(
            context,
            REQUEST_CODE_ACTIVITY,
            activityIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .setContentTitle("Cloudflare Scan Complete")
            .setContentText("Found $working clean IPs out of $total candidates in ${elapsedSec.toInt()}s")
            .setContentIntent(contentPendingIntent)
            .setOngoing(false)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .build()
    }
}
