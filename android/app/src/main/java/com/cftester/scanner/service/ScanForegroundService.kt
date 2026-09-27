package com.cftester.scanner.service

import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import androidx.core.app.ServiceCompat
import com.cftester.scanner.core.engine.TesterEngine
import com.cftester.scanner.core.model.ParsedConfig
import com.cftester.scanner.core.model.ScanCandidate
import com.cftester.scanner.core.model.ScanConfig
import com.cftester.scanner.core.model.ScanProgress
import com.cftester.scanner.core.model.ScanResult
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

class ScanForegroundService : Service() {

    companion object {
        const val TAG = "ScanForegroundService"

        const val ACTION_START = "com.cftester.scanner.action.START_SCAN"
        const val ACTION_STOP = "com.cftester.scanner.action.STOP_SCAN"
        const val ACTION_PAUSE = "com.cftester.scanner.action.PAUSE_SCAN"
        const val ACTION_RESUME = "com.cftester.scanner.action.RESUME_SCAN"

        const val NOTIFICATION_THROTTLE_MS = 500L
        const val WAKELOCK_TIMEOUT_MS = 30 * 60 * 1000L // 30 minutes safety ceiling

        // In-memory session references to avoid Binder 1MB TransactionTooLargeException
        @Volatile
        var activeCandidates: List<ScanCandidate>? = null
        @Volatile
        var activeScanConfig: ScanConfig? = null
        @Volatile
        var activeParsedConfig: ParsedConfig? = null

        // Global StateFlow observables for MainViewModel and Jetpack Compose UI
        private val _serviceState = MutableStateFlow(ScanServiceState.IDLE)
        val serviceState: StateFlow<ScanServiceState> = _serviceState.asStateFlow()

        private val _progressFlow = MutableStateFlow(ScanProgress())
        val progressFlow: StateFlow<ScanProgress> = _progressFlow.asStateFlow()

        private val _workingResults = MutableStateFlow<List<ScanResult>>(emptyList())
        val workingResults: StateFlow<List<ScanResult>> = _workingResults.asStateFlow()

        fun start(
            context: Context,
            candidates: List<ScanCandidate>,
            scanConfig: ScanConfig,
            parsedConfig: ParsedConfig
        ) {
            activeCandidates = candidates
            activeScanConfig = scanConfig
            activeParsedConfig = parsedConfig

            val intent = Intent(context, ScanForegroundService::class.java).apply {
                action = ACTION_START
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            val intent = Intent(context, ScanForegroundService::class.java).apply {
                action = ACTION_STOP
            }
            context.startService(intent)
        }

        fun pause(context: Context) {
            val intent = Intent(context, ScanForegroundService::class.java).apply {
                action = ACTION_PAUSE
            }
            context.startService(intent)
        }

        fun resume(context: Context) {
            val intent = Intent(context, ScanForegroundService::class.java).apply {
                action = ACTION_RESUME
            }
            context.startService(intent)
        }
    }

    enum class ScanServiceState {
        IDLE,
        RUNNING,
        PAUSED,
        COMPLETED,
        STOPPED,
        ERROR
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val engine = TesterEngine()
    private val notificationHelper = NotificationHelper()

    private var wakeLock: PowerManager.WakeLock? = null
    private var scanJob: Job? = null
    private var throttleJob: Job? = null

    private var lastNotificationTime = 0L
    private var pendingProgress: ScanProgress? = null

    override fun onCreate() {
        super.onCreate()
        notificationHelper.createNotificationChannel(this)

        val powerManager = getSystemService(Context.POWER_SERVICE) as? PowerManager
        wakeLock = powerManager?.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "cf-tester:ScanWakeLock")?.apply {
            setReferenceCounted(false)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action ?: return START_NOT_STICKY

        when (action) {
            ACTION_START -> {
                startForegroundSafely()
                acquireWakeLock()
                startScan()
            }
            ACTION_STOP -> {
                stopScan()
            }
            ACTION_PAUSE -> {
                engine.pause()
                _serviceState.value = ScanServiceState.PAUSED
                dispatchProgressNotification(_progressFlow.value, isPaused = true)
            }
            ACTION_RESUME -> {
                engine.resume()
                _serviceState.value = ScanServiceState.RUNNING
                dispatchProgressNotification(_progressFlow.value, isPaused = false)
            }
        }

        return START_NOT_STICKY
    }

    private fun startForegroundSafely() {
        val initialNotification = notificationHelper.buildProgressNotification(
            context = this,
            progress = ScanProgress(total = activeCandidates?.size ?: 0),
            isPaused = false
        )

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceCompat.startForeground(
                this,
                NotificationHelper.NOTIFICATION_ID,
                initialNotification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ServiceCompat.startForeground(
                this,
                NotificationHelper.NOTIFICATION_ID,
                initialNotification,
                0
            )
        } else {
            startForeground(NotificationHelper.NOTIFICATION_ID, initialNotification)
        }
    }

    private fun acquireWakeLock() {
        try {
            if (wakeLock?.isHeld != true) {
                wakeLock?.acquire(WAKELOCK_TIMEOUT_MS)
                Log.i(TAG, "Acquired PARTIAL_WAKE_LOCK (timeout = ${WAKELOCK_TIMEOUT_MS / 1000}s)")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to acquire WakeLock: ${e.message}", e)
        }
    }

    private fun releaseWakeLock() {
        try {
            if (wakeLock?.isHeld == true) {
                wakeLock?.release()
                Log.i(TAG, "Released PARTIAL_WAKE_LOCK")
            }
        } catch (e: Exception) {
            Log.w(TAG, "Error releasing WakeLock: ${e.message}", e)
        } finally {
            wakeLock = null
        }
    }

    private fun startScan() {
        val candidates = activeCandidates
        val scanConfig = activeScanConfig
        val parsedConfig = activeParsedConfig

        if (candidates.isNullOrEmpty() || scanConfig == null || parsedConfig == null) {
            Log.w(TAG, "Cannot start scan: missing active candidates or config")
            _serviceState.value = ScanServiceState.ERROR
            stopScan()
            return
        }

        scanJob?.cancel()
        _serviceState.value = ScanServiceState.RUNNING
        _workingResults.value = emptyList()

        val startTime = System.currentTimeMillis()
        val workingList = mutableListOf<ScanResult>()

        scanJob = serviceScope.launch {
            val progressCollector = launch {
                engine.progressFlow.collect { progress ->
                    _progressFlow.value = progress
                    dispatchProgressNotification(progress, isPaused = engine.isPaused.value)
                }
            }

            val resultCollector = launch {
                engine.workingResultFlow.collect { result ->
                    synchronized(workingList) {
                        workingList.add(result)
                        workingList.sortBy { if (it.googleLatencyMs > 0) it.googleLatencyMs else 99999f }
                        _workingResults.value = workingList.toList()
                    }
                }
            }

            try {
                val finalResults = engine.runScan(
                    candidates = candidates,
                    config = parsedConfig,
                    concurrency = scanConfig.concurrency,
                    timeoutSec = scanConfig.timeoutSec,
                    targetUrl = scanConfig.targetUrl
                )

                val elapsedSec = (System.currentTimeMillis() - startTime) / 1000f
                _serviceState.value = ScanServiceState.COMPLETED

                val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as? android.app.NotificationManager
                val finalNotification = notificationHelper.buildCompletedNotification(
                    context = this@ScanForegroundService,
                    total = candidates.size,
                    working = finalResults.size,
                    elapsedSec = elapsedSec
                )
                notificationManager?.notify(NotificationHelper.NOTIFICATION_ID, finalNotification)

            } catch (e: CancellationException) {
                Log.i(TAG, "Scan coroutine cancelled")
                _serviceState.value = ScanServiceState.STOPPED
            } catch (e: Exception) {
                Log.e(TAG, "Error during scan: ${e.message}", e)
                _serviceState.value = ScanServiceState.ERROR
            } finally {
                progressCollector.cancel()
                resultCollector.cancel()
                releaseWakeLock()
                ServiceCompat.stopForeground(this@ScanForegroundService, ServiceCompat.STOP_FOREGROUND_DETACH)
                stopSelf()
            }
        }
    }

    private fun dispatchProgressNotification(progress: ScanProgress, isPaused: Boolean) {
        val now = System.currentTimeMillis()
        val isCompleted = progress.tested >= progress.total && progress.total > 0

        if (isCompleted || (now - lastNotificationTime >= NOTIFICATION_THROTTLE_MS)) {
            throttleJob?.cancel()
            throttleJob = null
            lastNotificationTime = now
            pendingProgress = null

            val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as? android.app.NotificationManager
            val notification = notificationHelper.buildProgressNotification(this, progress, isPaused)
            notificationManager?.notify(NotificationHelper.NOTIFICATION_ID, notification)
        } else {
            pendingProgress = progress
            if (throttleJob == null || throttleJob?.isCompleted == true) {
                throttleJob = serviceScope.launch {
                    val waitMs = NOTIFICATION_THROTTLE_MS - (System.currentTimeMillis() - lastNotificationTime)
                    if (waitMs > 0) delay(waitMs)
                    lastNotificationTime = System.currentTimeMillis()
                    pendingProgress?.let {
                        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as? android.app.NotificationManager
                        val notification = notificationHelper.buildProgressNotification(this@ScanForegroundService, it, isPaused)
                        notificationManager?.notify(NotificationHelper.NOTIFICATION_ID, notification)
                    }
                    pendingProgress = null
                    throttleJob = null
                }
            }
        }
    }

    fun stopScan() {
        Log.i(TAG, "Stopping scan and releasing resources")
        engine.stop()
        scanJob?.cancel()
        scanJob = null
        throttleJob?.cancel()
        throttleJob = null
        releaseWakeLock()
        _serviceState.value = ScanServiceState.STOPPED

        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        super.onDestroy()
        stopScan()
        serviceScope.cancel()
        activeCandidates = null
        activeScanConfig = null
        activeParsedConfig = null
        Log.i(TAG, "ScanForegroundService destroyed")
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
