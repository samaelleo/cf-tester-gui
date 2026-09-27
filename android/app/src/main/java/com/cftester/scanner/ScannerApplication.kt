package com.cftester.scanner

import android.app.Application

class ScannerApplication : Application() {
    companion object {
        lateinit var instance: ScannerApplication
            private set
    }

    override fun onCreate() {
        super.onCreate()
        instance = this
    }
}
