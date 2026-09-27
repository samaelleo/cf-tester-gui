package com.cftester.scanner.ui.export

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import androidx.core.content.FileProvider
import java.io.File

object ShareHelper {

    const val PACKAGE_V2RAYNG = "com.v2ray.ang"
    const val PACKAGE_NEKOBOX = "moe.nb4a"
    const val PACKAGE_MATSURI = "moe.matsuri.lite"

    private const val MAX_CLIPBOARD_BYTES = 512 * 1024 // 512 KB safeguard

    /**
     * Safely copies text to the system clipboard, guarding against TransactionTooLargeException.
     * Returns true if successful, false if payload exceeds Binder threshold.
     */
    fun copyToClipboardSafe(context: Context, label: String, text: String): Boolean {
        if (text.toByteArray(Charsets.UTF_8).size > MAX_CLIPBOARD_BYTES) {
            return false
        }
        return try {
            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText(label, text)
            clipboard.setPrimaryClip(clip)
            true
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Dispatches text payload via Android Share Intent (ACTION_SEND).
     */
    fun shareText(context: Context, text: String, title: String? = null, subject: String = "CF Clean Config") {
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, subject)
            putExtra(Intent.EXTRA_TEXT, text)
        }
        val chooser = Intent.createChooser(intent, title ?: subject)
        context.startActivity(chooser)
    }

    /**
     * Dispatches payload directly to a proxy application if installed, otherwise opens chooser.
     */
    fun shareToProxyApp(context: Context, payload: String, targetPackage: String? = null, fallbackTitle: String = "Send Config") {
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, "CF Clean Config")
            putExtra(Intent.EXTRA_TEXT, payload)
            if (!targetPackage.isNullOrEmpty()) {
                setPackage(targetPackage)
            }
        }

        if (!targetPackage.isNullOrEmpty() && isPackageInstalled(context, targetPackage)) {
            try {
                context.startActivity(intent)
                return
            } catch (_: Exception) {}
        }

        val chooser = Intent.createChooser(intent, fallbackTitle)
        context.startActivity(chooser)
    }

    /**
     * Shares a cached file via FileProvider (ACTION_SEND with EXTRA_STREAM).
     */
    fun shareCachedFile(context: Context, filename: String, mimeType: String, content: String, title: String = "Share File") {
        val exportDir = File(context.cacheDir, "exports")
        if (!exportDir.exists()) exportDir.mkdirs()
        val file = File(exportDir, filename)
        file.writeText(content, Charsets.UTF_8)

        val uri: Uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = mimeType
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        val chooser = Intent.createChooser(intent, title)
        context.startActivity(chooser)
    }

    /**
     * Checks if a package is installed.
     */
    fun isPackageInstalled(context: Context, packageName: String): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                context.packageManager.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getPackageInfo(packageName, 0)
            }
            true
        } catch (_: PackageManager.NameNotFoundException) {
            false
        }
    }
}
