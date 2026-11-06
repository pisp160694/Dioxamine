package io.github.rhythmcache.dioxamine

import android.app.Application
import androidx.lifecycle.ViewModelStore
import androidx.lifecycle.ViewModelStoreOwner
import io.github.rhythmcache.dioxamine.core.AppLogger

class DioxamineApplication : Application(), ViewModelStoreOwner {

    override val viewModelStore: ViewModelStore by lazy {
        ViewModelStore()
    }

    override fun onCreate() {
        super.onCreate()
        AppLogger.init(this)
    }
}
