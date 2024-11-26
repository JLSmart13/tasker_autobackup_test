// app_handler.js
const appHandler = {
    appConfigs: {
        gaming: {
            patterns: [
                'com.game',
                'com.unity',
                'com.unreal'
            ],
            action: 'pause',
            priority: 'low',
            resumeDelay: 300000 // 5 minutes after game closes
        },
        streaming: {
            patterns: [
                'com.netflix',
                'com.youtube',
                'com.spotify'
            ],
            action: 'throttle',
            bandwidth: '1MB',
            priority: 'low'
        },
        productivity: {
            patterns: [
                'com.microsoft.office',
                'com.google.docs',
                'com.dropbox'
            ],
            action: 'priority',
            priority: 'high',
            instant: true
        },
        camera: {
            patterns: [
                'com.android.camera',
                'com.samsung.camera',
                'com.huawei.camera'
            ],
            action: 'instant',
            filter: ['image/*', 'video/*'],
            compression: true
        }
    },

    currentApp: null,
    activeConfigs: new Set(),

    init: function() {
        this.setupEventListeners();
        this.startMonitoring();
    },

    setupEventListeners: function() {
        // Listen for app changes
        eventBus.on('appChanged', this.handleAppChange.bind(this));
        
        // Listen for backup events
        eventBus.on('backupStarted', this.handleBackupStart.bind(this));
        eventBus.on('backupComplete', this.handleBackupComplete.bind(this));
    },

    startMonitoring: function() {
        