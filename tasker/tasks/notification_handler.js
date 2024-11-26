// tasker/tasks/notification_handler.js
const notificationHandler = {
    config: {
        channelId: 'backup_status',
        defaultIcon: 'backup',
        defaultColor: '#1a73e8',
        soundEnabled: true,
        vibrationEnabled: true,
        priority: 'high'
    },

    taskConfig: {
        name: 'NotificationHandler',
        priority: 10,
        collision: 'ignore'
    },

    init: function() {
        this.createNotificationChannels();
        this.setupEventHandlers();
    },

    createNotificationChannels: function() {
        const channels = [
            {
                id: 'backup_status',
                name: 'Backup Status',
                description: 'Shows backup progress and status',
                importance: 'high',
                lights: true,
                vibration: true
            },
            {
                id: 'backup_error',
                name: 'Backup Errors',
                description: 'Critical backup errors and issues',
                importance: 'max',
                lights: true,
                vibration: true
            },
            {
                id: 'backup_complete',
                name: 'Backup Complete',
                description: 'Backup completion notifications',
                importance: 'default',
                lights: false,
                vibration: false
            }
        ];

        channels.forEach(channel => {
            createNotificationChannel(channel.id, channel);
        });
    },

    setupEventHandlers: function() {
        // Register event handlers
        eventTrigger('backup_started', this.handleBackupStart.bind(this));
        eventTrigger('backup_progress', this.handleBackupProgress.bind(this));
        eventTrigger('backup_complete', this.handleBackupComplete.bind(this));
        eventTrigger('backup_error', this.handleBackupError.bind(this));
        eventTrigger('notification_action', this.handleNotificationAction.bind(this));
    },

    showNotification: function(params) {
        const notification = {
            ...this.config,
            ...params,
            id: params.id || Date.now().toString()
        };

        // Create AutoNotification
        createNotification(notification.id, {
            title: notification.title,
            text: notification.text,
            icon: notification.icon || this.config.defaultIcon,
            color: notification.color || this.config.defaultColor,
            priority: notification.priority || this.config.priority,
            ongoing: notification.ongoing || false,
            channelId: notification.channelId || this.config.channelId,
            sound: this.config.soundEnabled && notification.sound,
            vibrate: this.config.vibrationEnabled && notification.vibrate,
            actions: notification.actions || [],
            extras: notification.extras || {}
        });

        return notification.id;
    },

    updateNotification: function(id, updates) {
        updateNotification(id, updates);
    },

    cancelNotification: function(id) {
        cancelNotification(id);
    },

    handleBackupStart: function(data) {
        this.showNotification({
            id: 'backup_progress',
            channelId: 'backup_status',
            title: 'Backup Started',
            text: 'Preparing to backup files...',
            icon: 'backup',
            ongoing: true,
            sound: false,
            actions: ['pause', 'cancel'],
            extras: {
                progress: {
                    max: 100,
                    current: 0,
                    indeterminate: true
                }
            }
        });
    },

    handleBackupProgress: function(data) {
        this.updateNotification('backup_progress', {
            title: 'Backup in Progress',
            text: `Processing: ${data.currentFile}\n${data.processedFiles}/${data.totalFiles} files`,
            ongoing: true,
            actions: ['pause', 'cancel'],
            extras: {
                progress: {
                    max: 100,
                    current: data.percentage,
                    indeterminate: false
                },
                stats: {
                    speed: `${data.speed} MB/s`,
                    eta: this.formatTime(data.timeRemaining)
                }
            }
        });
    },

    handleBackupComplete: function(data) {
        // Cancel progress notification
        this.cancelNotification('backup_progress');

        // Show completion notification
        this.showNotification({
            channelId: 'backup_complete',
            title: 'Backup Complete',
            text: `Successfully backed up ${data.totalFiles} files`,
            icon: 'check_circle',
            sound: true,
            actions: ['view_details', 'dismiss'],
            extras: {
                summary: {
                    files: data.totalFiles,
                    size: this.formatSize(data.totalSize),
                    duration: this.formatTime(data.duration)
                }
            }
        });
    },

    handleBackupError: function(error) {
        this.showNotification({
            channelId: 'backup_error',
            title: 'Backup Error',
            text: error.message,
            icon: 'error',
            priority: 'max',
            sound: true,
            vibrate: true,
            actions: ['retry', 'view_details', 'dismiss'],
            extras: {
                error: {
                    code: error.code,
                    details: error.details
                }
            }
        });
    },

    handleNotificationAction: function(action) {
        switch(action.id) {
            case 'pause':
                setGlobal('%BACKUP_ACTION', 'pause');
                performTask('BackupControl', 10, 'pause');
                this.updateToPausedState();
                break;

            case 'resume':
                setGlobal('%BACKUP_ACTION', 'resume');
                performTask('BackupControl', 10, 'resume');
                this.updateToActiveState();
                break;

            case 'cancel':
                setGlobal('%BACKUP_ACTION', 'cancel');
                performTask('BackupControl', 10, 'cancel');
                this.cleanup();
                break;

            case 'retry':
                setGlobal('%BACKUP_ACTION', 'retry');
                performTask('BackupControl', 10, 'retry');
                break;

            case 'view_details':
                setGlobal('%BACKUP_ACTION', 'view_details');
                performTask('ShowBackupDetails', 10);
                break;
        }
    },

    updateToPausedState: function() {
        this.updateNotification('backup_progress', {
            title: 'Backup Paused',
            icon: 'pause_circle',
            actions: ['resume', 'cancel']
        });
    },

    updateToActiveState: function() {
        this.updateNotification('backup_progress', {
            title: 'Backup in Progress',
            icon: 'backup',
            actions: ['pause', 'cancel']
        });
    },

    cleanup: function() {
        // Cancel all backup-related notifications
        ['backup_progress', 'backup_error'].forEach(id => {
            this.cancelNotification(id);
        });
    },

    formatTime: function(seconds) {
        if (seconds < 60) return `${Math.round(seconds)}s`;
        if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
        return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
    },

    formatSize: function(bytes) {
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        if (bytes === 0) return '0 B';
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${sizes[i]}`;
    }
};

// Initialize notification handler
notificationHandler.init();

module.exports = notificationHandler;
