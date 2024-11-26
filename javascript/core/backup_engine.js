// main_backup.js
const mainBackup = {
    taskConfig: {
        taskName: 'MainBackup',
        priority: 'foreground',
        wakelock: true,
        notification: true
    },

    async execute(params = {}) {
        try {
            await this.preBackupChecks();
            await this.initializeBackup(params);
            await this.runBackup();
            await this.postBackupTasks();
        } catch (error) {
            this.handleTaskError(error);
        } finally {
            this.cleanup();
        }
    },

    async preBackupChecks() {
        const checks = [
            this.checkStorage(),
            this.checkNetwork(),
            this.checkBattery(),
            this.checkPermissions()
        ];

        const results = await Promise.all(checks);
        if (results.some(result => !result.success)) {
            throw new Error('Pre-backup checks failed');
        }
    },

    async initializeBackup(params) {
        // Set up notification channel
        AutoNotification.createChannel({
            id: 'backup_status',
            name: 'Backup Status',
            importance: 'high'
        });

        // Initialize systems
        await Promise.all([
            backupEngine.init(),
            performanceManager.init(),
            networkMonitor.init()
        ]);

        // Configure based on params
        this.configureBackup(params);
    },

    async runBackup() {
        // Start backup session
        const session = await backupEngine.startSession();
        
        // Set up progress monitoring
        this.monitorProgress(session);
        
        // Wait for completion or error
        await this.waitForCompletion(session);
    },

    async postBackupTasks() {
        await this.verifyBackups();
        await this.generateReport();
        this.notifyCompletion();
        await this.cleanupTempFiles();
    },

    // Utility functions
    async checkStorage() {
        const free = await this.getFreeSpace();
        const required = await this.getRequiredSpace();
        const buffer = 1024 * 1024 * 100; // 100MB buffer
        
        return {
            success: free > (required + buffer),
            details: {
                free,
                required,
                buffer,
                sufficient: free > (required + buffer)
            }
        };
    },

    async getFreeSpace() {
        return new Promise((resolve) => {
            Java.perform(() => {
                const StatFs = Java.use('android.os.StatFs');
                const Environment = Java.use('android.os.Environment');
                const stats = StatFs.$new(Environment.getExternalStorageDirectory().getPath());
                const availableBlocks = stats.getAvailableBlocksLong();
                const blockSize = stats.getBlockSizeLong();
                resolve(availableBlocks * blockSize);
            });
        });
    },

    async getRequiredSpace() {
        const files = await fileMonitor.getPendingFiles();
        return files.reduce((total, file) => total + file.size, 0);
    },

    async checkNetwork() {
        const status = networkMonitor.getNetworkStatus();
        const networkConfig = {
            minQuality: 30,
            preferredTypes: ['WIFI', 'ETHERNET'],
            allowMobile: true
        };

        return {
            success: this.isNetworkSuitable(status, networkConfig),
            details: {
                ...status,
                suitable: this.isNetworkSuitable(status, networkConfig),
                config: networkConfig
            }
        };
    },

    isNetworkSuitable(status, config) {
        return (
            status.quality >= config.minQuality &&
            (config.preferredTypes.includes(status.type) || 
             (config.allowMobile && status.type === 'MOBILE'))
        );
    },

    async checkBattery() {
        const level = parseInt(global('BATT'));
        const charging = global('CHARGING') === 'true';
        const temp = parseInt(global('TEMP'));
        
        return {
            success: this.isBatterySuitable(level, charging, temp),
            details: {
                level,
                charging,
                temp,
                suitable: this.isBatterySuitable(level, charging, temp)
            }
        };
    },

    isBatterySuitable(level, charging, temp) {
        return (level >= 20 || charging) && temp < 45;
    },

    checkPermissions() {
        const required = [
            'WRITE_EXTERNAL_STORAGE',
            'READ_EXTERNAL_STORAGE',
            'INTERNET',
            'ACCESS_NETWORK_STATE'
        ];
        
        const missing = required.filter(perm => !checkPermission(perm));
        
        return {
            success: missing.length === 0,
            details: {
                missing,
                granted: required.filter(perm => checkPermission(perm))
            }
        };
    },

    configureBackup(params) {
        const config = {
            ...this.taskConfig,
            ...params
        };

        if (config.priority === 'foreground') {
            setTaskPriority(10);
            acquireWakeLock();
        }

        if (config.notification) {
            this.setupNotification(config.notificationConfig);
        }

        if (config.customParams) {
            this.applyCustomParams(config.customParams);
        }
    },

    setupNotification(config = {}) {
        const defaultConfig = {
            id: 'backup_progress',
            channelId: 'backup_status',
            title: 'Backup in Progress',
            icon: 'backup',
            ongoing: true,
            priority: 'high',
            actions: ['pause', 'cancel']
        };

        AutoNotification.createNotification({
            ...defaultConfig,
            ...config
        });
    },

    applyCustomParams(params) {
        Object.entries(params).forEach(([key, value]) => {
            if (this.isValidParam(key, value)) {
                this[key] = value;
            }
        });
    },

    monitorProgress(session) {
        eventBus.on('backupProgress', this.updateProgress.bind(this));
        eventBus.on('backupError', this.handleError.bind(this));
        eventBus.on('backupComplete', this.handleComplete.bind(this));
        
        // Set up periodic status checks
        this.progressInterval = setInterval(() => {
            this.checkSessionStatus(session);
        }, 5000);
    },

    updateProgress(progress) {
        // Update notification
        AutoNotification.update({
            id: 'backup_progress',
            title: 'Backup in Progress',
            text: `${progress.processedFiles}/${progress.totalFiles} files (${progress.percentage}%)`,
            progress: progress.percentage,
            ongoing: true,
            actions: progress.canPause ? ['pause', 'cancel'] : ['cancel']
        });

        // Log progress
        logOperation(`Backup Progress: ${progress.percentage}%`);
        
        // Update system status
        this.updateSystemStatus(progress);
    },

    updateSystemStatus(progress) {
        setGlobal('BACKUP_PROGRESS', progress.percentage);
        setGlobal('BACKUP_STATUS', JSON.stringify({
            running: true,
            progress: progress.percentage,
            files: {
                total: progress.totalFiles,
                processed: progress.processedFiles
            },
            speed: progress.speed,
            timeRemaining: progress.eta
        }));
    },

    async waitForCompletion(session) {
        return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                reject(new Error('Backup timeout'));
            }, this.taskConfig.timeout || 24 * 60 * 60 * 1000); // 24 hour default

            eventBus.once('backupComplete', () => {
                clearTimeout(timeout);
                resolve();
            });

            eventBus.once('backupError', (error) => {
                clearTimeout(timeout);
                reject(error);
            });
        });
    },

    async verifyBackups() {
        const verifier = new BackupVerifier(backupEngine.getCurrentSession());
        const results = await verifier.verify();

        if (!results.success) {
            logError('Backup verification failed:', results.errors);
            throw new Error('Backup verification failed');
        }

        return results;
    },

    async generateReport() {
        const session = backupEngine.getCurrentSession();
        const report = await ReportGenerator.generate(session);
        
        // Save detailed report
        await this.saveReport(report);
        
        // Update statistics
        await this.updateStatistics(report);
        
        return report;
    },

    async saveReport(report) {
        const reportPath = `/storage/emulated/0/Backup/reports/${report.sessionId}.json`;
        await writeFile(reportPath, JSON.stringify(report, null, 2));
        
        // Keep only last 10 reports
        await this.cleanupOldReports();
    },

    async updateStatistics(report) {
        const stats = await this.loadStatistics();
        stats.lastBackup = report.timestamp;
        stats.totalBackups++;
        stats.totalFiles += report.totalFiles;
        stats.totalSize += report.totalSize;
        
        await writeFile('/storage/emulated/0/Backup/statistics.json', 
                       JSON.stringify(stats, null, 2));
    },

    notifyCompletion() {
        const stats = backupEngine.getStatus().stats;
        
        AutoNotification.notify({
            id: 'backup_complete',
            title: 'Backup Complete',
            text: `Successfully backed up ${stats.processedFiles} files`,
            icon: 'backup_complete',
            buttons: [
                {
                    text: 'View Report',
                    action: 'viewReport'
                },
                {
                    text: 'Dismiss',
                    action: 'dismiss'
                }
            ]
        });
    },

    handleTaskError(error) {
        logError('Backup task failed:', error);
        
        // Notify user
        AutoNotification.notify({
            id: 'backup_error',
            title: 'Backup Failed',
            text: error.message,
            icon: 'backup_error',
            importance: 'high',
            buttons: [
                {
                    text: 'Retry',
                    action: 'retryBackup'
                },
                {
                    text: 'View Details',
                    action: 'viewError'
                }
            ]
        });

        // Save error details
        this.saveErrorReport(error);
    },

    async cleanup() {
        // Clear notification
        AutoNotification.cancel('backup_progress');
        
        // Release wake lock
        if (this.taskConfig.wakelock) {
            releaseWakeLock();
        }
        
        // Clear intervals
        if (this.progressInterval) {
            clearInterval(this.progressInterval);
        }
        
        // Clean up temporary files
        await this.cleanupTempFiles();
        
        // Reset system status
        setGlobal('BACKUP_STATUS', JSON.stringify({
            running: false,
            lastRun: new Date().toISOString()
        }));
    },

    async cleanupTempFiles() {
        const tempDir = '/storage/emulated/0/Backup/temp';
        const files = await listFiles(tempDir);
        
        for (const file of files) {
            try {
                await deleteFile(file.path);
            } catch (error) {
                logError('Failed to delete temp file:', file.path);
            }
        }
    },

    async cleanupOldReports() {
        const reportsDir = '/storage/emulated/0/Backup/reports';
        const reports = await listFiles(reportsDir);
        
        if (reports.length > 10) {
            reports
                .sort((a, b) => b.lastModified() - a.lastModified())
                .slice(10)
                .forEach(file => deleteFile(file.path));
        }
    }
};

// Export the task
module.exports = mainBackup;
