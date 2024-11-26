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
        // System checks
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

        // Monitor progress
        this.monitorProgress(session);

        // Wait for completion
        await this.waitForCompletion(session);
    },

    async postBackupTasks() {
        await this.verifyBackups();
        await this.generateReport();
        this.notifyCompletion();
    },

    // Utility functions
    async checkStorage() {
        const free = await this.getFreeSpace();
        const required = await this.getRequiredSpace();
        return {
            success: free > required,
            details: { free, required }
        };
    },

    async checkNetwork() {
        const status = networkMonitor.getNetworkStatus();
        return {
            success: status.quality >= 30,
            details: status
        };
    },

    async checkBattery() {
        const level = parseInt(global('BATT'));
        const charging = global('CHARGING') === 'true';
        return {
            success: level >= 20 || charging,
            details: { level, charging }
        };
    },

    checkPermissions() {
        const required = ['WRITE_EXTERNAL_STORAGE', 'READ_EXTERNAL_STORAGE'];
        const missing = required.filter(perm => !checkPermission(perm));
        return {
            success: missing.length === 0,
            details: { missing }
        };
    },

    configureBackup(params) {
        const config = {
            ...this.taskConfig,
            ...params
        };

        // Apply configuration
        setTaskPriority(config.priority);
        if (config.wakelock) acquireWakeLock();
        if (config.notification) this.setupNotification();
    },

    monitorProgress(session) {
        // Set up progress monitoring
        eventBus.on('backupProgress', this.updateProgress.bind(this));
        eventBus.on('backupError', this.handleError.bind(this));
        eventBus.on('backupComplete', this.handleComplete.bind(this));
    },

    async waitForCompletion(session) {
        return new Promise((resolve, reject) => {
            eventBus.once('backupComplete', resolve);
            eventBus.once('backupError', reject);
        });
    },

    updateProgress(progress) {
        // Update notification
        AutoNotification.update({
            id: 'backup_progress',
            title: 'Backup in Progress',
            text: `${progress.processedFiles}/${progress.totalFiles} files (${progress.percentage}%)`,
            progress: progress.percentage,
            ongoing: true
        });

        // Log progress
        logOperation(`Backup Progress: ${progress.percentage}%`);
    },

    async verifyBackups() {
        const session = backupEngine.getCurrentSession();
        const verifier = new BackupVerifier(session);
        return verifier.verify();
    },

    async generateReport() {
        const session = backupEngine.getCurrentSession();
        const report = await ReportGenerator.generate(session);
        
        // Save report
        writeFile(`/storage/emulated/0/Backup/reports/${session.id}.json`, 
                 JSON.stringify(report, null, 2));
    },

    notifyCompletion() {
        const stats = backupEngine.getStatus().stats;
        
        AutoNotification.notify({
            id: 'backup_complete',
            title: 'Backup Complete',
            text: `Successfully backed up ${stats.processedFiles} files`,
            icon: 'backup_complete',
            buttons: ['View Report', 'Dismiss']
        });
    },

    handleTaskError(error) {
        logError('Backup task failed:', error);
        
        AutoNotification.