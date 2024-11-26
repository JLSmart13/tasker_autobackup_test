// javascript/utils/performance_monitor.js
const performanceMonitor = {
    metrics: {
        cpu: 0,
        memory: 0,
        disk: 0,
        battery: 0,
        network: {
            upload: 0,
            download: 0,
            latency: 0
        }
    },

    thresholds: {
        cpu: {
            warning: 70,
            critical: 90
        },
        memory: {
            warning: 75,
            critical: 90
        },
        disk: {
            warning: 85,
            critical: 95
        },
        battery: {
            warning: 20,
            critical: 10
        }
    },

    history: {
        maxEntries: 100,
        interval: 60000, // 1 minute
        data: new Map()
    },

    init: function() {
        this.setupMonitoring();
        this.setupEventListeners();
    },

    setupMonitoring: function() {
        setInterval(() => {
            this.updateMetrics();
            this.checkThresholds();
            this.storeMetrics();
            this.broadcastMetrics();
        }, 5000);
    },

    setupEventListeners: function() {
        eventBus.on('thresholdUpdate', this.updateThreshold.bind(this));
        eventBus.on('backupStarted', this.handleBackupStart.bind(this));
        eventBus.on('backupComplete', this.handleBackupComplete.bind(this));
    },

    updateMetrics: async function() {
        const [cpu, memory, disk] = await Promise.all([
            this.getCPUUsage(),
            this.getMemoryUsage(),
            this.getDiskUsage()
        ]);

        this.metrics.cpu = cpu;
        this.metrics.memory = memory;
        this.metrics.disk = disk;
        this.metrics.battery = this.getBatteryStatus();
        this.metrics.network = await this.getNetworkMetrics();
    },

    getCPUUsage: async function() {
        return new Promise((resolve) => {
            Java.perform(() => {
                const Process = Java.use('android.os.Process');
                const SystemClock = Java.use('android.os.SystemClock');
                
                const startTime = SystemClock.elapsedRealtime();
                const startCpu = Process.getElapsedCpuTime();
                
                setTimeout(() => {
                    const endTime = SystemClock.elapsedRealtime();
                    const endCpu = Process.getElapsedCpuTime();
                    
                    const cpuTime = endCpu - startCpu;
                    const realTime = endTime - startTime;
                    const usage = (cpuTime / realTime) * 100;
                    
                    resolve(Math.min(100, usage));
                }, 1000);
            });
        });
    },

    getMemoryUsage: async function() {
        return new Promise((resolve) => {
            Java.perform(() => {
                const Runtime = Java.use('java.lang.Runtime');
                const runtime = Runtime.getRuntime();
                
                const totalMem = runtime.totalMemory();
                const freeMem = runtime.freeMemory();
                const used = totalMem - freeMem;
                
                resolve((used / totalMem) * 100);
            });
        });
    },

    getDiskUsage: async function() {
        return new Promise((resolve) => {
            Java.perform(() => {
                const File = Java.use('java.io.File');
                const path = File.$new('/storage/emulated/0');
                
                const total = path.getTotalSpace();
                const free = path.getFreeSpace();
                const used = total - free;
                
                resolve((used / total) * 100);
            });
        });
    },

    getBatteryStatus: function() {
        return parseInt(global('BATT'));
    },

    getNetworkMetrics: async function() {
        return new Promise((resolve) => {
            Java.perform(() => {
                const TrafficStats = Java.use('android.net.TrafficStats');
                const upload = TrafficStats.getTotalTxBytes();
                const download = TrafficStats.getTotalRxBytes();
                
                resolve({
                    upload: this.calculateSpeed(upload, 'upload'),
                    download: this.calculateSpeed(download, 'download'),
                    latency: this.measureLatency()
                });
            });
        });
    },

    calculateSpeed: function(bytes, type) {
        const now = Date.now();
        const lastMetric = this.history.data.get(type);
        
        if (lastMetric) {
            const timeDiff = (now - lastMetric.timestamp) / 1000;
            const bytesDiff = bytes - lastMetric.bytes;
            return (bytesDiff / timeDiff) / (1024 * 1024); // MB/s
        }
        
        return 0;
    },

    measureLatency: function() {
        return new Promise((resolve) => {
            Java.perform(() => {
                const start = Date.now();
                Java.use('java.net.InetAddress')
                    .getByName('8.8.8.8')
                    .isReachable(1000);
                resolve(Date.now() - start);
            });
        });
    },

    checkThresholds: function() {
        Object.entries(this.metrics).forEach(([metric, value]) => {
            if (typeof value === 'object') return;
            
            const threshold = this.thresholds[metric];
            if (!threshold) return;

            if (value >= threshold.critical) {
                this.handleCriticalThreshold(metric, value);
            } else if (value >= threshold.warning) {
                this.handleWarningThreshold(metric, value);
            }
        });
    },

    handleWarningThreshold: function(metric, value) {
        eventBus.emit('performanceWarning', {
            metric,
            value,
            threshold: this.thresholds[metric].warning
        });
    },

    handleCriticalThreshold: function(metric, value) {
        eventBus.emit('performanceCritical', {
            metric,
            value,
            threshold: this.thresholds[metric].critical
        });
    },

    storeMetrics: function() {
        const timestamp = Date.now();
        const metrics = { ...this.metrics, timestamp };
        
        Object.entries(metrics).forEach(([key, value]) => {
            if (!this.history.data.has(key)) {
                this.history.data.set(key, []);
            }
            
            const history = this.history.data.get(key);
            history.push({ value, timestamp });
            
            if (history.length > this.history.maxEntries) {
                history.shift();
            }
        });
    },

    broadcastMetrics: function() {
        eventBus.emit('performanceUpdate', {
            current: this.metrics,
            history: this.getMetricHistory()
        });
    },

    getMetricHistory: function(metric, duration = 3600000) { // 1 hour default
        if (!metric) {
            return Object.fromEntries(
                Array.from(this.history.data.entries())
                    .map(([key, values]) => [key, this.filterHistory(values, duration)])
            );
        }
        
        const history = this.history.data.get(metric);
        return history ? this.filterHistory(history, duration) : [];
    },

    filterHistory: function(history, duration) {
        const cutoff = Date.now() - duration;
        return history.filter(entry => entry.timestamp >= cutoff);
    },

    updateThreshold: function(update) {
        const { metric, level, value } = update;
        if (this.thresholds[metric]) {
            this.thresholds[metric][level] = value;
        }
    },

    handleBackupStart: function() {
        this.history.interval = 30000; // Increase monitoring frequency
    },

    handleBackupComplete: function() {
        this.history.interval = 60000; // Restore normal monitoring frequency
    },

    getStatus: function() {
        return {
            metrics: { ...this.metrics },
            thresholds: { ...this.thresholds },
            history: this.getMetricHistory()
        };
    }
};

// Initialize performance monitor
performanceMonitor.init();

// Export for use in other modules
export default performanceMonitor;
