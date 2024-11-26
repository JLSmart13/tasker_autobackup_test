// javascript/utils/network.js
const networkUtils = {
    state: {
        type: null,
        quality: 0,
        speed: {
            upload: 0,
            download: 0
        },
        latency: 0,
        isConnected: false,
        isMetered: false,
        ssid: null,
        signal: 0,
        history: []
    },

    config: {
        speedTest: {
            interval: 300000, // 5 minutes
            timeout: 30000,
            retries: 3,
            samples: 3
        },
        thresholds: {
            quality: {
                poor: 30,
                fair: 50,
                good: 70
            },
            speed: {
                minimum: 1,    // 1 MB/s
                preferred: 5   // 5 MB/s
            },
            latency: {
                maximum: 200,  // 200ms
                preferred: 50  // 50ms
            }
        },
        history: {
            maxEntries: 100,
            retentionPeriod: 86400000 // 24 hours
        }
    },

    init: function() {
        this.setupMonitoring();
        this.setupEventListeners();
    },

    setupMonitoring: function() {
        // Regular network state checks
        setInterval(() => {
            this.checkNetworkState();
        }, 5000);

        // Periodic speed tests
        setInterval(() => {
            if (this.shouldRunSpeedTest()) {
                this.runSpeedTest();
            }
        }, this.config.speedTest.interval);
    },

    setupEventListeners: function() {
        eventBus.on('CONNECTIVITY_CHANGE', this.handleConnectivityChange.bind(this));
        eventBus.on('WIFI_STATE_CHANGED', this.handleWifiStateChange.bind(this));
        eventBus.on('backupStarted', this.handleBackupStart.bind(this));
        eventBus.on('backupComplete', this.handleBackupComplete.bind(this));
        eventBus.on('networkTestRequest', this.handleTestRequest.bind(this));
    },

    async checkNetworkState() {
        const previousState = { ...this.state };
        
        await this.updateConnectionState();
        await this.updateNetworkMetrics();
        
        if (this.hasStateChanged(previousState)) {
            this.notifyStateChange(previousState);
        }
    },

    async updateConnectionState() {
        return new Promise((resolve) => {
            Java.perform(() => {
                const Context = Java.use('android.content.Context');
                const ConnectivityManager = Java.use('android.net.ConnectivityManager');
                
                const manager = Context.getSystemService(Context.CONNECTIVITY_SERVICE);
                const network = manager.getActiveNetwork();
                const capabilities = manager.getNetworkCapabilities(network);
                
                this.state.isConnected = network !== null;
                this.state.isMetered = manager.isActiveNetworkMetered();
                
                if (capabilities) {
                    if (capabilities.hasTransport(ConnectivityManager.TRANSPORT_WIFI)) {
                        this.state.type = 'WIFI';
                        this.updateWifiInfo();
                    } else if (capabilities.hasTransport(ConnectivityManager.TRANSPORT_CELLULAR)) {
                        this.state.type = 'MOBILE';
                        this.updateMobileInfo();
                    } else {
                        this.state.type = 'OTHER';
                    }
                } else {
                    this.state.type = null;
                }
                
                resolve();
            });
        });
    },

    updateWifiInfo() {
        Java.perform(() => {
            const Context = Java.use('android.content.Context');
            const WifiManager = Java.use('android.net.wifi.WifiManager');
            
            const wifiManager = Context.getSystemService(Context.WIFI_SERVICE);
            const wifiInfo = wifiManager.getConnectionInfo();
            
            this.state.ssid = wifiInfo.getSSID().replace(/^"(.*)"$/, '$1');
            this.state.signal = this.calculateSignalLevel(wifiInfo.getRssi());
        });
    },

    updateMobileInfo() {
        Java.perform(() => {
            const Context = Java.use('android.content.Context');
            const TelephonyManager = Java.use('android.telephony.TelephonyManager');
            
            const telephonyManager = Context.getSystemService(Context.TELEPHONY_SERVICE);
            const signalStrength = telephonyManager.getSignalStrength();
            
            this.state.signal = this.calculateMobileSignal(signalStrength);
        });
    },

    async updateNetworkMetrics() {
        if (!this.state.isConnected) return;

        const metrics = await this.measureNetworkPerformance();
        this.updateMetricsState(metrics);
        this.updateHistory();
    },

    updateMetricsState(metrics) {
        this.state.speed = {
            upload: metrics.upload,
            download: metrics.download
        };
        this.state.latency = metrics.latency;
        this.state.quality = this.calculateNetworkQuality(metrics);
    },

    calculateNetworkQuality(metrics) {
        const speedScore = Math.min(100, 
            ((metrics.upload + metrics.download) / 
            (this.config.thresholds.speed.preferred * 2)) * 100
        );
        
        const latencyScore = Math.min(100,
            (this.config.thresholds.latency.maximum - metrics.latency) /
            (this.config.thresholds.latency.maximum - this.config.thresholds.latency.preferred) * 100
        );

        const signalScore = this.state.signal;

        return Math.round((speedScore * 0.4) + (latencyScore * 0.3) + (signalScore * 0.3));
    },

    async measureNetworkPerformance() {
        const results = {
            upload: 0,
            download: 0,
            latency: 0
        };

        for (let i = 0; i < this.config.speedTest.samples; i++) {
            const sample = await this.singleSpeedTest();
            results.upload += sample.upload;
            results.download += sample.download;
            results.latency += sample.latency;
        }

        return {
            upload: results.upload / this.config.speedTest.samples,
            download: results.download / this.config.speedTest.samples,
            latency: results.latency / this.config.speedTest.samples
        };
    },

    async singleSpeedTest() {
        return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => reject(new Error('Speed test timeout')), 
                this.config.speedTest.timeout);

            try {
                Java.perform(() => {
                    const TrafficStats = Java.use('android.net.TrafficStats');
                    const startTx = TrafficStats.getTotalTxBytes();
                    const startRx = TrafficStats.getTotalRxBytes();
                    const startTime = Date.now();

                    // Perform test connection
                    const url = Java.use('java.net.URL').$new('https://www.google.com');
                    const connection = url.openConnection();
                    connection.connect();

                    const latency = Date.now() - startTime;

                    // Calculate speeds
                    const endTx = TrafficStats.getTotalTxBytes();
                    const endRx = TrafficStats.getTotalRxBytes();
                    const duration = (Date.now() - startTime) / 1000;

                    clearTimeout(timeout);
                    resolve({
                        upload: (endTx - startTx) / duration / (1024 * 1024),
                        download: (endRx - startRx) / duration / (1024 * 1024),
                        latency
                    });
                });
            } catch (error) {
                clearTimeout(timeout);
                reject(error);
            }
        });
    },

    shouldRunSpeedTest() {
        if (!this.state.isConnected) return false;
        if (this.state.type === 'MOBILE' && this.state.isMetered) return false;
        return true;
    },

    updateHistory() {
        const entry = {
            timestamp: Date.now(),
            ...this.state
        };

        this.state.history.push(entry);

        // Cleanup old entries
        const cutoff = Date.now() - this.config.history.retentionPeriod;
        this.state.history = this.state.history.filter(entry => 
            entry.timestamp > cutoff
        ).slice(-this.config.history.maxEntries);
    },

    hasStateChanged(previousState) {
        return JSON.stringify(previousState) !== JSON.stringify(this.state);
    },

    notifyStateChange(previousState) {
        eventBus.emit('networkStateChange', {
            previous: previousState,
            current: this.state,
            changes: this.getStateChanges(previousState)
        });
    },

    getStateChanges(previousState) {
        const changes = {};
        Object.keys(this.state).forEach(key => {
            if (JSON.stringify(previousState[key]) !== JSON.stringify(this.state[key])) {
                changes[key] = {
                    from: previousState[key],
                    to: this.state[key]
                };
            }
        });
        return changes;
    },

    // Event Handlers
    handleConnectivityChange() {
        this.checkNetworkState();
    },

    handleWifiStateChange(event) {
        this.checkNetworkState();
    },

    handleBackupStart() {
        this.config.speedTest.interval = 60000; // More frequent during backup
    },

    handleBackupComplete() {
        this.config.speedTest.interval = 300000; // Return to normal interval
    },

    handleTestRequest() {
        this.runSpeedTest();
    },

    // Public Methods
    getNetworkStatus() {
        return {
            ...this.state,
            thresholds: this.config.thresholds
        };
    },

    getNetworkHistory(duration = 3600000) { // 1 hour default
        const cutoff = Date.now() - duration;
        return this.state.history.filter(entry => entry.timestamp > cutoff);
    },

    isNetworkSuitable() {
        return (
            this.state.isConnected &&
            this.state.quality >= this.config.thresholds.quality.fair &&
            (this.state.speed.upload >= this.config.thresholds.speed.minimum ||
             this.state.speed.download >= this.config.thresholds.speed.minimum)
        );
    }
};

// Initialize network utils
networkUtils.init();

// Export for use in other modules
export default networkUtils;
