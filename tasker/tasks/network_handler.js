// tasker/tasks/network_handler.js
const networkHandler = {
    config: {
        minQuality: 30,
        preferredTypes: ['WIFI', 'ETHERNET'],
        allowMobile: false,
        speedTest: {
            interval: 300, // 5 minutes
            timeout: 30,
            samples: 3
        }
    },

    taskConfig: {
        name: 'NetworkHandler',
        priority: 8,
        collision: 'skip'
    },

    state: {
        currentType: null,
        quality: 0,
        speed: {
            download: 0,
            upload: 0,
            latency: 0
        },
        lastTest: 0,
        isMonitoring: false
    },

    init: function() {
        this.setupEventHandlers();
        this.startMonitoring();
    },

    setupEventHandlers: function() {
        eventTrigger('CONNECTIVITY_CHANGE', this.handleConnectivityChange.bind(this));
        eventTrigger('WIFI_STATE', this.handleWifiStateChange.bind(this));
        eventTrigger('backup_started', this.handleBackupStart.bind(this));
        eventTrigger('backup_complete', this.handleBackupComplete.bind(this));
        eventTrigger('backup_error', this.handleBackupError.bind(this));
    },

    startMonitoring: function() {
        if (this.state.isMonitoring) return;
        
        this.state.isMonitoring = true;
        this.checkNetworkState();
        
        setInterval(() => {
            this.checkNetworkState();
        }, 5000);

        setInterval(() => {
            this.runSpeedTest();
        }, this.config.speedTest.interval * 1000);
    },

    checkNetworkState: function() {
        const wifi = global('WIFI') === 'on';
        const mobile = global('MOBILE') === 'on';
        const vpn = global('VPN') === 'on';

        let type = 'none';
        if (wifi) type = 'WIFI';
        else if (mobile) type = 'MOBILE';

        if (type !== this.state.currentType) {
            this.handleNetworkTypeChange(type);
        }

        this.updateQualityMetrics();
    },

    handleNetworkTypeChange: function(newType) {
        const oldType = this.state.currentType;
        this.state.currentType = newType;

        if (this.isNetworkSuitable()) {
            if (oldType === null || !this.isNetworkSuitable(oldType)) {
                eventBus.emit('networkAvailable', this.getNetworkStatus());
            }
        } else {
            if (this.isNetworkSuitable(oldType)) {
                eventBus.emit('networkLost', {
                    previousType: oldType,
                    newType: newType
                });
            }
        }

        this.runSpeedTest();
    },

    updateQualityMetrics: function() {
        let quality = 0;

        switch (this.state.currentType) {
            case 'WIFI':
                const signal = parseInt(global('WIFI_SIGNAL'));
                quality = this.calculateWifiQuality(signal);
                break;

            case 'MOBILE':
                const strength = parseInt(global('CELLSIG'));
                quality = this.calculateMobileQuality(strength);
                break;

            default:
                quality = 0;
        }

        if (Math.abs(this.state.quality - quality) > 5) {
            this.state.quality = quality;
            eventBus.emit('networkQualityChange', {
                quality: quality,
                type: this.state.currentType
            });
        }
    },

    calculateWifiQuality: function(signal) {
        return Math.min(100, Math.max(0, 2 * (signal + 100)));
    },

    calculateMobileQuality: function(strength) {
        return Math.min(100, Math.max(0, (strength / 31) * 100));
    },

    async runSpeedTest: function() {
        if (!this.shouldRunSpeedTest()) return;

        try {
            this.state.lastTest = Date.now();
            const results = await this.performSpeedTest();
            this.updateSpeedMetrics(results);
        } catch (error) {
            logError('Speed test failed:', error);
            eventBus.emit('networkTestFailed', error);
        }
    },

    shouldRunSpeedTest: function() {
        const timeSinceLastTest = (Date.now() - this.state.lastTest) / 1000;
        if (timeSinceLastTest < this.config.speedTest.interval) return false;
        if (!this.isNetworkSuitable()) return false;
        return true;
    },

    async performSpeedTest: function() {
        const results = {
            download: 0,
            upload: 0,
            latency: 0
        };

        for (let i = 0; i < this.config.speedTest.samples; i++) {
            const sample = await this.singleSpeedTest();
            results.download += sample.download;
            results.upload += sample.upload;
            results.latency += sample.latency;
        }

        results.download /= this.config.speedTest.samples;
        results.upload /= this.config.speedTest.samples;
        results.latency /= this.config.speedTest.samples;

        return results;
    },

    async singleSpeedTest: function() {
        return new Promise((resolve) => {
            Java.perform(() => {
                const NetworkCapabilities = Java.use('android.net.NetworkCapabilities');
                const Context = Java.use('android.content.Context');
                const connectivityManager = Context.getSystemService(Context.CONNECTIVITY_SERVICE);
                const network = connectivityManager.getActiveNetwork();
                const capabilities = connectivityManager.getNetworkCapabilities(network);
                
                const downloadSpeed = capabilities.getLinkDownstreamBandwidthKbps() / 1000; // Convert to Mbps
                const uploadSpeed = capabilities.getLinkUpstreamBandwidthKbps() / 1000; // Convert to Mbps
                
                resolve({
                    download: downloadSpeed,
                    upload: uploadSpeed,
                    latency: this.measureLatency()
                });
            });
        });
    },

    measureLatency: function() {
        return new Promise((resolve) => {
            Java.perform(() => {
                const InetAddress = Java.use('java.net.InetAddress');
                const startTime = Date.now();
                
                try {
                    InetAddress.getByName('8.8.8.8').isReachable(1000);
                    const latency = Date.now() - startTime;
                    resolve(latency);
                } catch (e) {
                    resolve(999); // High latency value to indicate issues
                }
            });
        });
    },

    updateSpeedMetrics: function(results) {
        this.state.speed = results;
        eventBus.emit('networkSpeedUpdate', results);
        
        const status = this.getNetworkStatus();
        eventBus.emit('networkStatusUpdate', status);
    },

    isNetworkSuitable: function(type = this.state.currentType) {
        if (!type) return false;
        if (!this.config.allowMobile && type === 'MOBILE') return false;
        if (!this.config.preferredTypes.includes(type)) return false;
        if (this.state.quality < this.config.minQuality) return false;
        return true;
    },

    getNetworkStatus: function() {
        return {
            type: this.state.currentType,
            quality: this.state.quality,
            speed: this.state.speed,
            suitable: this.isNetworkSuitable(),
            lastTest: this.state.lastTest
        };
    },

    handleBackupStart: function() {
        this.config.speedTest.interval = 60;
        this.runSpeedTest();
    },

    handleBackupComplete: function() {
        this.config.speedTest.interval = 300;
    },

    handleBackupError: function(error) {
        if (error.code === 'NETWORK_ERROR') {
            this.runSpeedTest();
        }
    },

    handleConnectivityChange: function() {
        this.checkNetworkState();
    },

    handleWifiStateChange: function(data) {
        if (data.state === 'DISCONNECTED') {
            this.handleNetworkTypeChange('MOBILE');
        } else {
            this.checkNetworkState();
        }
    }
};

// Initialize network handler
networkHandler.init();

// Export the module
module.exports = networkHandler;
