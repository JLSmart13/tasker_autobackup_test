// queue_manager.js
const queueManager = {
    queue: [],
    activeTransfers: new Map(),
    maxConcurrent: 3,
    
    init: function() {
        this.setupEventListeners();
        this.startQueueProcessor();
    },

    setupEventListeners: function() {
        eventBus.on('networkConfigUpdate', (config) => {
            this.maxConcurrent = config.concurrent;
            this.updateActiveTransfers();
        });

        eventBus.on('fileAdded', (file) => {
            this.addToQueue(file);
        });
    },

    addToQueue: function(file) {
        const queueItem = {
            id: Date.now() + '-' + Math.random().toString(36).substr(2, 9),
            file: file,
            status: 'queued',
            priority: this.calculatePriority(file),
            attempts: 0,
            added: new Date(),
            size: file.size
        };

        this.queue.push(queueItem);
        this.sortQueue();
        this.notifyQueueUpdated();
    },

    calculatePriority: function(file) {
        // Priority based on file type and size
        let priority = 1;
        const ext = file.name.split('.').pop().toLowerCase();
        
        // Higher priority for documents and important files
        if (['doc', 'docx', 'pdf', 'txt'].includes(ext)) priority += 2;
        // Medium priority for images
        if (['jpg', 'png', 'gif'].includes(ext)) priority += 1;
        // Lower priority for large media files
        if (['mp4', 'mov', 'mp3'].includes(ext)) priority += 0;

        // Size consideration
        if (file.size < 1024 * 1024) priority += 1; // Small files get priority

        return priority;
    },

    sortQueue: function() {
        this.queue.sort((a, b) => {
            // Sort by priority first
            if (b.priority !== a.priority) return b.priority - a.priority;
            // Then by age in queue
            return a.added - b.added;
        });
    },

    startQueueProcessor: function() {
        setInterval(() => {
            this.processQueue();
        }, 1000);
    },

    processQueue: function() {
        if (this.activeTransfers.size >= this.maxConcurrent) return;

        const availableSlots = this.maxConcurrent - this.activeTransfers.size;
        const nextItems = this.queue
            .filter(item => item.status === 'queued')
            .slice(0, availableSlots);

        nextItems.forEach(item => this.startTransfer(item));
    },

    startTransfer: function(item) {
        item.status = 'transferring';
        item.startTime = new Date();
        
        this.activeTransfers.set(item.id, {
            progress: 0,
            speed: 0,
            startTime: item.startTime
        });

        this.uploadFile(item);
    },

    uploadFile: function(item) {
        const chunkSize = networkMonitor.getNetworkStatus().optimizedConfig.chunkSize;
        let uploaded = 0;
        
        const upload = async () => {
            try {
                while (uploaded < item.size) {
                    const chunk = await this.readChunk(item.file, uploaded, chunkSize);
                    await this.uploadChunk(chunk);
                    
                    uploaded += chunk.length;
                    this.updateProgress(item.id, uploaded);
                }
                
                this.completeTransfer(item.id);
            } catch (error) {
                this.handleError(item, error);
            }
        };

        upload();
    },

    updateProgress: function(id, uploaded) {
        const transfer = this.activeTransfers.get(id);
        const item = this.queue.find(i => i.id === id);
        
        if (transfer && item) {
            const now = new Date();
            const elapsed = (now - transfer.startTime) / 1000;
            const speed = uploaded / elapsed;

            transfer.progress = (uploaded / item.size) * 100;
            transfer.speed = speed;

            this.notifyProgressUpdated(id, transfer);
        }
    },

    completeTransfer: function(id) {
        const item = this.queue.find(i => i.id === id);
        if (item) {
            item.status = 'completed';
            item.completedAt = new Date();
        }
        
        this.activeTransfers.delete(id);
        this.notifyTransferCompleted(id);
        this.processQueue();
    },

    handleError: function(item, error) {
        item.attempts++;
        if (item.attempts < 3) {
            item.status = 'queued';
            setTimeout(() => {
                this.processQueue();
            }, Math.pow(2, item.attempts) * 1000);
        } else {
            item.status = 'failed';
            item.error = error.message;
            this.notifyTransferFailed(item.id, error);
        }
        
        this.activeTransfers.delete(item.id);
    },

    getQueueStatus: function() {
        return {
            queued: this.queue.filter(i => i.status === 'queued').length,
            active: this.activeTransfers.size,
            completed: this.queue.filter(i => i.status === 'completed').length,
            failed: this.queue.filter(i => i.status === 'failed').length,
            totalSize: this.queue.reduce((sum, item) => sum + item.size, 0),
            transfers: Array.from(this.activeTransfers.entries()).map(([id, transfer]) => {
                const item = this.queue.find(i => i.id === id);
                return {
                    id,
                    filename: item.file.name,
                    progress: transfer.progress,
                    speed: transfer.speed
                };
            })
        };
    },

    notifyQueueUpdated: function() {
        eventBus.emit('queueUpdated', this.getQueueStatus());
    },

    notifyProgressUpdated: function(id, transfer) {
        eventBus.emit('progressUpdated', { id, ...transfer });
    },

    notifyTransferCompleted: function(id) {
        eventBus.emit('transferCompleted', { id });
    },

    notifyTransferFailed: function(id, error) {
        eventBus.emit('transferFailed', { id, error });
    }
};
