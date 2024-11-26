// file_monitor.js
const fileMonitor = {
    watchPaths: new Set(),
    fileStates: new Map(),
    checksumCache: new Map(),
    
    init: function() {
        this.loadConfiguration();
        this.startWatching();
    },

    loadConfiguration: function() {
        try {
            const config = JSON.parse(global('WATCH_PATHS'));
            config.paths.forEach(path => this.addWatchPath(path));
        } catch (e) {
            // Default paths if no configuration found
            this.addWatchPath('/storage/emulated/0/Documents');
            this.addWatchPath('/storage/emulated/0/Pictures');
        }
    },

    addWatchPath: function(path) {
        this.watchPaths.add(path);
        this.scanPath(path);
    },

    scanPath: function(path) {
        const files = this.getFilesInPath(path);
        files.forEach(file => {
            this.processFile(file);
        });
    },

    getFilesInPath: function(path) {
        return Array.prototype.slice.call(listFiles(path));
    },

    processFile: function(file) {
        const stats = this.getFileStats(file);
        const currentState = this.fileStates.get(file.path);

        if (!currentState) {
            // New file
            this.fileStates.set(file.path, stats);
            this.notifyFileAdded(file);
        } else if (this.hasFileChanged(currentState, stats)) {
            // Modified file
            this.fileStates.set(file.path, stats);
            this.notifyFileChanged(file);
        }
    },

    getFileStats: function(file) {
        return {
            size: file.size(),
            modified: file.lastModified(),
            checksum: this.getFileChecksum(file)
        };
    },

    getFileChecksum: function(file) {
        const cacheKey = `${file.path}-${file.lastModified()}`;
        if (this.checksumCache.has(cacheKey)) {
            return this.checksumCache.get(cacheKey);
        }

        const checksum = JavaWrapper.MD5(new File(file.path));
        this.checksumCache.set(cacheKey, checksum);
        return checksum;
    },

    hasFileChanged: function(oldStats, newStats) {
        return oldStats.size !== newStats.size ||
               oldStats.modified !== newStats.modified ||
               oldStats.checksum !== newStats.checksum;
    },

    startWatching: function() {
        // Main monitoring loop
        setInterval(() => {
            this.watchPaths.forEach(path => {
                this.scanPath(path);
            });
            this.cleanupDeletedFiles();
        }, 5000);
    },

    cleanupDeletedFiles: function() {
        for (const [path, stats] of this.fileStates) {
            if (!fileExists(path)) {
                this.fileStates.delete(path);
                this.notifyFileDeleted(path);
            }
        }
    },

    notifyFileAdded: function(file) {
        eventBus.emit('fileAdded', {
            path: file.path,
            name: file.name,
            size: file.size(),
            modified: file.lastModified(),
            type: this.getFileType(file)
        });
    },

    notifyFileChanged: function(file) {
        eventBus.emit('fileChanged', {
            path: file.path,
            name: file.name,
            size: file.size(),
            modified: file.lastModified(),
            type: this.getFileType(file)
        });
    },

    notifyFileDeleted: function(path) {
        eventBus.emit('fileDeleted', { path });
    },

    getFileType: function(file) {
        const ext = file.name.split('.').pop().toLowerCase();
        return fileTypeUtils.getFileTypeInfo(ext);
    }
};
