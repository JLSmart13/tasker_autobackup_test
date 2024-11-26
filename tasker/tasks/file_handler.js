// file_handler.js
const fileHandler = {
    // Configuration
    config: {
        maxFileSize: 2 * 1024 * 1024 * 1024, // 2GB
        chunkSize: 1024 * 1024, // 1MB default
        compressionThreshold: 10 * 1024 * 1024, // 10MB
        tempDir: '/storage/emulated/0/Backup/temp/',
        supportedTypes: new Set([
            'document', 'image', 'video', 'audio',
            'archive', 'text', 'application'
        ])
    },

    // Initialization
    init: function() {
        this.ensureDirectories();
        this.setupEventListeners();
        this.initializeProcessors();
    },

    ensureDirectories: function() {
        [this.config.tempDir].forEach(dir => {
            if (!fileExists(dir)) {
                createDirectory(dir);
            }
        });
    },

    setupEventListeners: function() {
        eventBus.on('networkConfigUpdate', this.updateChunkSize.bind(this));
        eventBus.on('storageWarning', this.handleStorageWarning.bind(this));
    },

    initializeProcessors: function() {
        this.processors = {
            document: new DocumentProcessor(),
            image: new ImageProcessor(),
            video: new VideoProcessor(),
            audio: new AudioProcessor(),
            archive: new ArchiveProcessor(),
            text: new TextProcessor(),
            application: new ApplicationProcessor()
        };
    },

    // Main File Processing
    async processFile(file, options = {}) {
        try {
            await this.validateFile(file);
            const processedFile = await this.prepareFile(file, options);
            const chunks = await this.createChunks(processedFile);
            const metadata = await this.generateMetadata(processedFile);
            
            return {
                file: processedFile,
                chunks,
                metadata
            };
        } catch (error) {
            this.handleProcessingError(file, error);
            throw error;
        }
    },

    async validateFile(file) {
        // Size check
        if (file.size > this.config.maxFileSize) {
            throw new Error('File exceeds maximum size limit');
        }

        // Type check
        const type = fileTypeUtils.getFileType(file.name);
        if (!this.config.supportedTypes.has(type)) {
            throw new Error('Unsupported file type');
        }

        // Accessibility check
        if (!await this.isFileAccessible(file)) {
            throw new Error('File is not accessible');
        }

        return true;
    },

    async prepareFile(file, options) {
        const processor = this.processors[fileTypeUtils.getFileType(file.name)];
        if (!processor) {
            return file;
        }

        // Process based on file type and options
        const processedFile = await processor.process(file, {
            compress: this.shouldCompress(file),
            encrypt: options.encrypt,
            optimize: options.optimize
        });

        return processedFile;
    },

    shouldCompress(file) {
        if (file.size < this.config.compressionThreshold) {
            return false;
        }

        const type = fileTypeUtils.getFileType(file.name);
        const compressibleTypes = ['document', 'text', 'image'];
        return compressibleTypes.includes(type);
    },

    async createChunks(file) {
        const chunks = [];
        const totalChunks = Math.ceil(file.size / this.config.chunkSize);
        
        for (let i = 0; i < totalChunks; i++) {
            const start = i * this.config.chunkSize;
            const end = Math.min(start + this.config.chunkSize, file.size);
            
            const chunk = await this.readChunk(file, start, end);
            const checksum = await this.calculateChecksum(chunk);
            
            chunks.push({
                index: i,
                size: chunk.length,
                checksum,
                data: chunk
            });
        }

        return chunks;
    },

    async readChunk(file, start, end) {
        return new Promise((resolve, reject) => {
            try {
                const reader = new FileReader();
                reader.onload = () => resolve(reader.result);
                reader.onerror = reject;
                
                const blob = file.slice(start, end);
                reader.readAsArrayBuffer(blob);
            } catch (error) {
                reject(error);
            }
        });
    },

    async generateMetadata(file) {
        return {
            name: file.name,
            size: file.size,
            type: fileTypeUtils.getFileType(file.name),
            modified: file.lastModified,
            checksum: await this.calculateFileChecksum(file),
            chunks: file.chunks?.length || 0,
            compressed: file.compressed || false,
            encrypted: file.encrypted || false,
            originalSize: file.originalSize || file.size,
            permissions: await this.getFilePermissions(file),
            attributes: await this.getFileAttributes(file)
        };
    },

    // File Operations
    async moveFile(source, destination) {
        try {
            await this.copyFile(source, destination);
            await this.verifyFile(source, destination);
            await this.deleteFile(source);
        } catch (error) {
            await this.handleMoveError(source, destination, error);
            throw error;
        }
    },

    async copyFile(source, destination) {
        return new Promise((resolve, reject) => {
            try {
                const reader = new FileReader();
                reader.onload = async () => {
                    try {
                        await writeFile(destination, reader.result);
                        resolve();
                    } catch (error) {
                        reject(error);
                    }
                };
                reader.onerror = reject;
                reader.readAsArrayBuffer(source);
            } catch (error) {
                reject(error);
            }
        });
    },

    async verifyFile(source, destination) {
        const sourceChecksum = await this.calculateFileChecksum(source);
        const destChecksum = await this.calculateFileChecksum(destination);
        
        if (sourceChecksum !== destChecksum) {
            throw new Error('File verification failed');
        }
        
        return true;
    },

    // Utility Functions
    async calculateChecksum(data) {
        return new Promise((resolve, reject) => {
            try {
                const hash = Java.use('java.security.MessageDigest')
                    .getInstance('MD5');
                hash.update(data);
                resolve(this.bytesToHex(hash.digest()));
            } catch (error) {
                reject(error);
            }
        });
    },

    async calculateFileChecksum(file) {
        return new Promise((resolve, reject) => {
            try {
                const reader = new FileReader();
                reader.onload = async () => {
                    try {
                        const checksum = await this.calculateChecksum(reader.result);
                        resolve(checksum);
                    } catch (error) {
                        reject(error);
                    }
                };
                reader.onerror = reject;
                reader.readAsArrayBuffer(file);
            } catch (error) {
                reject(error);
            }
        });
    },

    bytesToHex(bytes) {
        return Array.from(bytes)
            .map(byte => byte.toString(16).padStart(2, '0'))
            .join('');
    },

    async getFilePermissions(file) {
        return new Promise((resolve) => {
            Java.perform(() => {
                const File = Java.use('java.io.File');
                const f = File.$new(file.path);
                resolve({
                    read: f.canRead(),
                    write: f.canWrite(),
                    execute: f.canExecute()
                });
            });
        });
    },

    async getFileAttributes(file) {
        return new Promise((resolve) => {
            Java.perform(() => {
                const File = Java.use('java.io.File');
                const f = File.$new(file.path);
                resolve({
                    hidden: f.isHidden(),
                    directory: f.isDirectory(),
                    symbolic: f.isSymbolicLink()
                });
            });
        });
    },

    // Error Handling
    handleProcessingError(file, error) {
        logError(`File processing error: ${file.name}`, error);
        
        eventBus.emit('fileError', {
            file: file,
            error: error,
            timestamp: new Date()
        });

        // Save error details for reporting
        this.saveErrorReport(file, error);
    },

    async handleMoveError(source, destination, error) {
        logError(`File move error: ${source} -> ${destination}`, error);
        
        // Cleanup any partial destination file
        if (await fileExists(destination)) {
            await this.deleteFile(destination);
        }
    },

    // Event Handlers
    updateChunkSize(networkConfig) {
        this.config.chunkSize = networkConfig.chunkSize || this.config.chunkSize;
    },

    handleStorageWarning(warning) {
        if (warning.freeSpace < 1024 * 1024 * 100) { // Less than 100MB
            this.cleanup();
        }
    },

    // Cleanup
    async cleanup() {
        const tempFiles = await listFiles(this.config.tempDir);
        for (const file of tempFiles) {
            try {
                await this.deleteFile(file.path);
            } catch (error) {
                logError(`Cleanup error: ${file.path}`, error);
            }
        }
    }
};

// Initialize the file handler
fileHandler.init();

// Export the module
module.exports = fileHandler;
