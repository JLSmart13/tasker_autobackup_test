// File type categorization and utilities
const fileTypeUtils = {
    // Get detailed file type info
    getFileTypeInfo(filename) {
        const extension = filename.split('.').pop().toLowerCase();
        
        const typeMap = {
            // Documents
            'pdf': { 
                category: 'document',
                icon: 'file-text',
                color: '#FF5733'
            },
            'doc': { 
                category: 'document',
                icon: 'file-text',
                color: '#2B579A'
            },
            'docx': {
                category: 'document',
                icon: 'file-text',
                color: '#2B579A'
            },
            
            // Images
            'jpg': {
                category: 'image',
                icon: 'image',
                color: '#34A853'
            },
            'jpeg': {
                category: 'image',
                icon: 'image',
                color: '#34A853'
            },
            'png': {
                category: 'image',
                icon: 'image',
                color: '#34A853'
            },
            
            // Video
            'mp4': {
                category: 'video',
                icon: 'video',
                color: '#EA4335'
            },
            'mov': {
                category: 'video',
                icon: 'film',
                color: '#EA4335'
            },
            
            // Audio
            'mp3': {
                category: 'audio',
                icon: 'music',
                color: '#FBBC05'
            },
            'wav': {
                category: 'audio',
                icon: 'music',
                color: '#FBBC05'
            },
            
            // Archives
            'zip': {
                category: 'archive',
                icon: 'archive',
                color: '#8E44AD'
            },
            'rar': {
                category: 'archive',
                icon: 'archive',
                color: '#8E44AD'
            },
            
            // Code
            'js': {
                category: 'code',
                icon: 'code',
                color: '#F7DF1E'
            },
            'py': {
                category: 'code',
                icon: 'code',
                color: '#3776AB'
            },
            
            // Default
            'default': {
                category: 'other',
                icon: 'file',
                color: '#95A5A6'
            }
        };
        
        return typeMap[extension] || typeMap.default;
    },
    
    // Format file size
    formatFileSize(bytes) {
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        if (bytes === 0) return '0 B';
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${sizes[i]}`;
    },
    
    // Group files by type
    groupFilesByType(files) {
        return files.reduce((groups, file) => {
            const typeInfo = this.getFileTypeInfo(file.name);
            if (!groups[typeInfo.category]) {
                groups[typeInfo.category] = [];
            }
            groups[typeInfo.category].push(file);
            return groups;
        }, {});
    },
    
    // Get file type statistics
    getTypeStatistics(files) {
        const groups = this.groupFilesByType(files);
        return Object.entries(groups).map(([type, files]) => ({
            type,
            count: files.length,
            totalSize: files.reduce((sum, file) => sum + file.size, 0)
        }));
    }
};

export default fileTypeUtils;
