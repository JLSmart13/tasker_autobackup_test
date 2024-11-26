import React, { useState, useRef, useEffect } from 'react';
import { 
  X, Minimize, Maximize2, Wifi, WifiOff, AlertCircle, 
  Pause, Play, RotateCcw, Settings, ChevronRight,
  Download, Trash, CloudOff, File, Image, Video,
  Music, FileText, Archive, Code, Table, Film,
  FileJson, FileSpreadsheet, Mail, Camera,
  Folder, Database
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { Card } from '@/components/ui/card';

// File type icon mapping
const FileTypeIcon = ({ type, className = "w-4 h-4" }) => {
  const iconMap = {
    // Documents
    'pdf': FileText,
    'doc': FileText,
    'docx': FileText,
    'txt': FileText,
    'md': FileText,
    'rtf': FileText,
    
    // Images
    'jpg': Image,
    'jpeg': Image,
    'png': Image,
    'gif': Image,
    'svg': Image,
    'webp': Image,
    'raw': Camera,
    
    // Video
    'mp4': Video,
    'mov': Video,
    'avi': Film,
    'mkv': Film,
    'webm': Film,
    
    // Audio
    'mp3': Music,
    'wav': Music,
    'flac': Music,
    'm4a': Music,
    
    // Archives
    'zip': Archive,
    'rar': Archive,
    '7z': Archive,
    'tar': Archive,
    'gz': Archive,
    
    // Code
    'js': Code,
    'py': Code,
    'java': Code,
    'cpp': Code,
    'html': Code,
    'css': Code,
    
    // Data
    'json': FileJson,
    'csv': Table,
    'xlsx': FileSpreadsheet,
    'xls': FileSpreadsheet,
    'sql': Database,
    
    // Email
    'eml': Mail,
    'msg': Mail,
    
    // Folders
    'folder': Folder,
    
    // Default
    'default': File
  };

  const getIconComponent = (filename) => {
    const extension = filename.split('.').pop().toLowerCase();
    return iconMap[extension] || iconMap.default;
  };

  const IconComponent = getIconComponent(type);
  return <IconComponent className={className} />;
};

const FileTypeBadge = ({ filename, animate = true }) => {
  const extension = filename.split('.').pop().toLowerCase();
  
  const badgeVariants = {
    initial: { scale: 0.8, opacity: 0 },
    animate: { scale: 1, opacity: 1 },
    exit: { scale: 0.8, opacity: 0 }
  };

  return (
    <motion.div
      variants={animate ? badgeVariants : undefined}
      initial={animate ? "initial" : undefined}
      animate={animate ? "animate" : undefined}
      exit={animate ? "exit" : undefined}
      className="flex items-center gap-1 px-2 py-1 rounded-md"
      style={{
        backgroundColor: currentTheme.surfaceVariant,
        color: currentTheme.onSurface
      }}
    >
      <FileTypeIcon type={filename} />
      <span className="text-xs uppercase">{extension}</span>
    </motion.div>
  );
};

// Current file section with icon
const CurrentFile = ({ file, progress }) => {
  return (
    <div className="flex items-center gap-3">
      <FileTypeBadge filename={file} />
      <div className="flex-1">
        <div className="text-sm font-medium truncate">{file}</div>
        <div className="h-1 mt-1 rounded-full overflow-hidden bg-surfaceVariant">
          <motion.div
            className="h-full bg-primary"
            initial={{ width: 0 }}
            animate={{ width: `${progress}%` }}
            transition={{ duration: 0.3 }}
          />
        </div>
      </div>
    </div>
  );
};

// Log entry with file type
const LogEntry = ({ entry }) => {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="flex items-center gap-2 p-2 rounded-lg mb-2"
      style={{
        backgroundColor: currentTheme.surfaceContainer
      }}
    >
      <FileTypeIcon type={entry.filename} />
      <div className="flex-1">
        <div className="text-sm truncate">{entry.filename}</div>
        <div className="text-xs" style={{ color: currentTheme.outline }}>
          {entry.timestamp.toLocaleTimeString()}
        </div>
      </div>
      <div 
        className="text-xs px-2 py-1 rounded"
        style={{
          backgroundColor: getStatusColor(entry.status).bg,
          color: getStatusColor(entry.status).text
        }}
      >
        {entry.status}
      </div>
    </motion.div>
  );
};

// Function to get status colors
const getStatusColor = (status) => {
  const colors = {
    completed: {
      bg: currentTheme.primaryContainer,
      text: currentTheme.onPrimaryContainer
    },
    error: {
      bg: currentTheme.errorContainer,
      text: currentTheme.error
    },
    uploading: {
      bg: currentTheme.surfaceVariant,
      text: currentTheme.onSurface
    }
  };
  return colors[status] || colors.uploading;
};

// Recent files list with icons
const RecentFiles = ({ files }) => {
  return (
    <div className="mt-4">
      <div className="text-sm font-medium mb-2">Recent Files</div>
      <div className="space-y-2">
        {files.map((file, index) => (
          <motion.div
            key={file.id}
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: index * 0.1 }}
            className="flex items-center gap-2 p-2 rounded-lg"
            style={{
              backgroundColor: currentTheme.surfaceVariant
            }}
          >
            <FileTypeIcon type={file.name} />
            <div className="flex-1">
              <div className="text-sm truncate">{file.name}</div>
              <div className="text-xs" style={{ color: currentTheme.outline }}>
                {file.size}
              </div>
            </div>
            <motion.div
              className="w-1 h-1 rounded-full"
              style={{
                backgroundColor: 
                  file.status === 'completed' ? currentTheme.primary :
                  file.status === 'error' ? currentTheme.error :
                  currentTheme.outline
              }}
            />
          </motion.div>
        ))}
      </div>
    </div>
  );
};

// Log viewer component
const LogViewer = ({ logs }) => {
  return (
    <Card className="mt-4 p-4">
      <div className="text-sm font-medium mb-4">Upload History</div>
      <div className="space-y-2 max-h-60 overflow-y-auto">
        {logs.map((entry) => (
          <LogEntry key={entry.id} entry={entry} />
        ))}
      </div>
    </Card>
  );
};

// Rest of the BackupPIPMonitor component remains the same,
// but now uses these new components in its render method
// [Previous component code continues...]
