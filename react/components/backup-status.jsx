// react/components/BackupStatus.jsx
import React from 'react';
import { AlertCircle, Check, Clock, Upload } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';

const BackupStatus = ({ status, currentFile, progress, error, stats }) => {
    const getStatusColor = () => {
        switch (status) {
            case 'running': return 'bg-primary';
            case 'completed': return 'bg-green-500';
            case 'error': return 'bg-red-500';
            case 'paused': return 'bg-yellow-500';
            default: return 'bg-gray-500';
        }
    };

    const getStatusIcon = () => {
        switch (status) {
            case 'running': return <Upload className="h-5 w-5" />;
            case 'completed': return <Check className="h-5 w-5" />;
            case 'error': return <AlertCircle className="h-5 w-5" />;
            case 'paused': return <Clock className="h-5 w-5" />;
            default: return null;
        }
    };

    return (
        <Card>
            <CardHeader>
                <CardTitle className="flex items-center justify-between">
                    <span>Backup Status</span>
                    <div className={`${getStatusColor()} p-2 rounded-full`}>
                        {getStatusIcon()}
                    </div>
                </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
                {error && (
                    <Alert variant="destructive">
                        <AlertCircle className="h-4 w-4" />
                        <AlertTitle>Error</AlertTitle>
                        <AlertDescription>{error}</AlertDescription>
                    </Alert>
                )}

                <div className="space-y-2">
                    {currentFile && (
                        <div>
                            <p className="text-sm text-muted-foreground">Current File</p>
                            <p className="font-medium truncate">{currentFile}</p>
                        </div>
                    )}

                    {progress !== undefined && (
                        <div>
                            <div className="flex justify-between text-sm mb-1">
                                <span>Progress</span>
                                <span>{progress}%</span>
                            </div>
                            <div className="w-full bg-secondary rounded-full h-2">
                                <div 
                                    className="bg-primary rounded-full h-2 transition-all duration-300"
                                    style={{ width: `${progress}%` }}
                                />
                            </div>
                        </div>
                    )}

                    {stats && (
                        <div className="grid grid-cols-2 gap-4 pt-4">
                            <div>
                                <p className="text-sm text-muted-foreground">Files Processed</p>
                                <p className="font-medium">{stats.processedFiles} / {stats.totalFiles}</p>
                            </div>
                            <div>
                                <p className="text-sm text-muted-foreground">Upload Speed</p>
                                <p className="font-medium">{stats.speed} MB/s</p>
                            </div>
                            <div>
                                <p className="text-sm text-muted-foreground">Time Remaining</p>
                                <p className="font-medium">{stats.timeRemaining}</p>
                            </div>
                            <div>
                                <p className="text-sm text-muted-foreground">Total Size</p>
                                <p className="font-medium">{stats.totalSize}</p>
                            </div>
                        </div>
                    )}
                </div>
            </CardContent>
        </Card>
    );
};

export default BackupStatus;
