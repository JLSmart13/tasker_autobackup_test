// react/components/ProgressIndicator.jsx
import React, { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Upload, Check, AlertCircle, Clock } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';

const ProgressIndicator = ({ 
    progress, 
    status = 'idle', 
    speed = 0,
    estimatedTime = 0,
    currentFile = '',
    showDetails = true 
}) => {
    const [showSpeedWarning, setShowSpeedWarning] = useState(false);

    useEffect(() => {
        if (speed < 0.5 && status === 'running') {
            setShowSpeedWarning(true);
        } else {
            setShowSpeedWarning(false);
        }
    }, [speed, status]);

    const getStatusColor = () => {
        switch (status) {
            case 'running':
                return 'text-blue-500';
            case 'completed':
                return 'text-green-500';
            case 'error':
                return 'text-red-500';
            case 'paused':
                return 'text-yellow-500';
            default:
                return 'text-gray-500';
        }
    };

    const getStatusIcon = () => {
        switch (status) {
            case 'running':
                return (
                    <motion.div
                        animate={{ rotate: 360 }}
                        transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
                    >
                        <Upload className="h-6 w-6" />
                    </motion.div>
                );
            case 'completed':
                return <Check className="h-6 w-6" />;
            case 'error':
                return <AlertCircle className="h-6 w-6" />;
            case 'paused':
                return <Clock className="h-6 w-6" />;
            default:
                return null;
        }
    };

    const formatTime = (seconds) => {
        if (seconds < 60) return `${Math.round(seconds)}s`;
        if (seconds < 3600) {
            const minutes = Math.floor(seconds / 60);
            const remainingSeconds = Math.round(seconds % 60);
            return `${minutes}m ${remainingSeconds}s`;
        }
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        return `${hours}h ${minutes}m`;
    };

    const formatSpeed = (mbps) => {
        if (mbps < 0.1) return `${(mbps * 1000).toFixed(1)} KB/s`;
        return `${mbps.toFixed(1)} MB/s`;
    };

    return (
        <Card className="w-full">
            <CardContent className="pt-6">
                <div className="space-y-4">
                    {/* Progress Circle */}
                    <div className="flex justify-center">
                        <div className="relative w-24 h-24">
                            {/* Background Circle */}
                            <svg className="w-full h-full" viewBox="0 0 100 100">
                                <circle
                                    className="text-gray-200"
                                    strokeWidth="8"
                                    stroke="currentColor"
                                    fill="transparent"
                                    r="42"
                                    cx="50"
                                    cy="50"
                                />
                                <motion.circle
                                    className={getStatusColor()}
                                    strokeWidth="8"
                                    stroke="currentColor"
                                    fill="transparent"
                                    r="42"
                                    cx="50"
                                    cy="50"
                                    initial={{ pathLength: 0 }}
                                    animate={{ pathLength: progress / 100 }}
                                    transition={{ duration: 0.5, ease: "easeInOut" }}
                                    strokeLinecap="round"
                                    transform="rotate(-90 50 50)"
                                    style={{
                                        strokeDasharray: "264, 264",
                                    }}
                                />
                            </svg>
                            {/* Center Icon */}
                            <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2">
                                {getStatusIcon()}
                            </div>
                        </div>
                    </div>

                    {/* Progress Text */}
                    <div className="text-center">
                        <div className="text-2xl font-semibold">
                            {progress}%
                        </div>
                        {showDetails && (
                            <motion.div
                                initial={{ opacity: 0, y: 10 }}
                                animate={{ opacity: 1, y: 0 }}
                                className="text-sm text-gray-500 mt-1"
                            >
                                {status === 'running' && (
                                    <>
                                        <div>{formatSpeed(speed)}</div>
                                        <div>ETA: {formatTime(estimatedTime)}</div>
                                    </>
                                )}
                            </motion.div>
                        )}
                    </div>

                    {/* Current File */}
                    {currentFile && showDetails && (
                        <div className="text-center text-sm text-gray-500">
                            <div className="truncate max-w-xs mx-auto">
                                {currentFile}
                            </div>
                        </div>
                    )}

                    {/* Warnings */}
                    <AnimatePresence>
                        {showSpeedWarning && (
                            <motion.div
                                initial={{ opacity: 0, y: 20 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: -20 }}
                            >
                                <Alert variant="warning">
                                    <AlertCircle className="h-4 w-4" />
                                    <AlertDescription>
                                        Slow upload speed detected. Check your network connection.
                                    </AlertDescription>
                                </Alert>
                            </motion.div>
                        )}
                    </AnimatePresence>
                </div>
            </CardContent>
        </Card>
    );
};

export default ProgressIndicator;
