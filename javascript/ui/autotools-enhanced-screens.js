// Base configuration for all screens
const baseConfig = {
    theme: {
        type: 'material_you',
        dynamicColors: true,
        animations: true,
        transitions: {
            duration: 300,
            type: 'spring'
        }
    },
    gestures: {
        swipe: true,
        longPress: true,
        doubleTap: true
    }
};

// Enhanced Statistics Dashboard
const statsDashboard = {
    ...baseConfig,
    layout: 'grid',
    columns: 2,
    items: [
        {
            type: 'chart',
            title: 'Backup Performance',
            data: '%backup_stats',
            chartType: 'line',
            interactive: true,
            features: {
                zoom: true,
                timeRange: ['1h', '24h', '7d', '30d'],
                dataPoints: ['speed', 'files', 'success_rate'],
                annotations: true,
                tooltip: {
                    enabled: true,
                    format: 'detailed'
                },
                compare: {
                    enabled: true,
                    periods: ['previous', 'average']
                }
            }
        },
        {
            type: 'pieChart',
            title: 'Storage Analysis',
            interactive: true,
            features: {
                drill: true,
                filter: true,
                legend: {
                    interactive: true,
                    position: 'right'
                },
                segments: {
                    expandable: true,
                    highlight: true
                }
            }
        }
    ]
};

// Enhanced File Manager
const fileManager = {
    ...baseConfig,
    layout: 'adaptive',
    views: ['list', 'grid', 'timeline'],
    features: {
        search: {
            type: 'advanced',
            filters: ['type', 'size', 'date', 'status'],
            suggestions: true,
            history: true
        },
        sort: {
            fields: ['name', 'date', 'size', 'type', 'priority'],
            direction: 'asc',
            multiple: true
        },
        selection: {
            type: 'multiple',
            actions: ['backup', 'delete', 'priority', 'exclude'],
            drag: true
        },
        preview: {
            enabled: true,
            types: ['image', 'text', 'pdf'],
            sidebar: true
        }
    }
};

// New Screen: Backup Rules Manager
const rulesManager = {
    ...baseConfig,
    layout: 'cards',
    items: [
        {
            type: 'ruleBuilder',
            title: 'Backup Rules',
            features: {
                conditions: [
                    'fileType',
                    'size',
                    'age',
                    'location',
                    'network',
                    'battery',
                    'schedule'
                ],
                actions: [
                    'backup',
                    'ignore',
                    'notify',
                    'compress',
                    'encrypt'
                ],
                templates: true,
                testing: true
            }
        }
    ]
};

// New Screen: System Health Monitor
const healthMonitor = {
    ...baseConfig,
    layout: 'dashboard',
    refresh: 5000,
    items: [
        {
            type: 'metrics',
            layout: 'grid',
            items: [
                {
                    type: 'gauge',
                    title: 'Storage',
                    value: '%storage_used',
                    thresholds: [
                        { value: 75, color: 'warning' },
                        { value: 90, color: 'danger' }
                    ],
                    interactive: true
                },
                {
                    type: 'lineGraph',
                    title: 'Network',
                    metrics: ['speed', 'latency', 'quality'],
                    realtime: true
                }
            ]
        }
    ]
};

// New Screen: Backup Queue Manager
const queueManager = {
    ...baseConfig,
    layout: 'split',
    views: {
        left: {
            type: 'queue',
            title: 'Pending',
            draggable: true,
            features: {
                prioritize: true,
                reorder: true,
                pause: true
            }
        },
        right: {
            type: 'completed',
            title: 'Completed',
            features: {
                filter: true,
                search: true,
                status: true
            }
        }
    }
};

// New Screen: Schedule Optimizer
const scheduleOptimizer = {
    ...baseConfig,
    layout: 'calendar',
    features: {
        timeSlots: {
            editable: true,
            drag: true,
            resize: true,
            repeat: true
        },
        rules: {
            network: ['wifi', 'ethernet', 'mobile'],
            power: ['charging', 'battery_level'],
            system: ['idle', 'screen_off', 'cpu_usage']
        },
        optimization: {
            auto: true,
            suggestions: true,
            conflicts: true
        }
    }
};

// New Screen: Backup Analytics
const backupAnalytics = {
    ...baseConfig,
    layout: 'tabs',
    sections: [
        {
            title: 'Performance',
            type: 'charts',
            items: [
                {
                    type: 'speedHistory',
                    range: 'dynamic',
                    annotations: true
                },
                {
                    type: 'successRate',
                    breakdown: ['type', 'size', 'time']
                }
            ]
        },
        {
            title: 'Storage',
            type: 'analysis',
            items: [
                {
                    type: 'treeMap',
                    data: '%storage_usage',
                    interactive: true
                },
                {
                    type: 'trends',
                    metrics: ['growth', 'patterns', 'predictions']
                }
            ]
        }
    ]
};

// Interactive Features for All Screens
const interactiveFeatures = {
    gestures: {
        swipeLeft: 'nextScreen',
        swipeRight: 'previousScreen',
        swipeDown: 'refresh',
        swipeUp: 'details'
    },
    tooltips: {
        enabled: true,
        interactive: true,
        position: 'smart'
    },
    contextMenus: {
        enabled: true,
        customizable: true
    },
    shortcuts: {
        keyboard: true,
        gesture: true,
        custom: true
    },
    notifications: {
        position: 'bottom',
        interactive: true,
        actions: true
    }
};

// Floating Action Button Menu
const fabMenu = {
    type: 'speed_dial',
    items: [
        {
            icon: 'backup',
            label: 'Quick Backup',
            action: 'startBackup'
        },
        {
            icon: 'schedule',
            label: 'Schedule',
            action: 'openSchedule'
        },
        {
            icon: 'settings',
            label: 'Settings',
            action: 'openSettings'
        }
    ]
};

// Export configurations
export const screens = {
    statsDashboard,
    fileManager,
    rulesManager,
    healthMonitor,
    queueManager,
    scheduleOptimizer,
    backupAnalytics
};

export const features = {
    interactive: interactiveFeatures,
    fab: fabMenu
};
