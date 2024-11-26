import React, { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Switch } from '@/components/ui/switch';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip } from 'recharts';
import { FolderOpen, Wifi, Clock, Battery, Settings, AlertCircle } from 'lucide-react';

const BackupManager = () => {
  const [settings, setSettings] = useState({
    backgroundThrottle: true,
    networkPriority: true,
    cpuPriority: true,
    autoSchedule: true,
    powerManagement: true,
  });

  const [metrics, setMetrics] = useState({
    uploadSpeed: 0,
    batteryLevel: 0,
    activeUploads: 0,
    queuedFiles: 0,
    networkQuality: 0
  });

  // Sample performance data for the chart
  const performanceData = [
    { time: '10:00', speed: 2.4 },
    { time: '10:05', speed: 3.1 },
    { time: '10:10', speed: 2.8 },
    { time: '10:15', speed: 3.4 },
    { time: '10:20', speed: 2.9 }
  ];

  return (
    <div className="max-w-4xl mx-auto p-4 space-y-4">
      {/* Header Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <span>Backup Manager Dashboard</span>
            <Settings className="w-6 h-6" />
          </CardTitle>
        </CardHeader>
      </Card>

      {/* Current Status */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Active Transfers</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <span>Upload Speed</span>
                <span className="font-mono">{metrics.uploadSpeed} MB/s</span>
              </div>
              <div className="flex justify-between items-center">
                <span>Active Files</span>
                <span className="font-mono">{metrics.activeUploads}</span>
              </div>
              <div className="flex justify-between items-center">
                <span>Queued Files</span>
                <span className="font-mono">{metrics.queuedFiles}</span>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-lg">System Status</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <span>Network Quality</span>
                <div className="flex space-x-1">
                  {[...Array(5)].map((_, i) => (
                    <div
                      key={i}
                      className={`w-2 h-4 rounded ${
                        i < metrics.networkQuality ? 'bg-green-500' : 'bg-gray-200'
                      }`}
                    />
                  ))}
                </div>
              </div>
              <div className="flex justify-between items-center">
                <span>Battery Level</span>
                <div className="flex items-center">
                  <Battery className="w-4 h-4 mr-2" />
                  <span>{metrics.batteryLevel}%</span>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Performance Graph */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Network Performance</CardTitle>
        </CardHeader>
        <CardContent>
          <LineChart width={600} height={200} data={performanceData}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="time" />
            <YAxis />
            <Tooltip />
            <Line type="monotone" dataKey="speed" stroke="#2563eb" />
          </LineChart>
        </CardContent>
      </Card>

      {/* Performance Controls */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Performance Controls</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <span>Background App Throttling</span>
              <Switch
                checked={settings.backgroundThrottle}
                onCheckedChange={(checked) =>
                  setSettings({ ...settings, backgroundThrottle: checked })
                }
              />
            </div>
            <div className="flex justify-between items-center">
              <span>Network Priority</span>
              <Switch
                checked={settings.networkPriority}
                onCheckedChange={(checked) =>
                  setSettings({ ...settings, networkPriority: checked })
                }
              />
            </div>
            <div className="flex justify-between items-center">
              <span>CPU Priority</span>
              <Switch
                checked={settings.cpuPriority}
                onCheckedChange={(checked) =>
                  setSettings({ ...settings, cpuPriority: checked })
                }
              />
            </div>
            <div className="flex justify-between items-center">
              <span>Auto Scheduling</span>
              <Switch
                checked={settings.autoSchedule}
                onCheckedChange={(checked) =>
                  setSettings({ ...settings, autoSchedule: checked })
                }
              />
            </div>
            <div className="flex justify-between items-center">
              <span>Power Management</span>
              <Switch
                checked={settings.powerManagement}
                onCheckedChange={(checked) =>
                  setSettings({ ...settings, powerManagement: checked })
                }
              />
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default BackupManager;
