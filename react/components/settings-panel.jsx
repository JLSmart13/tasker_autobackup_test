// react/components/SettingsPanel.jsx
import React, { useState, useEffect } from 'react';
import { 
    Wifi, 
    Battery, 
    HardDrive, 
    Clock, 
    Bell, 
    Shield,
    Save
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Switch } from '@/components/ui/switch';
import { Slider } from '@/components/ui/slider';
import { Button } from '@/components/ui/button';
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from '@/components/ui/select';

const SettingsPanel = ({ settings, onSettingChange, onSave }) => {
    const [localSettings, setLocalSettings] = useState(settings);
    const [hasChanges, setHasChanges] = useState(false);

    useEffect(() => {
        setLocalSettings(settings);
    }, [settings]);

    const handleSettingChange = (key, value) => {
        setLocalSettings(prev => {
            const newSettings = {
                ...prev,
                [key]: value
            };
            setHasChanges(JSON.stringify(newSettings) !== JSON.stringify(settings));
            return newSettings;
        });
        onSettingChange?.(key, value);
    };

    const handleSave = () => {
        onSave?.(localSettings);
        setHasChanges(false);
    };

    return (
        <div className="space-y-6">
            {/* Network Settings */}
            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <Wifi className="h-5 w-5" />
                        Network Settings
                    </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                    <div className="flex justify-between items-center">
                        <span>WiFi Only</span>
                        <Switch
                            checked={localSettings.wifiOnly}
                            onCheckedChange={(checked) => 
                                handleSettingChange('wifiOnly', checked)
                            }
                        />
                    </div>
                    <div className="space-y-2">
                        <span>Bandwidth Limit</span>
                        <Slider
                            value={[localSettings.bandwidthLimit]}
                            onValueChange={([value]) => 
                                handleSettingChange('bandwidthLimit', value)
                            }
                            max={10}
                            step={0.5}
                        />
                        <span className="text-sm text-gray-500">
                            {localSettings.bandwidthLimit} MB/s
                        </span>
                    </div>
                </CardContent>
            </Card>

            {/* Battery Settings */}
            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <Battery className="h-5 w-5" />
                        Battery Settings
                    </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                    <div className="flex justify-between items-center">
                        <span>Require Charging</span>
                        <Switch
                            checked={localSettings.requireCharging}
                            onCheckedChange={(checked) => 
                                handleSettingChange('requireCharging', checked)
                            }
                        />
                    </div>
                    <div className="space-y-2">
                        <span>Minimum Battery Level</span>
                        <Slider
                            value={[localSettings.minBatteryLevel]}
                            onValueChange={([value]) => 
                                handleSettingChange('minBatteryLevel', value)
                            }
                            max={100}
                            step={5}
                        />
                        <span className="text-sm text-gray-500">
                            {localSettings.minBatteryLevel}%
                        </span>
                    </div>
                </CardContent>
            </Card>

            {/* Storage Settings */}
            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <HardDrive className="h-5 w-5" />
                        Storage Settings
                    </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                    <div className="space-y-2">
                        <span>Maximum File Size</span>
                        <Select
                            value={localSettings.maxFileSize}
                            onValueChange={(value) => 
                                handleSettingChange('maxFileSize', value)
                            }
                        >
                            <SelectTrigger>
                                <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                                <SelectItem value="100MB">100 MB</SelectItem>
                                <SelectItem value="500MB">500 MB</SelectItem>
                                <SelectItem value="1GB">1 GB</SelectItem>
                                <SelectItem value="2GB">2 GB</SelectItem>
                                <SelectItem value="5GB">5 GB</SelectItem>
                                <SelectItem value="unlimited">Unlimited</SelectItem>
                            </SelectContent>
                        </Select>
                    </div>
                    <div className="flex justify-between items-center">
                        <span>Compress Files</span>
                        <Switch
                            checked={localSettings.compression}
                            onCheckedChange={(checked) => 
                                handleSettingChange('compression', checked)
                            }
                        />
                    </div>
                </CardContent>
            </Card>

            {/* Schedule Settings */}
            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <Clock className="h-5 w-5" />
                        Schedule Settings
                    </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                    <div className="space-y-2">
                        <span>Backup Frequency</span>
                        <Select
                            value={localSettings.backupFrequency}
                            onValueChange={(value) => 
                                handleSettingChange('backupFrequency', value)
                            }
                        >
                            <SelectTrigger>
                                <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                                <SelectItem value="hourly">Every Hour</SelectItem>
                                <SelectItem value="daily">Daily</SelectItem>
                                <SelectItem value="weekly">Weekly</SelectItem>
                                <SelectItem value="monthly">Monthly</SelectItem>
                            </SelectContent>
                        </Select>
                    </div>
                </CardContent>
            </Card>

            {/* Notification Settings */}
            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <Bell className="h-5 w-5" />
                        Notification Settings
                    </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                    <div className="flex justify-between items-center">
                        <span>Show Progress</span>
                        <Switch
                            checked={localSettings.showProgress}
                            onCheckedChange={(checked) => 
                                handleSettingChange('showProgress', checked)
                            }
                        />
                    </div>
                    <div className="flex justify-between items-center">
                        <span>Error Notifications</span>
                        <Switch
                            checked={localSettings.errorNotifications}
                            onCheckedChange={(checked) => 
                                handleSettingChange('errorNotifications', checked)
                            }
                        />
                    </div>
                    <div className="flex justify-between items-center">
                        <span>Completion Notification</span>
                        <Switch
                            checked={localSettings.completionNotification}
                            onCheckedChange={(checked) => 
                                handleSettingChange('completionNotification', checked)
                            }
                        />
                    </div>
                </CardContent>
            </Card>

            {/* Security Settings */}
            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <Shield className="h-5 w-5" />
                        Security Settings
                    </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                    <div className="flex justify-between items-center">
                        <span>Encrypt Backups</span>
                        <Switch
                            checked={localSettings.encryption}
                            onCheckedChange={(checked) => 
                                handleSettingChange('encryption', checked)
                            }
                        />
                    </div>
                    {localSettings.encryption && (
                        <div className="space-y-2">
                            <span>Encryption Level</span>
                            <Select
                                value={localSettings.encryptionLevel}
                                onValueChange={(value) => 
                                    handleSettingChange('encryptionLevel', value)
                                }
                            >
                                <SelectTrigger>
                                    <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="aes128">AES-128</SelectItem>
                                    <SelectItem value="aes256">AES-256</SelectItem>
                                </SelectContent>
                            </Select>
                        </div>
                    )}
                </CardContent>
            </Card>

            {/* Save Button */}
            {hasChanges && (
                <Button 
                    className="w-full"
                    onClick={handleSave}
                >
                    <Save className="h-4 w-4 mr-2" />
                    Save Changes
                </Button>
            )}
        </div>
    );
};

export default SettingsPanel;
