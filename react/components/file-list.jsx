// react/components/FileList.jsx
import React, { useState } from 'react';
import { 
    File, 
    Image, 
    Film, 
    Music, 
    Archive, 
    MoreVertical,
    ChevronUp,
    ChevronDown 
} from 'lucide-react';
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from '@/components/ui/table';
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';

const FileList = ({ files, onPriorityChange, onExclude }) => {
    const [sortConfig, setSortConfig] = useState({
        key: 'name',
        direction: 'asc'
    });

    const getFileIcon = (type) => {
        switch (type) {
            case 'image':
                return <Image className="h-4 w-4" />;
            case 'video':
                return <Film className="h-4 w-4" />;
            case 'audio':
                return <Music className="h-4 w-4" />;
            case 'archive':
                return <Archive className="h-4 w-4" />;
            default:
                return <File className="h-4 w-4" />;
        }
    };

    const formatSize = (bytes) => {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
    };

    const formatDate = (date) => {
        return new Date(date).toLocaleString();
    };

    const requestSort = (key) => {
        let direction = 'asc';
        if (sortConfig.key === key && sortConfig.direction === 'asc') {
            direction = 'desc';
        }
        setSortConfig({ key, direction });
    };

    const getSortedFiles = () => {
        const sortedFiles = [...files];
        if (sortConfig.key) {
            sortedFiles.sort((a, b) => {
                if (a[sortConfig.key] < b[sortConfig.key]) {
                    return sortConfig.direction === 'asc' ? -1 : 1;
                }
                if (a[sortConfig.key] > b[sortConfig.key]) {
                    return sortConfig.direction === 'asc' ? 1 : -1;
                }
                return 0;
            });
        }
        return sortedFiles;
    };

    const getSortIcon = (key) => {
        if (sortConfig.key === key) {
            return sortConfig.direction === 'asc' ? 
                <ChevronUp className="h-4 w-4" /> : 
                <ChevronDown className="h-4 w-4" />;
        }
        return null;
    };

    return (
        <div className="rounded-md border">
            <Table>
                <TableHeader>
                    <TableRow>
                        <TableHead className="w-12">Type</TableHead>
                        <TableHead 
                            className="cursor-pointer"
                            onClick={() => requestSort('name')}
                        >
                            <div className="flex items-center gap-2">
                                Name
                                {getSortIcon('name')}
                            </div>
                        </TableHead>
                        <TableHead 
                            className="cursor-pointer"
                            onClick={() => requestSort('size')}
                        >
                            <div className="flex items-center gap-2">
                                Size
                                {getSortIcon('size')}
                            </div>
                        </TableHead>
                        <TableHead 
                            className="cursor-pointer"
                            onClick={() => requestSort('modified')}
                        >
                            <div className="flex items-center gap-2">
                                Modified
                                {getSortIcon('modified')}
                            </div>
                        </TableHead>
                        <TableHead 
                            className="cursor-pointer"
                            onClick={() => requestSort('priority')}
                        >
                            <div className="flex items-center gap-2">
                                Priority
                                {getSortIcon('priority')}
                            </div>
                        </TableHead>
                        <TableHead className="w-12"></TableHead>
                    </TableRow>
                </TableHeader>
                <TableBody>
                    {getSortedFiles().map((file) => (
                        <TableRow key={file.id}>
                            <TableCell>
                                {getFileIcon(file.type)}
                            </TableCell>
                            <TableCell className="font-medium">
                                {file.name}
                            </TableCell>
                            <TableCell>
                                {formatSize(file.size)}
                            </TableCell>
                            <TableCell>
                                {formatDate(file.modified)}
                            </TableCell>
                            <TableCell>
                                <span className={`
                                    inline-flex items-center rounded-full px-2 py-1 text-xs font-medium
                                    ${file.priority === 'high' ? 'bg-red-100 text-red-700' : 
                                      file.priority === 'medium' ? 'bg-yellow-100 text-yellow-700' : 
                                      'bg-green-100 text-green-700'}
                                `}>
                                    {file.priority}
                                </span>
                            </TableCell>
                            <TableCell>
                                <DropdownMenu>
                                    <DropdownMenuTrigger>
                                        <MoreVertical className="h-4 w-4" />
                                    </DropdownMenuTrigger>
                                    <DropdownMenuContent align="end">
                                        <DropdownMenuItem
                                            onClick={() => onPriorityChange(file.id, 'high')}
                                        >
                                            Set High Priority
                                        </DropdownMenuItem>
                                        <DropdownMenuItem
                                            onClick={() => onPriorityChange(file.id, 'medium')}
                                        >
                                            Set Medium Priority
                                        </DropdownMenuItem>
                                        <DropdownMenuItem
                                            onClick={() => onPriorityChange(file.id, 'low')}
                                        >
                                            Set Low Priority
                                        </DropdownMenuItem>
                                        <DropdownMenuItem
                                            onClick={() => onExclude(file.id)}
                                            className="text-red-600"
                                        >
                                            Exclude from Backup
                                        </DropdownMenuItem>
                                    </DropdownMenuContent>
                                </DropdownMenu>
                            </TableCell>
                        </TableRow>
                    ))}
                </TableBody>
            </Table>
        </div>
    );
};

export default FileList;
