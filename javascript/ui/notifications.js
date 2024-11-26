// javascript/ui/notifications.js
const uiNotifications = {
    currentNotifications: new Map(),
    config: {
        position: 'bottom-right',
        duration: 5000,
        maxVisible: 3,
        spacing: 10,
        width: 320,
        animation: {
            duration: 300,
            easing: 'ease-in-out'
        }
    },

    init() {
        this.createContainer();
        this.setupEventListeners();
    },

    createContainer() {
        this.container = document.createElement('div');
        this.container.id = 'notification-container';
        this.container.style.cssText = `
            position: fixed;
            ${this.config.position.includes('bottom') ? 'bottom: 20px;' : 'top: 20px;'}
            ${this.config.position.includes('right') ? 'right: 20px;' : 'left: 20px;'}
            display: flex;
            flex-direction: column;
            gap: ${this.config.spacing}px;
            z-index: 9999;
            pointer-events: none;
        `;
        document.body.appendChild(this.container);
    },

    setupEventListeners() {
        eventBus.on('backupProgress', this.handleBackupProgress.bind(this));
        eventBus.on('backupError', this.handleBackupError.bind(this));
        eventBus.on('backupComplete', this.handleBackupComplete.bind(this));
        eventBus.on('networkStatus', this.handleNetworkStatus.bind(this));
        eventBus.on('systemWarning', this.handleSystemWarning.bind(this));
    },

    show(options) {
        const id = options.id || Date.now().toString();
        const notification = this.createNotification(id, options);
        
        this.currentNotifications.set(id, notification);
        this.updateNotificationStack();

        if (options.duration !== Infinity) {
            setTimeout(() => {
                this.dismiss(id);
            }, options.duration || this.config.duration);
        }

        return id;
    },

    createNotification(id, options) {
        const notification = document.createElement('div');
        notification.id = `notification-${id}`;
        notification.className = 'notification';
        notification.style.cssText = `
            width: ${this.config.width}px;
            background: var(--md-sys-color-surface);
            border: 1px solid var(--md-sys-color-outline);
            border-radius: 8px;
            padding: 16px;
            margin-bottom: ${this.config.spacing}px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            opacity: 0;
            transform: translateX(20px);
            transition: all ${this.config.animation.duration}ms ${this.config.animation.easing};
            pointer-events: auto;
        `;

        const content = this.createNotificationContent(options);
        notification.appendChild(content);

        if (options.dismissible !== false) {
            const dismissButton = this.createDismissButton(id);
            notification.appendChild(dismissButton);
        }

        this.container.appendChild(notification);
        
        // Trigger animation
        requestAnimationFrame(() => {
            notification.style.opacity = '1';
            notification.style.transform = 'translateX(0)';
        });

        return notification;
    },

    createNotificationContent(options) {
        const content = document.createElement('div');
        content.className = 'notification-content';
        content.style.cssText = 'display: flex; gap: 12px; align-items: flex-start;';

        if (options.icon) {
            const icon = document.createElement('div');
            icon.className = 'notification-icon';
            icon.innerHTML = options.icon;
            icon.style.cssText = `
                width: 24px;
                height: 24px;
                color: var(--md-sys-color-${options.type || 'primary'});
            `;
            content.appendChild(icon);
        }

        const textContent = document.createElement('div');
        textContent.className = 'notification-text';
        textContent.style.cssText = 'flex: 1;';

        if (options.title) {
            const title = document.createElement('div');
            title.className = 'notification-title';
            title.textContent = options.title;
            title.style.cssText = 'font-weight: 500; margin-bottom: 4px;';
            textContent.appendChild(title);
        }

        const message = document.createElement('div');
        message.className = 'notification-message';
        message.textContent = options.message;
        message.style.cssText = 'color: var(--md-sys-color-on-surface-variant);';
        textContent.appendChild(message);

        content.appendChild(textContent);
        return content;
    },

    createDismissButton(id) {
        const button = document.createElement('button');
        button.className = 'notification-dismiss';
        button.innerHTML = `
            <svg width="20" height="20" viewBox="0 0 20 20">
                <path d="M15 5L5 15M5 5L15 15" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
            </svg>
        `;
        button.style.cssText = `
            position: absolute;
            top: 8px;
            right: 8px;
            border: none;
            background: none;
            cursor: pointer;
            padding: 4px;
            color: var(--md-sys-color-on-surface-variant);
            opacity: 0.6;
            transition: opacity 200ms ease;
        `;
        
        button.addEventListener('click', () => this.dismiss(id));
        button.addEventListener('mouseenter', () => button.style.opacity = '1');
        button.addEventListener('mouseleave', () => button.style.opacity = '0.6');
        
        return button;
    },

    updateNotificationStack() {
        const notifications = Array.from(this.currentNotifications.values());
        const visibleCount = Math.min(notifications.length, this.config.maxVisible);

        notifications.forEach((notification, index) => {
            if (index < visibleCount) {
                notification.style.display = 'block';
                notification.style.transform = `translateY(${index * (notification.offsetHeight + this.config.spacing)}px)`;
            } else {
                notification.style.display = 'none';
            }
        });
    },

    dismiss(id) {
        const notification = this.currentNotifications.get(id);
        if (!notification) return;

        notification.style.opacity = '0';
        notification.style.transform = 'translateX(20px)';

        setTimeout(() => {
            notification.remove();
            this.currentNotifications.delete(id);
            this.updateNotificationStack();
        }, this.config.animation.duration);
    },

    dismissAll() {
        Array.from(this.currentNotifications.keys()).forEach(id => {
            this.dismiss(id);
        });
    },

    // Event Handlers
    handleBackupProgress(data) {
        const id = 'backup-progress';
        const existing = this.currentNotifications.has(id);

        const options = {
            id,
            title: 'Backup in Progress',
            message: `${data.current} (${data.percentage}%)`,
            icon: `<svg>...</svg>`, // Progress icon
            type: 'primary',
            duration: Infinity
        };

        if (existing) {
            this.updateNotification(id, options);
        } else {
            this.show(options);
        }
    },

    handleBackupError(error) {
        this.show({
            title: 'Backup Error',
            message: error.message,
            icon: `<svg>...</svg>`, // Error icon
            type: 'error',
            duration: 10000
        });
    },

    handleBackupComplete(data) {
        this.show({
            title: 'Backup Complete',
            message: `Successfully backed up ${data.fileCount} files`,
            icon: `<svg>...</svg>`, // Success icon
            type: 'success'
        });
    },

    handleNetworkStatus(status) {
        if (status.quality < 30) {
            this.show({
                title: 'Poor Network Connection',
                message: 'Backup speed may be affected',
                icon: `<svg>...</svg>`, // Warning icon
                type: 'warning'
            });
        }
    },

    handleSystemWarning(warning) {
        this.show({
            title: warning.title,
            message: warning.message,
            icon: `<svg>...</svg>`, // Warning icon
            type: 'warning',
            duration: warning.duration || 7000
        });
    },

    updateNotification(id, options) {
        const notification = this.currentNotifications.get(id);
        if (!notification) return;

        const content = notification.querySelector('.notification-text');
        if (options.title) {
            content.querySelector('.notification-title').textContent = options.title;
        }
        if (options.message) {
            content.querySelector('.notification-message').textContent = options.message;
        }
    }
};

// Initialize the notification system
uiNotifications.init();

// Export for use in other modules
export default uiNotifications;
