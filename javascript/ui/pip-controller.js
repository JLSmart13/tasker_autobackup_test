// javascript/ui/pip_controller.js
const pipController = {
    state: {
        visible: false,
        minimized: false,
        position: { x: 20, y: 20 },
        size: { width: 300, height: 400 },
        data: {
            currentFile: null,
            progress: 0,
            speed: 0,
            remaining: 0
        }
    },

    init: function() {
        this.setupEventListeners();
        this.createPIPWindow();
    },

    setupEventListeners: function() {
        eventBus.on('backupProgress', this.updateProgress.bind(this));
        eventBus.on('backupError', this.showError.bind(this));
        eventBus.on('backupComplete', this.handleComplete.bind(this));
        
        // Window events
        window.addEventListener('resize', this.handleResize.bind(this));
    },

    createPIPWindow: function() {
        const scene = new Scene('pip_monitor');
        scene.show({
            x: this.state.position.x,
            y: this.state.position.y,
            width: this.state.size.width,
            height: this.state.size.height,
            flags: Scene.FLAG_STAY_ON_TOP | Scene.FLAG_NOT_FOCUSABLE
        });

        this.state.visible = true;
    },

    updateProgress: function(data) {
        this.state.data = {
            currentFile: data.file,
            progress: data.progress,
            speed: data.speed,
            remaining: data.remaining
        };

        this.updateUI();
    },

    showError: function(error) {
        // Show error in PIP
        Scene.findElement('error_text').setText(error.message);
        Scene.findElement('error_container').setVisibility(View.VISIBLE);
    },

    handleComplete: function() {
        // Show completion state
        Scene.findElement('complete_animation').start();
        setTimeout(() => this.hide(), 3000);
    },

    updateUI: function() {
        if (!this.state.visible) return;

        // Update progress elements
        Scene.findElement('current_file').setText(this.state.data.currentFile);
        Scene.findElement('progress_bar').setProgress(this.state.data.progress);
        Scene.findElement('speed_text').setText(`${this.state.data.speed} MB/s`);
        Scene.findElement('remaining_text').setText(this.formatTime(this.state.data.remaining));
    },

    show: function() {
        if (this.state.visible) return;
        
        Scene.show();
        this.state.visible = true;
    },

    hide: function() {
        if (!this.state.visible) return;
        
        Scene.hide();
        this.state.visible = false;
    },

    minimize: function() {
        if (this.state.minimized) return;
        
        this.state.minimized = true;
        Scene.animate()
            .scaleX(0.5)
            .scaleY(0.5)
            .setDuration(300)
            .start();
    },

    maximize: function() {
        if (!this.state.minimized) return;
        
        this.state.minimized = false;
        Scene.animate()
            .scaleX(1)
            .scaleY(1)
            .setDuration(300)
            .start();
    },

    move: function(x, y) {
        this.state.position = { x, y };
        Scene.setPosition(x, y);
    },

    resize: function(width, height) {
        this.state.size = { width, height };
        Scene.setSize(width, height);
    },

    handleResize: function() {
        const screenWidth = window.innerWidth;
        const screenHeight = window.innerHeight;
        
        // Keep PIP within screen bounds
        if (this.state.position.x + this.state.size.width > screenWidth) {
            this.move(screenWidth - this.state.size.width, this.state.position.y);
        }
        
        if (this.state.position.y + this.state.size.height > screenHeight) {
            this.move(this.state.position.x, screenHeight - this.state.size.height);
        }
    },

    formatTime: function(seconds) {
        if (seconds < 60) return `${Math.round(seconds)}s`;
        if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
        return `${Math.round(seconds / 3600)}h ${Math.round((seconds % 3600) / 60)}m`;
    }
};

// Initialize PIP controller
pipController.init();

// Export for use in other modules
export default pipController;
