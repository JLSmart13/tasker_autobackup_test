// voice_control.js
const voiceCommandHandler = {
    commands: {
        start: {
            triggers: ['start backup', 'begin backup', 'initiate backup'],
            action: 'startBackup',
            confirmationPhrase: 'Starting backup process'
        },
        pause: {
            triggers: ['pause backup', 'stop backup', 'halt backup'],
            action: 'pauseBackup',
            confirmationPhrase: 'Pausing backup process'
        },
        resume: {
            triggers: ['resume backup', 'continue backup'],
            action: 'resumeBackup',
            confirmationPhrase: 'Resuming backup process'
        },
        status: {
            triggers: ['backup status', 'check backup', 'backup progress'],
            action: 'checkStatus',
            confirmationPhrase: 'Checking backup status'
        }
    },

    handleCommand: function(voiceInput) {
        const command = this.parseCommand(voiceInput);
        if (command) {
            this.executeCommand(command);
            return true;
        }
        return false;
    },

    parseCommand: function(input) {
        input = input.toLowerCase().trim();
        for (const [key, cmd] of Object.entries(this.commands)) {
            if (cmd.triggers.some(trigger => input.includes(trigger))) {
                return {
                    type: key,
                    ...cmd
                };
            }
        }
        return null;
    },

    executeCommand: function(command) {
        // Speak confirmation if AutoVoice is available
        if (global('VOICE')) {
            say(command.confirmationPhrase);
        }

        // Execute the command
        switch (command.action) {
            case 'startBackup':
                performTask('StartBackup');
                break;
            case 'pauseBackup':
                performTask('PauseBackup');
                break;
            case 'resumeBackup':
                performTask('ResumeBackup');
                break;
            case 'checkStatus':
                performTask('CheckStatus');
                break;
        }

        // Update UI
        eventBus.emit('commandExecuted', {
            command: command.type,
            timestamp: new Date().toISOString()
        });
    }
};
