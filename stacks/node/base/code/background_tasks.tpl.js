/*
File: background_tasks.tpl.js
Purpose: Background job processing with BullMQ
Generated for: {{PROJECT_NAME}}
*/

const { Queue, Worker, QueueScheduler, QueueEvents } = require('bullmq');
const Redis = require('ioredis');

// Redis connection
const connection = new Redis(process.env.REDIS_URL || 'redis://localhost:6379', {
    maxRetriesPerRequest: null,
});

// Queue configuration
const defaultJobOptions = {
    attempts: 3,
    backoff: {
        type: 'exponential',
        delay: 1000,
    },
    removeOnComplete: {
        count: 1000,
        age: 24 * 3600, // 24 hours
    },
    removeOnFail: {
        count: 5000,
        age: 7 * 24 * 3600, // 7 days
    },
};

// Create queues
const emailQueue = new Queue('email', { connection, defaultJobOptions });
const processingQueue = new Queue('processing', { connection, defaultJobOptions });
const scheduledQueue = new Queue('scheduled', { connection, defaultJobOptions });

// Queue schedulers (required for delayed jobs)
const emailScheduler = new QueueScheduler('email', { connection });
const processingScheduler = new QueueScheduler('processing', { connection });

// Queue events for monitoring
const emailEvents = new QueueEvents('email', { connection });
emailEvents.on('completed', ({ jobId, returnvalue }) => {
    console.log(`Email job ${jobId} completed:`, returnvalue);
});
emailEvents.on('failed', ({ jobId, failedReason }) => {
    console.error(`Email job ${jobId} failed:`, failedReason);
});

// Job processors
const emailProcessor = async (job) => {
    const { to, subject, body, template, data } = job.data;
    console.log(`Sending email to ${to}: ${subject}`);

    // Update progress
    await job.updateProgress(10);

    // Implement email sending logic here
    // const result = await sendEmail({ to, subject, body, template, data });

    await job.updateProgress(100);
    return { status: 'sent', to, subject };
};

const processingProcessor = async (job) => {
    const { fileId, userId, operation } = job.data;
    console.log(`Processing file ${fileId} for user ${userId}: ${operation}`);

    // Simulate processing with progress updates
    for (let i = 0; i <= 100; i += 10) {
        await job.updateProgress(i);
        await new Promise((resolve) => setTimeout(resolve, 100));
    }

    return { status: 'processed', fileId, operation };
};

// Workers
const emailWorker = new Worker('email', emailProcessor, {
    connection,
    concurrency: 5,
});

const processingWorker = new Worker('processing', processingProcessor, {
    connection,
    concurrency: 2,
});

// Worker event handlers
emailWorker.on('completed', (job) => {
    console.log(`Email job ${job.id} completed`);
});

emailWorker.on('failed', (job, err) => {
    console.error(`Email job ${job?.id} failed:`, err.message);
});

processingWorker.on('completed', (job) => {
    console.log(`Processing job ${job.id} completed`);
});

processingWorker.on('failed', (job, err) => {
    console.error(`Processing job ${job?.id} failed:`, err.message);
});

// Job creation helpers
const jobs = {
    // Send email
    async sendEmail(to, subject, body, options = {}) {
        return emailQueue.add('send-email', { to, subject, body }, options);
    },

    // Send templated email
    async sendTemplatedEmail(to, template, data, options = {}) {
        return emailQueue.add('send-templated-email', { to, template, data }, options);
    },

    // Schedule email
    async scheduleEmail(to, subject, body, sendAt) {
        const delay = new Date(sendAt).getTime() - Date.now();
        return emailQueue.add('send-email', { to, subject, body }, { delay });
    },

    // Process file
    async processFile(fileId, userId, operation = 'default') {
        return processingQueue.add('process-file', { fileId, userId, operation });
    },

    // Batch process files
    async processFiles(files, userId) {
        const jobs = files.map((fileId) => ({
            name: 'process-file',
            data: { fileId, userId, operation: 'batch' },
        }));
        return processingQueue.addBulk(jobs);
    },

    // Get job status
    async getJobStatus(queueName, jobId) {
        const queue = { email: emailQueue, processing: processingQueue }[queueName];
        if (!queue) throw new Error(`Unknown queue: ${queueName}`);

        const job = await queue.getJob(jobId);
        if (!job) return null;

        const state = await job.getState();
        const progress = job.progress;

        return {
            id: job.id,
            name: job.name,
            state,
            progress,
            data: job.data,
            result: job.returnvalue,
            failedReason: job.failedReason,
            timestamp: job.timestamp,
            processedOn: job.processedOn,
            finishedOn: job.finishedOn,
        };
    },

    // Cancel job
    async cancelJob(queueName, jobId) {
        const queue = { email: emailQueue, processing: processingQueue }[queueName];
        const job = await queue.getJob(jobId);
        if (job) {
            await job.remove();
            return true;
        }
        return false;
    },

    // Retry failed job
    async retryJob(queueName, jobId) {
        const queue = { email: emailQueue, processing: processingQueue }[queueName];
        const job = await queue.getJob(jobId);
        if (job) {
            await job.retry();
            return true;
        }
        return false;
    },
};

// Scheduled/recurring jobs
async function setupScheduledJobs() {
    // Clean up expired sessions every day at 2 AM
    await scheduledQueue.add(
        'cleanup-sessions',
        {},
        {
            repeat: { cron: '0 2 * * *' },
            jobId: 'cleanup-sessions',
        }
    );

    // Sync external data every hour
    await scheduledQueue.add(
        'sync-external-data',
        { source: 'external_api' },
        {
            repeat: { cron: '0 * * * *' },
            jobId: 'sync-external-data',
        }
    );

    // Send weekly digest every Monday at 9 AM
    await scheduledQueue.add(
        'send-weekly-digest',
        {},
        {
            repeat: { cron: '0 9 * * 1' },
            jobId: 'weekly-digest',
        }
    );
}

// Graceful shutdown
async function shutdown() {
    console.log('Shutting down workers...');
    await emailWorker.close();
    await processingWorker.close();
    await emailScheduler.close();
    await processingScheduler.close();
    await connection.quit();
    console.log('Workers shut down');
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

module.exports = {
    queues: { emailQueue, processingQueue, scheduledQueue },
    workers: { emailWorker, processingWorker },
    jobs,
    setupScheduledJobs,
    shutdown,
};
