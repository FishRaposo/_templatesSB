/*
File: queue.tpl.js
Purpose: Background job processing with BullMQ
Generated for: {{PROJECT_NAME}}
*/

const { Queue, Worker, QueueScheduler } = require('bullmq');
const Redis = require('ioredis');

// Redis connection for all queues
const connection = new Redis({
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT || '6379', 10),
    maxRetriesPerRequest: null,
});

// Queue registry
const queues = {};
const workers = {};

function createQueue(name, options = {}) {
    if (queues[name]) {
        return queues[name];
    }

    const queue = new Queue(name, {
        connection,
        defaultJobOptions: {
            attempts: 3,
            backoff: {
                type: 'exponential',
                delay: 1000,
            },
            removeOnComplete: {
                age: 24 * 60 * 60, // 24 hours
                count: 1000,
            },
            removeOnFail: {
                age: 7 * 24 * 60 * 60, // 7 days
            },
            ...options.defaultJobOptions,
        },
        ...options,
    });

    queues[name] = queue;
    return queue;
}

function createWorker(queueName, processor, options = {}) {
    if (workers[queueName]) {
        return workers[queueName];
    }

    const worker = new Worker(
        queueName,
        async (job) => {
            console.log(`Processing job ${job.id} in queue ${queueName}`);
            try {
                const result = await processor(job.data, job);
                console.log(`Job ${job.id} completed`);
                return result;
            } catch (error) {
                console.error(`Job ${job.id} failed:`, error);
                throw error;
            }
        },
        {
            connection,
            concurrency: options.concurrency || 5,
            ...options,
        }
    );

    worker.on('completed', (job) => {
        console.log(`Job ${job.id} completed successfully`);
    });

    worker.on('failed', (job, error) => {
        console.error(`Job ${job?.id} failed:`, error.message);
    });

    workers[queueName] = worker;
    return worker;
}

// Pre-defined queues
const emailQueue = createQueue('email');
const processingQueue = createQueue('processing');

// Job handlers
const jobHandlers = {
    sendEmail: async (data) => {
        const { to, subject, body } = data;
        console.log(`Sending email to ${to}: ${subject}`);
        // Implement email sending
        return { status: 'sent', to };
    },

    processFile: async (data) => {
        const { filePath } = data;
        console.log(`Processing file: ${filePath}`);
        // Implement file processing
        return { status: 'processed', file: filePath };
    },
};

// Helper to add jobs
async function addJob(queueName, jobName, data, options = {}) {
    const queue = queues[queueName] || createQueue(queueName);
    return queue.add(jobName, data, options);
}

// Scheduled/recurring jobs
async function scheduleRecurringJobs() {
    // Daily cleanup at midnight
    await processingQueue.add(
        'cleanupExpiredTokens',
        {},
        {
            repeat: {
                pattern: '0 0 * * *', // Daily at midnight
            },
        }
    );

    // Daily digest at 8 AM
    await emailQueue.add(
        'sendDailyDigest',
        {},
        {
            repeat: {
                pattern: '0 8 * * *', // Daily at 8 AM
            },
        }
    );
}

// Initialize workers
function startWorkers() {
    createWorker('email', jobHandlers.sendEmail);
    createWorker('processing', jobHandlers.processFile);
    console.log('Workers started');
}

// Graceful shutdown
async function shutdown() {
    console.log('Shutting down workers...');
    await Promise.all(Object.values(workers).map((w) => w.close()));
    await Promise.all(Object.values(queues).map((q) => q.close()));
    await connection.quit();
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

module.exports = {
    createQueue,
    createWorker,
    addJob,
    emailQueue,
    processingQueue,
    startWorkers,
    scheduleRecurringJobs,
};

// Usage:
// const { addJob, startWorkers } = require('./queue');
// startWorkers();
// await addJob('email', 'sendEmail', { to: 'user@example.com', subject: 'Hello', body: 'World' });
