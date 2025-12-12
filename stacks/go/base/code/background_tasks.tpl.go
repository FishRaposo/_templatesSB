// File: background_tasks.tpl.go
// Purpose: Background job processing with Asynq
// Generated for: {{PROJECT_NAME}}

package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/hibiken/asynq"
)

// Task types
const (
	TaskSendEmail        = "email:send"
	TaskProcessFile      = "file:process"
	TaskCleanupSessions  = "sessions:cleanup"
	TaskSyncExternalData = "data:sync"
	TaskGenerateReport   = "report:generate"
)

// Redis connection options
func GetRedisOpts() asynq.RedisClientOpt {
	return asynq.RedisClientOpt{
		Addr: "localhost:6379",
		DB:   0,
	}
}

// Client for enqueuing tasks
type Client struct {
	client *asynq.Client
}

func NewClient() *Client {
	return &Client{
		client: asynq.NewClient(GetRedisOpts()),
	}
}

func (c *Client) Close() error {
	return c.client.Close()
}

// Email task payloads
type EmailPayload struct {
	To       string                 `json:"to"`
	Subject  string                 `json:"subject"`
	Body     string                 `json:"body"`
	Template string                 `json:"template,omitempty"`
	Data     map[string]interface{} `json:"data,omitempty"`
}

func (c *Client) EnqueueEmail(payload EmailPayload, opts ...asynq.Option) (*asynq.TaskInfo, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	task := asynq.NewTask(TaskSendEmail, data, opts...)
	return c.client.Enqueue(task)
}

// File processing task payloads
type FilePayload struct {
	FileID    string `json:"file_id"`
	UserID    uint   `json:"user_id"`
	Operation string `json:"operation"`
}

func (c *Client) EnqueueFileProcessing(payload FilePayload, opts ...asynq.Option) (*asynq.TaskInfo, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	task := asynq.NewTask(TaskProcessFile, data, opts...)
	return c.client.Enqueue(task)
}

// Report task payloads
type ReportPayload struct {
	ReportType string                 `json:"report_type"`
	Params     map[string]interface{} `json:"params"`
	UserID     uint                   `json:"user_id"`
}

func (c *Client) EnqueueReport(payload ReportPayload, opts ...asynq.Option) (*asynq.TaskInfo, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	task := asynq.NewTask(TaskGenerateReport, data, opts...)
	return c.client.Enqueue(task)
}

// Schedule recurring tasks
func (c *Client) ScheduleRecurringTasks(scheduler *asynq.Scheduler) error {
	// Cleanup sessions daily at 2 AM
	if _, err := scheduler.Register("0 2 * * *", asynq.NewTask(TaskCleanupSessions, nil)); err != nil {
		return fmt.Errorf("failed to register cleanup task: %w", err)
	}

	// Sync external data every hour
	syncPayload, _ := json.Marshal(map[string]string{"source": "external_api"})
	if _, err := scheduler.Register("0 * * * *", asynq.NewTask(TaskSyncExternalData, syncPayload)); err != nil {
		return fmt.Errorf("failed to register sync task: %w", err)
	}

	return nil
}

// Task handlers
type Handler struct {
	// Add dependencies here
}

func NewHandler() *Handler {
	return &Handler{}
}

func (h *Handler) HandleSendEmail(ctx context.Context, t *asynq.Task) error {
	var payload EmailPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	log.Printf("Sending email to %s: %s", payload.To, payload.Subject)
	// Implement email sending logic here

	return nil
}

func (h *Handler) HandleProcessFile(ctx context.Context, t *asynq.Task) error {
	var payload FilePayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	log.Printf("Processing file %s for user %d: %s", payload.FileID, payload.UserID, payload.Operation)
	// Implement file processing logic here

	return nil
}

func (h *Handler) HandleCleanupSessions(ctx context.Context, t *asynq.Task) error {
	log.Println("Cleaning up expired sessions")
	// Implement session cleanup logic here

	return nil
}

func (h *Handler) HandleSyncExternalData(ctx context.Context, t *asynq.Task) error {
	var payload map[string]string
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	log.Printf("Syncing data from %s", payload["source"])
	// Implement data sync logic here

	return nil
}

func (h *Handler) HandleGenerateReport(ctx context.Context, t *asynq.Task) error {
	var payload ReportPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	log.Printf("Generating %s report for user %d", payload.ReportType, payload.UserID)
	// Implement report generation logic here

	return nil
}

// Server for processing tasks
type Server struct {
	server    *asynq.Server
	handler   *Handler
	scheduler *asynq.Scheduler
}

func NewServer() *Server {
	srv := asynq.NewServer(
		GetRedisOpts(),
		asynq.Config{
			Concurrency: 10,
			Queues: map[string]int{
				"critical": 6,
				"default":  3,
				"low":      1,
			},
			RetryDelayFunc: func(n int, e error, t *asynq.Task) time.Duration {
				return time.Duration(n) * time.Minute
			},
		},
	)

	scheduler := asynq.NewScheduler(GetRedisOpts(), nil)

	return &Server{
		server:    srv,
		handler:   NewHandler(),
		scheduler: scheduler,
	}
}

func (s *Server) Run() error {
	mux := asynq.NewServeMux()

	// Register handlers
	mux.HandleFunc(TaskSendEmail, s.handler.HandleSendEmail)
	mux.HandleFunc(TaskProcessFile, s.handler.HandleProcessFile)
	mux.HandleFunc(TaskCleanupSessions, s.handler.HandleCleanupSessions)
	mux.HandleFunc(TaskSyncExternalData, s.handler.HandleSyncExternalData)
	mux.HandleFunc(TaskGenerateReport, s.handler.HandleGenerateReport)

	// Start scheduler in a goroutine
	go func() {
		if err := s.scheduler.Run(); err != nil {
			log.Printf("Scheduler error: %v", err)
		}
	}()

	return s.server.Run(mux)
}

func (s *Server) Shutdown() {
	s.server.Shutdown()
	s.scheduler.Shutdown()
}

// Middleware for logging
func LoggingMiddleware(h asynq.Handler) asynq.Handler {
	return asynq.HandlerFunc(func(ctx context.Context, t *asynq.Task) error {
		start := time.Now()
		log.Printf("Starting task %s", t.Type())
		err := h.ProcessTask(ctx, t)
		if err != nil {
			log.Printf("Task %s failed after %v: %v", t.Type(), time.Since(start), err)
			return err
		}
		log.Printf("Task %s completed in %v", t.Type(), time.Since(start))
		return nil
	})
}

// Usage:
// // Client side
// client := NewClient()
// defer client.Close()
// info, err := client.EnqueueEmail(EmailPayload{
//     To:      "user@example.com",
//     Subject: "Hello",
//     Body:    "World",
// })
//
// // Server side
// server := NewServer()
// if err := server.Run(); err != nil {
//     log.Fatal(err)
// }
