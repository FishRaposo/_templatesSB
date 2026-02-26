<!--
File: CONCURRENCY-PATTERNS.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# Go Concurrency Patterns

## Purpose
Comprehensive guide to Go concurrency patterns, including goroutines, channels, select statements, and advanced synchronization techniques.

## Core Concurrency Patterns

### 1. Basic Goroutine Patterns
```go
package main

import (
	"fmt"
	"sync"
	"time"
)

// Simple goroutine for background processing
func processData(data int, wg *sync.WaitGroup) {
	defer wg.Done()
	
	// Simulate processing time
	time.Sleep(time.Second * 2)
	
	fmt.Printf("Processed data: %d\n", data)
}

// Worker pool pattern
func worker(id int, jobs <-chan int, results chan<- int, wg *sync.WaitGroup) {
	defer wg.Done()
	
	for job := range jobs {
		fmt.Printf("Worker %d processing job %d\n", id, job)
		time.Sleep(time.Second) // Simulate work
		results <- job * 2 // Return processed result
	}
}

func main() {
	// Basic goroutine usage
	var wg sync.WaitGroup
	
	data := []int{1, 2, 3, 4, 5}
	
	for _, d := range data {
		wg.Add(1)
		go processData(d, &wg)
	}
	
	wg.Wait()
	fmt.Println("All data processed")
	
	// Worker pool implementation
	jobs := make(chan int, 100)
	results := make(chan int, 100)
	
	// Start workers
	numWorkers := 3
	for w := 1; w <= numWorkers; w++ {
		wg.Add(1)
		go worker(w, jobs, results, &wg)
	}
	
	// Send jobs
	for j := 1; j <= 5; j++ {
		jobs <- j
	}
	close(jobs)
	
	// Wait for workers to finish
	wg.Wait()
	close(results)
	
	// Collect results
	for result := range results {
		fmt.Printf("Result: %d\n", result)
	}
}
```

### 2. Channel Patterns
```go
package main

import (
	"fmt"
	"time"
)

// Fan-out pattern: distribute work to multiple goroutines
func fanOut(input <-chan int, workers int) []chan int {
	outputs := make([]chan int, workers)
	
	for i := 0; i < workers; i++ {
		outputs[i] = make(chan int)
		
		go func(ch chan<- int) {
			for val := range input {
				ch <- val * val // Process value
			}
			close(ch)
		}(outputs[i])
	}
	
	return outputs
}

// Fan-in pattern: collect results from multiple channels
func fanIn(inputs ...<-chan int) <-chan int {
	output := make(chan int)
	
	var wg sync.WaitGroup
	
	for _, input := range inputs {
		wg.Add(1)
		
		go func(ch <-chan int) {
			defer wg.Done()
			
			for val := range ch {
				output <- val
			}
		}(input)
	}
	
	go func() {
		wg.Wait()
		close(output)
	}()
	
	return output
}

// Buffered channel for rate limiting
func rateLimit(requests <-chan int, rate time.Duration) <-chan int {
	output := make(chan int)
	
	go func() {
		ticker := time.NewTicker(rate)
		defer ticker.Stop()
		
		for req := range requests {
			<-ticker.C // Wait for tick
			output <- req
		}
		close(output)
	}()
	
	return output
}

// Timeout pattern with channels
func withTimeout(operation func() (int, error), timeout time.Duration) (int, error) {
	result := make(chan int)
	errChan := make(chan error)
	
	go func() {
		res, err := operation()
		if err != nil {
			errChan <- err
			return
		}
		result <- res
	}()
	
	select {
	case res := <-result:
		return res, nil
	case err := <-errChan:
		return 0, err
	case <-time.After(timeout):
		return 0, fmt.Errorf("operation timed out")
	}
}

// Pipeline pattern
func generator(nums ...int) <-chan int {
	out := make(chan int)
	
	go func() {
		defer close(out)
		
		for _, n := range nums {
			out <- n
		}
	}()
	
	return out
}

func square(in <-chan int) <-chan int {
	out := make(chan int)
	
	go func() {
		defer close(out)
		
		for n := range in {
			out <- n * n
		}
	}()
	
	return out
}

func main() {
	// Fan-out/Fan-in example
	input := make(chan int)
	
	// Send data
	go func() {
		defer close(input)
		for i := 1; i <= 10; i++ {
			input <- i
		}
	}()
	
	// Fan-out to 3 workers
	workerOutputs := fanOut(input, 3)
	
	// Fan-in results
	finalOutput := fanIn(workerOutputs...)
	
	// Print results
	for result := range finalOutput {
		fmt.Printf("Final result: %d\n", result)
	}
	
	// Pipeline example
	numbers := generator(1, 2, 3, 4, 5)
	squares := square(numbers)
	
	for sq := range squares {
		fmt.Printf("Square: %d\n", sq)
	}
}
```

### 3. Select Statement Patterns
```go
package main

import (
	"fmt"
	"math/rand"
	"time"
)

// Multiplexing with select
func multiplex(ch1, ch2 <-chan string) <-chan string {
	output := make(chan string)
	
	go func() {
		defer close(output)
		
		for {
			select {
			case msg1 := <-ch1:
				output <- fmt.Sprintf("Channel 1: %s", msg1)
			case msg2 := <-ch2:
				output <- fmt.Sprintf("Channel 2: %s", msg2)
			}
		}
	}()
	
	return output
}

// Select with timeout
func selectWithTimeout(ch <-chan string, timeout time.Duration) (string, error) {
	select {
	case msg := <-ch:
		return msg, nil
	case <-time.After(timeout):
		return "", fmt.Errorf("timeout waiting for message")
	}
}

// Select with default (non-blocking)
func nonBlockingSelect(ch <-chan int) {
	select {
	case val := <-ch:
		fmt.Printf("Received: %d\n", val)
	default:
		fmt.Println("No message available")
	}
}

// Select with multiple operations
func complexSelect() {
	ch1 := make(chan string)
	ch2 := make(chan string)
	quit := make(chan bool)
	
	// Producer goroutines
	go func() {
		for i := 0; i < 5; i++ {
			ch1 <- fmt.Sprintf("Message 1-%d", i)
			time.Sleep(time.Millisecond * 100)
		}
	}()
	
	go func() {
		for i := 0; i < 5; i++ {
			ch2 <- fmt.Sprintf("Message 2-%d", i)
			time.Sleep(time.Millisecond * 150)
		}
	}()
	
	// Consumer with select
	for {
		select {
		case msg1 := <-ch1:
			fmt.Printf("Received from ch1: %s\n", msg1)
		case msg2 := <-ch2:
			fmt.Printf("Received from ch2: %s\n", msg2)
		case <-quit:
			fmt.Println("Quitting...")
			return
		case <-time.After(time.Second * 2):
			fmt.Println("Timeout, quitting...")
			return
		}
	}
}

// Random select with weighted probability
func weightedSelect() {
	ch1 := make(chan string, 1)
	ch2 := make(chan string, 1)
	
	// Send messages
	ch1 <- "Message from channel 1"
	ch2 <- "Message from channel 2"
	
	// Weighted selection
	for i := 0; i < 10; i++ {
		select {
		case msg := <-ch1:
			fmt.Printf("Selected ch1: %s\n", msg)
		case msg := <-ch2:
			fmt.Printf("Selected ch2: %s\n", msg)
		default:
			fmt.Println("No channel ready")
		}
		
		// Random delay to simulate different readiness
		time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)
	}
}

func main() {
	// Test select patterns
	complexSelect()
	weightedSelect()
}
```

## Advanced Concurrency Patterns

### 1. Context-Based Cancellation
```go
package main

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Context-based worker
func contextWorker(ctx context.Context, id int, jobs <-chan int, results chan<- int) {
	for {
		select {
		case <-ctx.Done():
			fmt.Printf("Worker %d shutting down\n", id)
			return
		case job, ok := <-jobs:
			if !ok {
				fmt.Printf("Worker %d: jobs channel closed\n", id)
				return
			}
			
			// Simulate work with context awareness
			select {
			case <-ctx.Done():
				fmt.Printf("Worker %d cancelled during job %d\n", id, job)
				return
			case results <- job * 2:
				fmt.Printf("Worker %d completed job %d\n", id, job)
			}
		}
	}
}

// Context with timeout
func contextWithTimeout(ctx context.Context, duration time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, duration)
}

// Context with deadline
func contextWithDeadline(ctx context.Context, deadline time.Time) (context.Context, context.CancelFunc) {
	return context.WithDeadline(ctx, deadline)
}

// Context with values
func contextWithValue(ctx context.Context, key, value string) context.Context {
	return context.WithValue(ctx, key, value)
}

// Context-aware HTTP client
func contextAwareHTTPClient(ctx context.Context, url string) (string, error) {
	// Create HTTP request with context
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	
	// Make request with context cancellation
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	
	return string(body), nil
}

func main() {
	// Context cancellation example
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Create channels
	jobs := make(chan int, 100)
	results := make(chan int, 100)
	
	// Start workers
	numWorkers := 3
	var wg sync.WaitGroup
	
	for w := 1; w <= numWorkers; w++ {
		wg.Add(1)
		go contextWorker(ctx, w, jobs, results)
	}
	
	// Send jobs
	go func() {
		defer close(jobs)
		for j := 1; j <= 10; j++ {
			jobs <- j
		}
	}()
	
	// Collect results
	go func() {
		wg.Wait()
		close(results)
	}()
	
	// Cancel after 3 seconds
	go func() {
		time.Sleep(time.Second * 3)
		cancel()
	}()
	
	// Print results
	for result := range results {
		fmt.Printf("Result: %d\n", result)
	}
	
	// Context with timeout example
	timeoutCtx, timeoutCancel := context.WithTimeout(context.Background(), time.Second*2)
	defer timeoutCancel()
	
	_, err := contextAwareHTTPClient(timeoutCtx, "https://httpbin.org/delay/5")
	if err != nil {
		fmt.Printf("HTTP request failed: %v\n", err)
	}
}
```

### 2. Sync Package Patterns
```go
package main

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Atomic operations for counters
type AtomicCounter struct {
	value int64
}

func (c *AtomicCounter) Increment() {
	atomic.AddInt64(&c.value, 1)
}

func (c *AtomicCounter) Decrement() {
	atomic.AddInt64(&c.value, -1)
}

func (c *AtomicCounter) Get() int64 {
	return atomic.LoadInt64(&c.value)
}

// Mutex for complex operations
type SafeMap struct {
	mu   sync.RWMutex
	data map[string]int
}

func NewSafeMap() *SafeMap {
	return &SafeMap{
		data: make(map[string]int),
	}
}

func (sm *SafeMap) Set(key string, value int) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.data[key] = value
}

func (sm *SafeMap) Get(key string) (int, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	value, exists := sm.data[key]
	return value, exists
}

func (sm *SafeMap) Delete(key string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.data, key)
}

// Once pattern for initialization
type Singleton struct {
	data string
}

var (
	instance *Singleton
	once     sync.Once
)

func GetInstance() *Singleton {
	once.Do(func() {
		instance = &Singleton{data: "singleton data"}
	})
	return instance
}

// Pool pattern for object reuse
type ObjectPool struct {
	pool sync.Pool
}

func NewObjectPool() *ObjectPool {
	return &ObjectPool{
		pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 1024)
			},
		},
	}
}

func (op *ObjectPool) Get() []byte {
	return op.pool.Get().([]byte)
}

func (op *ObjectPool) Put(buf []byte) {
	op.pool.Put(buf[:0]) // Reset length but keep capacity
}

// WaitGroup for goroutine coordination
func waitGroupExample() {
	var wg sync.WaitGroup
	numWorkers := 5
	
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		
		go func(workerID int) {
			defer wg.Done()
			
			fmt.Printf("Worker %d starting\n", workerID)
			time.Sleep(time.Second)
			fmt.Printf("Worker %d finished\n", workerID)
		}(i)
	}
	
	wg.Wait()
	fmt.Println("All workers finished")
}

// Condition variable for complex synchronization
type BoundedBuffer struct {
	mu     sync.Mutex
	cond   *sync.Cond
	buffer []int
	size   int
}

func NewBoundedBuffer(size int) *BoundedBuffer {
	b := &BoundedBuffer{
		buffer: make([]int, 0, size),
		size:   size,
	}
	b.cond = sync.NewCond(&b.mu)
	return b
}

func (bb *BoundedBuffer) Put(item int) {
	bb.mu.Lock()
	defer bb.mu.Unlock()
	
	for len(bb.buffer) == bb.size {
		bb.cond.Wait()
	}
	
	bb.buffer = append(bb.buffer, item)
	bb.cond.Signal()
}

func (bb *BoundedBuffer) Get() int {
	bb.mu.Lock()
	defer bb.mu.Unlock()
	
	for len(bb.buffer) == 0 {
		bb.cond.Wait()
	}
	
	item := bb.buffer[0]
	bb.buffer = bb.buffer[1:]
	bb.cond.Signal()
	
	return item
}

func main() {
	// Atomic counter example
	counter := &AtomicCounter{}
	
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			counter.Increment()
		}()
	}
	
	wg.Wait()
	fmt.Printf("Final counter value: %d\n", counter.Get())
	
	// Safe map example
	safeMap := NewSafeMap()
	
	var mapWg sync.WaitGroup
	for i := 0; i < 10; i++ {
		mapWg.Add(1)
		go func(id int) {
			defer mapWg.Done()
			safeMap.Set(fmt.Sprintf("key%d", id), id*10)
		}(i)
	}
	
	mapWg.Wait()
	
	for i := 0; i < 10; i++ {
		if value, exists := safeMap.Get(fmt.Sprintf("key%d", i)); exists {
			fmt.Printf("Key %d: %d\n", i, value)
		}
	}
	
	// Bounded buffer example
	buffer := NewBoundedBuffer(3)
	
	// Producer
	go func() {
		for i := 0; i < 10; i++ {
			fmt.Printf("Producing: %d\n", i)
			buffer.Put(i)
			time.Sleep(time.Millisecond * 100)
		}
	}()
	
	// Consumer
	go func() {
		for i := 0; i < 10; i++ {
			item := buffer.Get()
			fmt.Printf("Consumed: %d\n", item)
		}
	}()
	
	time.Sleep(time.Second * 2)
}
```

### 3. Error Handling in Concurrent Code
```go
package main

import (
	"errors"
	"fmt"
	"sync"
)

// Error group pattern
type ErrorGroup struct {
	wg     sync.WaitGroup
	errors []error
	mu     sync.Mutex
}

func NewErrorGroup() *ErrorGroup {
	return &ErrorGroup{}
}

func (eg *ErrorGroup) Go(f func() error) {
	eg.wg.Add(1)
	
	go func() {
		defer eg.wg.Done()
		
		if err := f(); err != nil {
			eg.mu.Lock()
			eg.errors = append(eg.errors, err)
			eg.mu.Unlock()
		}
	}()
}

func (eg *ErrorGroup) Wait() []error {
	eg.wg.Wait()
	
	eg.mu.Lock()
	defer eg.mu.Unlock()
	
	return eg.errors
}

// Error channel pattern
func workerWithErrorChan(id int, jobs <-chan int, errChan chan<- error) {
	for job := range jobs {
		if job < 0 {
			errChan <- fmt.Errorf("worker %d: invalid job %d", id, job)
			continue
		}
		
		// Process job
		fmt.Printf("Worker %d processed job %d\n", id, job)
	}
}

// Error collection pattern
type ErrorCollector struct {
	errors chan error
	done   chan struct{}
}

func NewErrorCollector() *ErrorCollector {
	ec := &ErrorCollector{
		errors: make(chan error, 100),
		done:   make(chan struct{}),
	}
	
	// Start error collector goroutine
	go ec.collectErrors()
	
	return ec
}

func (ec *ErrorCollector) collectErrors() {
	var errors []error
	
	for {
		select {
		case err := <-ec.errors:
			errors = append(errors, err)
		case <-ec.done:
			// Print all collected errors
			for _, err := range errors {
				fmt.Printf("Collected error: %v\n", err)
			}
			return
		}
	}
}

func (ec *ErrorCollector) AddError(err error) {
	ec.errors <- err
}

func (ec *ErrorCollector) Close() {
	close(ec.done)
}

// Safe concurrent error handling
type SafeWorker struct {
	id     int
	errChan chan<- error
}

func (sw *SafeWorker) Process(data int) error {
	if data < 0 {
		return fmt.Errorf("worker %d: negative data %d", sw.id, data)
	}
	
	if data > 100 {
		return fmt.Errorf("worker %d: data too large %d", sw.id, data)
	}
	
	// Simulate processing
	fmt.Printf("Worker %d processed data %d\n", sw.id, data)
	return nil
}

func (sw *SafeWorker) SafeProcess(data int) {
	if err := sw.Process(data); err != nil {
		sw.errChan <- err
	}
}

func main() {
	// Error group example
	eg := NewErrorGroup()
	
	for i := 0; i < 5; i++ {
		workerID := i
		eg.Go(func() error {
			if workerID == 2 {
				return fmt.Errorf("worker %d failed", workerID)
			}
			fmt.Printf("Worker %d completed successfully\n", workerID)
			return nil
		})
	}
	
	errors := eg.Wait()
	if len(errors) > 0 {
		fmt.Printf("Errors occurred: %v\n", errors)
	}
	
	// Error channel example
	jobs := make(chan int, 10)
	errChan := make(chan error, 10)
	
	// Start workers
	for w := 1; w <= 3; w++ {
		go workerWithErrorChan(w, jobs, errChan)
	}
	
	// Send jobs
	go func() {
		defer close(jobs)
		for i := -2; i < 8; i++ {
			jobs <- i
		}
	}()
	
	// Collect errors
	go func() {
		for err := range errChan {
			fmt.Printf("Error: %v\n", err)
		}
	}()
	
	time.Sleep(time.Second)
	close(errChan)
	
	// Error collector example
	ec := NewErrorCollector()
	
	// Simulate errors from multiple goroutines
	for i := 0; i < 5; i++ {
		go func(id int) {
			if id%2 == 0 {
				ec.AddError(fmt.Errorf("error from goroutine %d", id))
			}
		}(i)
	}
	
	time.Sleep(time.Second)
	ec.Close()
}
```

## Real-World Concurrency Patterns

### 1. Web Server with Connection Pool
```go
package main

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Connection pool pattern
type ConnectionPool struct {
	mu         sync.Mutex
	connections chan *http.Client
	factory    func() *http.Client
	maxSize    int
}

func NewConnectionPool(maxSize int, factory func() *http.Client) *ConnectionPool {
	pool := &ConnectionPool{
		connections: make(chan *http.Client, maxSize),
		factory:    factory,
		maxSize:    maxSize,
	}
	
	// Pre-populate pool
	for i := 0; i < maxSize; i++ {
		pool.connections <- factory()
	}
	
	return pool
}

func (cp *ConnectionPool) Get() *http.Client {
	select {
	case conn := <-cp.connections:
		return conn
	default:
		// Pool empty, create new connection
		return cp.factory()
	}
}

func (cp *ConnectionPool) Put(conn *http.Client) {
	select {
	case cp.connections <- conn:
		// Connection returned to pool
	default:
		// Pool full, discard connection
	}
}

// Concurrent HTTP handler
func (cp *ConnectionPool) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second*5)
	defer cancel()
	
	client := cp.Get()
	defer cp.Put(client)
	
	req, err := http.NewRequestWithContext(ctx, "GET", "https://httpbin.org/delay/1", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	fmt.Fprintf(w, "Request completed with status: %s", resp.Status)
}

// Rate limiting middleware
type RateLimiter struct {
	ticker *time.Ticker
}

func NewRateLimiter(rate time.Duration) *RateLimiter {
	return &RateLimiter{
		ticker: time.NewTicker(rate),
	}
}

func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-rl.ticker.C // Wait for tick
		next.ServeHTTP(w, r)
	})
}

func main() {
	// Create connection pool
	pool := NewConnectionPool(10, func() *http.Client {
		return &http.Client{
			Timeout: time.Second * 10,
		}
	})
	
	// Create rate limiter
	rateLimiter := NewRateLimiter(time.Millisecond * 100)
	
	// Setup server with middleware
	mux := http.NewServeMux()
	mux.Handle("/", pool)
	
	handler := rateLimiter.Middleware(mux)
	
	fmt.Println("Server starting on :8080")
	http.ListenAndServe(":8080", handler)
}
```

### 2. Pipeline for Data Processing
```go
package main

import (
	"fmt"
	"sync"
	"time"
)

// Pipeline stage interface
type Stage interface {
	Process(in <-chan interface{}) <-chan interface{}
}

// Map stage
type MapStage struct {
	mapper func(interface{}) interface{}
}

func NewMapStage(mapper func(interface{}) interface{}) *MapStage {
	return &MapStage{mapper: mapper}
}

func (ms *MapStage) Process(in <-chan interface{}) <-chan interface{} {
	out := make(chan interface{})
	
	go func() {
		defer close(out)
		
		for item := range in {
			out <- ms.mapper(item)
		}
	}()
	
	return out
}

// Filter stage
type FilterStage struct {
	filter func(interface{}) bool
}

func NewFilterStage(filter func(interface{}) bool) *FilterStage {
	return &FilterStage{filter}
}

func (fs *FilterStage) Process(in <-chan interface{}) <-chan interface{} {
	out := make(chan interface{})
	
	go func() {
		defer close(out)
		
		for item := range in {
			if fs.filter(item) {
				out <- item
			}
		}
	}()
	
	return out
}

// Reduce stage
type ReduceStage struct {
	reducer func(acc, item interface{}) interface{}
	initial interface{}
}

func NewReduceStage(reducer func(acc, item interface{}) interface{}, initial interface{}) *ReduceStage {
	return &ReduceStage{reducer: reducer, initial: initial}
}

func (rs *ReduceStage) Process(in <-chan interface{}) <-chan interface{} {
	out := make(chan interface{})
	
	go func() {
		defer close(out)
		
		acc := rs.initial
		for item := range in {
			acc = rs.reducer(acc, item)
		}
		out <- acc
	}()
	
	return out
}

// Pipeline
type Pipeline struct {
	stages []Stage
}

func NewPipeline(stages ...Stage) *Pipeline {
	return &Pipeline{stages: stages}
}

func (p *Pipeline) Execute(input <-chan interface{}) <-chan interface{} {
	current := input
	
	for _, stage := range p.stages {
		current = stage.Process(current)
	}
	
	return current
}

// Example usage
func main() {
	// Create input channel
	input := make(chan interface{})
	
	// Send data
	go func() {
		defer close(input)
		
		numbers := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
		for _, num := range numbers {
			input <- num
		}
	}()
	
	// Create pipeline
	pipeline := NewPipeline(
		NewMapStage(func(item interface{}) interface{} {
			num := item.(int)
			return num * num
		}),
		NewFilterStage(func(item interface{}) bool {
			num := item.(int)
			return num%2 == 0 // Keep even numbers
		}),
		NewReduceStage(func(acc, item interface{}) interface{} {
			sum := acc.(int)
			num := item.(int)
			return sum + num
		}, 0),
	)
	
	// Execute pipeline
	result := pipeline.Execute(input)
	
	// Get final result
	finalResult := <-result
	fmt.Printf("Final result: %v\n", finalResult)
}
```

## Best Practices

### 1. Concurrency Guidelines
```go
// ✅ GOOD: Use buffered channels for known workloads
func goodWorkerPool() {
	jobs := make(chan int, 100) // Buffered channel
	results := make(chan int, 100)
	
	// Start workers
	for w := 1; w <= 3; w++ {
		go worker(w, jobs, results)
	}
	
	// Send jobs
	for j := 1; j <= 10; j++ {
		jobs <- j
	}
	close(jobs)
	
	// Collect results
	for a := 1; a <= 10; a++ {
		<-results
	}
}

// ❌ BAD: Use unbuffered channels for high-throughput scenarios
func badWorkerPool() {
	jobs := make(chan int) // Unbuffered channel - can cause deadlock
	results := make(chan int)
	
	// This can deadlock if workers aren't ready
	for j := 1; j <= 10; j++ {
		jobs <- j // Will block if no worker is ready
	}
}

// ✅ GOOD: Use context for cancellation
func goodContextWorker(ctx context.Context, jobs <-chan int) {
	for {
		select {
		case <-ctx.Done():
			return
		case job, ok := <-jobs:
			if !ok {
				return
			}
			// Process job
			processJob(job)
		}
	}
}

// ❌ BAD: Ignore cancellation signals
func badWorker(jobs <-chan int) {
	for job := range jobs {
		// This will run even if context is cancelled
		processJob(job)
	}
}

// ✅ GOOD: Proper error handling in goroutines
func goodWorkerWithErrorHandling(jobs <-chan int, errChan chan<- error) {
	for job := range jobs {
		if err := processJob(job); err != nil {
			errChan <- fmt.Errorf("job %d failed: %w", job, err)
			continue
		}
	}
}

// ❌ BAD: Ignore errors in goroutines
func badWorkerIgnoringErrors(jobs <-chan int) {
	for job := range jobs {
		processJob(job) // Error is ignored
	}
}
```

### 2. Performance Considerations
```go
// ✅ GOOD: Use sync.Pool for object reuse
var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 0, 1024)
	},
}

func processData(data []byte) []byte {
	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf[:0]) // Reset but keep capacity
	
	// Process data
	buf = append(buf, data...)
	
	result := make([]byte, len(buf))
	copy(result, buf)
	
	return result
}

// ✅ GOOD: Use atomic operations for simple counters
type AtomicCounter struct {
	value int64
}

func (c *AtomicCounter) Increment() {
	atomic.AddInt64(&c.value, 1)
}

// ❌ BAD: Use mutex for simple operations
type BadCounter struct {
	mu    sync.Mutex
	value int64
}

func (c *BadCounter) Increment() {
	c.mu.Lock()
	c.value++
	c.mu.Unlock()
}
```

This comprehensive Go concurrency guide covers all essential patterns from basic goroutines and channels to advanced synchronization techniques, context-based cancellation, and real-world applications like web servers and data processing pipelines.

---

**Go Version**: [GO_VERSION]  
**Last Updated**: [DATE]  
**Template Version**: 1.0
