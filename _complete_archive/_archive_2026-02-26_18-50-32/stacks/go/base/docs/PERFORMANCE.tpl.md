<!--
File: PERFORMANCE.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# Performance Optimization Guide - Go

This guide covers performance optimization techniques, profiling tools, and best practices for Go applications.

## 🚀 Go Performance Overview

Go provides excellent performance through compiled execution, efficient garbage collection, and built-in concurrency. This guide covers profiling, optimization strategies, and performance monitoring.

## 📊 Performance Metrics

### Key Performance Indicators
- **Response Time**: Time to process requests
- **Throughput**: Requests per second (RPS)
- **CPU Usage**: Processor utilization percentage
- **Memory Usage**: Heap allocation and GC pressure
- **Goroutine Count**: Number of active goroutines
- **GC Pause Time**: Garbage collection pause duration

### Performance Targets
```go
// Target performance metrics
const (
    TargetResponseTimeMs    = 100
    TargetThroughputRPS     = 1000
    TargetCPUPercentage     = 70
    TargetMemoryUsageMB     = 512
    TargetGoroutineCount    = 1000
    TargetGCPauseTimeMs     = 10
)
```

## 🔍 Performance Profiling Tools

### Built-in Go Profiling
```go
// Enable pprof profiling
import (
    _ "net/http/pprof"
    "net/http"
    "log"
)

func init() {
    // Start pprof server
    go func() {
        log.Println(http.ListenAndServe("localhost:6060", nil))
    }()
}

// CPU profiling
func startCPUProfile(filename string) (*os.File, error) {
    f, err := os.Create(filename)
    if err != nil {
        return nil, err
    }
    
    if err := pprof.StartCPUProfile(f); err != nil {
        f.Close()
        return nil, err
    }
    
    return f, nil
}

func stopCPUProfile(f *os.File) {
    pprof.StopCPUProfile()
    f.Close()
}

// Memory profiling
func writeHeapProfile(filename string) error {
    f, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer f.Close()
    
    runtime.GC() // Force GC before profiling
    return pprof.WriteHeapProfile(f)
}

// Usage
func main() {
    // CPU profiling
    cpuFile, err := startCPUProfile("cpu.prof")
    if err != nil {
        log.Fatal(err)
    }
    defer stopCPUProfile(cpuFile)
    
    // Application logic
    runApp()
    
    // Memory profiling
    if err := writeHeapProfile("heap.prof"); err != nil {
        log.Fatal(err)
    }
}
```

### Command Line Profiling
```bash
# CPU profiling
go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30

# Memory profiling
go tool pprof http://localhost:6060/debug/pprof/heap

# Goroutine profiling
go tool pprof http://localhost:6060/debug/pprof/goroutine

# Block profiling
go tool pprof http://localhost:6060/debug/pprof/block

# Generate visualizations
go tool pprof -png cpu.prof > cpu.png
go tool pprof -png heap.prof > heap.png
```

### Advanced Profiling with go-torch
```bash
# Install go-torch
go get github.com/uber/go-torch

# Generate flame graph
go-torch -u http://localhost:6060 -t 30 -f cpu.svg

# Memory flame graph
go-torch -u http://localhost:6060 -p -t 30 -f memory.svg
```

## ⚡ Concurrency Performance

### Goroutine Optimization

#### Before: Goroutine Leak
```go
// BAD: Goroutine leak
func leakyGoroutine() {
    ch := make(chan int)
    
    go func() {
        // This goroutine will never exit
        for {
            select {
            case <-ch:
                fmt.Println("Received")
            default:
                time.Sleep(time.Second)
            }
        }
    }()
    
    // Channel is never closed, goroutine leaks
}
```

#### After: Proper Goroutine Management
```go
// GOOD: Proper goroutine lifecycle
func properGoroutine(ctx context.Context) error {
    ch := make(chan int)
    done := make(chan struct{})
    
    go func() {
        defer close(done)
        
        for {
            select {
            case <-ch:
                fmt.Println("Received")
            case <-ctx.Done():
                return // Exit when context is cancelled
            }
        }
    }()
    
    // Use context to cancel goroutine
    select {
    case <-done:
        return nil
    case <-time.After(time.Second):
        return fmt.Errorf("timeout")
    }
}

// BETTER: Worker pool pattern
type WorkerPool struct {
    workers    int
    jobQueue   chan Job
    workerPool chan chan Job
    quit       chan bool
}

type Job struct {
    ID       int
    Data     interface{}
    Callback func(interface{})
}

func NewWorkerPool(workers int) *WorkerPool {
    return &WorkerPool{
        workers:    workers,
        jobQueue:   make(chan Job, 100),
        workerPool: make(chan chan Job, workers),
        quit:       make(chan bool),
    }
}

func (wp *WorkerPool) Start() {
    for i := 0; i < wp.workers; i++ {
        worker := NewWorker(wp.workerPool)
        worker.Start()
    }
    
    go wp.dispatch()
}

func (wp *WorkerPool) dispatch() {
    for {
        select {
        case job := <-wp.jobQueue:
            go func() {
                jobChannel := <-wp.workerPool
                jobChannel <- job
            }()
        case <-wp.quit:
            return
        }
    }
}

func (wp *WorkerPool) AddJob(job Job) {
    wp.jobQueue <- job
}

func (wp *WorkerPool) Stop() {
    close(wp.quit)
}

type Worker struct {
    jobQueue chan Job
    quit     chan bool
}

func NewWorker(workerPool chan chan Job) *Worker {
    return &Worker{
        jobQueue: make(chan Job),
        quit:     make(chan bool),
    }
}

func (w *Worker) Start() {
    go func() {
        for {
            w.workerPool <- w.jobQueue
            select {
            case job := <-w.jobQueue:
                job.Callback(job.Data)
            case <-w.quit:
                return
            }
        }
    }()
}
```

### Channel Optimization

#### Before: Inefficient Channel Usage
```go
// BAD: Unbuffered channel causing blocking
func processItemsBad(items []Item) []Result {
    results := make([]Result, len(items))
    
    for i, item := range items {
        ch := make(chan Result) // Unbuffered channel
        go func(item Item) {
            ch <- processItem(item) // Blocks until receiver is ready
        }(item)
        
        results[i] = <-ch // Sequential processing
    }
    
    return results
}
```

#### After: Optimized Channel Usage
```go
// GOOD: Buffered channels and parallel processing
func processItemsGood(items []Item) []Result {
    results := make([]Result, len(items))
    ch := make(chan Result, len(items)) // Buffered channel
    
    // Process items in parallel
    for _, item := range items {
        go func(item Item) {
            ch <- processItem(item)
        }(item)
    }
    
    // Collect results
    for i := 0; i < len(items); i++ {
        results[i] = <-ch
    }
    
    return results
}

// BETTER: Using sync.WaitGroup
func processItemsWithWaitGroup(items []Item) []Result {
    var wg sync.WaitGroup
    results := make([]Result, len(items))
    
    for i, item := range items {
        wg.Add(1)
        go func(index int, item Item) {
            defer wg.Done()
            results[index] = processItem(item)
        }(i, item)
    }
    
    wg.Wait()
    return results
}
```

## 💾 Memory Management

### Memory Allocation Optimization

#### Before: Excessive Allocations
```go
// BAD: Excessive memory allocations
func concatenateStringsBad(strings []string) string {
    var result string
    for _, s := range strings {
        result += s // Creates new string on each iteration
    }
    return result
}

func processSliceBad(data []int) []int {
    var result []int
    for _, v := range data {
        result = append(result, v*2) // Multiple allocations
    }
    return result
}
```

#### After: Memory-Efficient Operations
```go
// GOOD: Using strings.Builder
func concatenateStringsGood(strings []string) string {
    var builder strings.Builder
    builder.Grow(len(strings) * 10) // Pre-allocate capacity
    
    for _, s := range strings {
        builder.WriteString(s)
    }
    return builder.String()
}

// BETTER: Pre-allocated slice
func processSliceGood(data []int) []int {
    result := make([]int, 0, len(data)) // Pre-allocate capacity
    for _, v := range data {
        result = append(result, v*2)
    }
    return result
}

// OPTIMAL: In-place operations when possible
func processSliceInPlace(data []int) {
    for i := range data {
        data[i] *= 2
    }
}
```

### Object Pool Pattern
```go
// GOOD: Object pooling for expensive objects
type ObjectPool struct {
    pool sync.Pool
}

func NewObjectPool() *ObjectPool {
    return &ObjectPool{
        pool: sync.Pool{
            New: func() interface{} {
                return make([]byte, 1024) // Expensive allocation
            },
        },
    }
}

func (p *ObjectPool) Get() []byte {
    return p.pool.Get().([]byte)
}

func (p *ObjectPool) Put(buf []byte) {
    if cap(buf) == 1024 { // Only pool if correct size
        p.pool.Put(buf[:0]) // Reset length but keep capacity
    }
}

// Usage
func processWithPool(data []byte) {
    pool := NewObjectPool()
    buf := pool.Get()
    defer pool.Put(buf)
    
    // Use buffer
    copy(buf, data)
    processData(buf)
}
```

### Memory Profiling and Optimization
```go
// Memory monitoring
func monitorMemory() {
    var m runtime.MemStats
    runtime.ReadMemStats(&m)
    
    fmt.Printf("Alloc = %v MiB", bToMb(m.Alloc))
    fmt.Printf("TotalAlloc = %v MiB", bToMb(m.TotalAlloc))
    fmt.Printf("Sys = %v MiB", bToMb(m.Sys))
    fmt.Printf("NumGC = %v", m.NumGC)
}

func bToMb(b uint64) uint64 {
    return b / 1024 / 1024
}

// GC tuning
func tuneGC() {
    // Set GC target percentage
    debug.SetGCPercent(100) // Default is 100
    
    // Set memory limit (Go 1.19+)
    debug.SetMemoryLimit(1024 * 1024 * 1024) // 1GB
}
```

## 🔄 I/O Performance

### Efficient File Operations

#### Before: Inefficient File I/O
```go
// BAD: Reading entire file into memory
func processLargeFileBad(filename string) error {
    data, err := ioutil.ReadFile(filename) // Loads entire file
    if err != nil {
        return err
    }
    
    lines := strings.Split(string(data), "\n")
    for _, line := range lines {
        processLine(line)
    }
    
    return nil
}
```

#### After: Streaming File Operations
```go
// GOOD: Streaming file processing
func processLargeFileGood(filename string) error {
    file, err := os.Open(filename)
    if err != nil {
        return err
    }
    defer file.Close()
    
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        processLine(scanner.Text())
    }
    
    return scanner.Err()
}

// BETTER: Buffered I/O with custom buffer size
func processLargeFileOptimized(filename string) error {
    file, err := os.Open(filename)
    if err != nil {
        return err
    }
    defer file.Close()
    
    reader := bufio.NewReaderSize(file, 64*1024) // 64KB buffer
    
    for {
        line, err := reader.ReadString('\n')
        if err != nil {
            if err == io.EOF {
                break
            }
            return err
        }
        
        processLine(strings.TrimSpace(line))
    }
    
    return nil
}
```

### Network Optimization

#### Before: Inefficient Network Operations
```go
// BAD: Sequential HTTP requests
func fetchURLsBad(urls []string) ([]string, error) {
    var results []string
    for _, url := range urls {
        resp, err := http.Get(url) // Sequential requests
        if err != nil {
            return nil, err
        }
        
        body, err := ioutil.ReadAll(resp.Body)
        resp.Body.Close()
        if err != nil {
            return nil, err
        }
        
        results = append(results, string(body))
    }
    
    return results, nil
}
```

#### After: Concurrent Network Operations
```go
// GOOD: Concurrent HTTP requests
func fetchURLsGood(urls []string) ([]string, error) {
    var wg sync.WaitGroup
    results := make([]string, len(urls))
    errors := make([]error, len(urls))
    
    for i, url := range urls {
        wg.Add(1)
        go func(index int, url string) {
            defer wg.Done()
            
            resp, err := http.Get(url)
            if err != nil {
                errors[index] = err
                return
            }
            
            body, err := ioutil.ReadAll(resp.Body)
            resp.Body.Close()
            if err != nil {
                errors[index] = err
                return
            }
            
            results[index] = string(body)
        }(i, url)
    }
    
    wg.Wait()
    
    // Check for errors
    for _, err := range errors {
        if err != nil {
            return nil, err
        }
    }
    
    return results, nil
}

// BETTER: HTTP client with connection pooling
func createOptimizedClient() *http.Client {
    return &http.Client{
        Transport: &http.Transport{
            MaxIdleConns:        100,
            MaxIdleConnsPerHost: 10,
            IdleConnTimeout:     90 * time.Second,
            DisableCompression:  false,
        },
        Timeout: 30 * time.Second,
    }
}

func fetchURLsWithClient(client *http.Client, urls []string) ([]string, error) {
    var wg sync.WaitGroup
    results := make([]string, len(urls))
    errors := make([]error, len(urls))
    
    for i, url := range urls {
        wg.Add(1)
        go func(index int, url string) {
            defer wg.Done()
            
            resp, err := client.Get(url)
            if err != nil {
                errors[index] = err
                return
            }
            
            body, err := ioutil.ReadAll(resp.Body)
            resp.Body.Close()
            if err != nil {
                errors[index] = err
                return
            }
            
            results[index] = string(body)
        }(i, url)
    }
    
    wg.Wait()
    
    for _, err := range errors {
        if err != nil {
            return nil, err
        }
    }
    
    return results, nil
}
```

## 🗄️ Database Performance

### Connection Pooling
```go
// GOOD: Database connection pool
type DBPool struct {
    pool chan *sql.DB
    max  int
}

func NewDBPool(dsn string, maxConnections int) (*DBPool, error) {
    pool := make(chan *sql.DB, maxConnections)
    
    for i := 0; i < maxConnections; i++ {
        db, err := sql.Open("postgres", dsn)
        if err != nil {
            return nil, err
        }
        pool <- db
    }
    
    return &DBPool{pool: pool, max: maxConnections}, nil
}

func (p *DBPool) Get() *sql.DB {
    return <-p.pool
}

func (p *DBPool) Put(db *sql.DB) {
    p.pool <- db
}

func (p *DBPool) Close() {
    close(p.pool)
    for db := range p.pool {
        db.Close()
    }
}

// Usage
func queryWithPool(pool *DBPool, query string, args ...interface{}) (*sql.Rows, error) {
    db := pool.Get()
    defer pool.Put(db)
    
    return db.Query(query, args...)
}
```

### Query Optimization
```go
// GOOD: Prepared statements for query optimization
type QueryCache struct {
    cache map[string]*sql.Stmt
    mutex sync.RWMutex
    db    *sql.DB
}

func NewQueryCache(db *sql.DB) *QueryCache {
    return &QueryCache{
        cache: make(map[string]*sql.Stmt),
        db:    db,
    }
}

func (qc *QueryCache) Prepare(query string) (*sql.Stmt, error) {
    qc.mutex.RLock()
    stmt, exists := qc.cache[query]
    qc.mutex.RUnlock()
    
    if exists {
        return stmt, nil
    }
    
    qc.mutex.Lock()
    defer qc.mutex.Unlock()
    
    // Double-check after acquiring write lock
    stmt, exists = qc.cache[query]
    if exists {
        return stmt, nil
    }
    
    stmt, err := qc.db.Prepare(query)
    if err != nil {
        return nil, err
    }
    
    qc.cache[query] = stmt
    return stmt, nil
}

// Batch operations for better performance
func batchInsert(db *sql.DB, records []Record) error {
    if len(records) == 0 {
        return nil
    }
    
    // Build batch query
    valueStrings := make([]string, 0, len(records))
    valueArgs := make([]interface{}, 0, len(records)*3)
    
    for _, record := range records {
        valueStrings = append(valueStrings, "(?, ?, ?)")
        valueArgs = append(valueArgs, record.Name, record.Value, record.Timestamp)
    }
    
    query := fmt.Sprintf("INSERT INTO records (name, value, timestamp) VALUES %s",
        strings.Join(valueStrings, ","))
    
    _, err := db.Exec(query, valueArgs...)
    return err
}
```

## 🧪 Performance Testing

### Benchmark Testing
```go
// Benchmark tests
func BenchmarkStringConcatenation(b *testing.B) {
    strings := []string{"hello", "world", "benchmark", "test"}
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        concatenateStringsBad(strings)
    }
}

func BenchmarkStringBuilder(b *testing.B) {
    strings := []string{"hello", "world", "benchmark", "test"}
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        concatenateStringsGood(strings)
    }
}

func BenchmarkProcessItems(b *testing.B) {
    items := make([]Item, 1000)
    for i := range items {
        items[i] = Item{ID: i, Data: fmt.Sprintf("item-%d", i)}
    }
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        processItemsGood(items)
    }
}

// Parallel benchmarks
func BenchmarkParallelProcess(b *testing.B) {
    items := make([]Item, 1000)
    for i := range items {
        items[i] = Item{ID: i, Data: fmt.Sprintf("item-%d", i)}
    }
    
    b.ResetTimer()
    b.RunParallel(func(pb *testing.PB) {
        for pb.Next() {
            processItemsGood(items)
        }
    })
}
```

### Load Testing
```go
// HTTP load testing
func loadTest(url string, concurrency int, duration time.Duration) error {
    var wg sync.WaitGroup
    var totalRequests int64
    var totalErrors int64
    
    startTime := time.Now()
    endTime := startTime.Add(duration)
    
    for i := 0; i < concurrency; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            
            client := &http.Client{Timeout: 5 * time.Second}
            
            for time.Now().Before(endTime) {
                resp, err := client.Get(url)
                if err != nil {
                    atomic.AddInt64(&totalErrors, 1)
                    continue
                }
                resp.Body.Close()
                atomic.AddInt64(&totalRequests, 1)
            }
        }()
    }
    
    wg.Wait()
    
    actualDuration := time.Since(startTime)
    rps := float64(totalRequests) / actualDuration.Seconds()
    
    fmt.Printf("Load Test Results:\n")
    fmt.Printf("Duration: %v\n", actualDuration)
    fmt.Printf("Total Requests: %d\n", totalRequests)
    fmt.Printf("Total Errors: %d\n", totalErrors)
    fmt.Printf("Requests/Second: %.2f\n", rps)
    
    return nil
}
```

## 📈 Performance Monitoring

### Custom Metrics
```go
// Performance monitoring system
type PerformanceMetrics struct {
    RequestCount    int64
    ErrorCount      int64
    ResponseTime    time.Duration
    MemoryUsage     uint64
    GoroutineCount  int
    
    mutex sync.RWMutex
}

func (pm *PerformanceMetrics) RecordRequest(duration time.Duration, err error) {
    pm.mutex.Lock()
    defer pm.mutex.Unlock()
    
    pm.RequestCount++
    if err != nil {
        pm.ErrorCount++
    }
    pm.ResponseTime += duration
}

func (pm *PerformanceMetrics) UpdateSystemMetrics() {
    pm.mutex.Lock()
    defer pm.mutex.Unlock()
    
    var m runtime.MemStats
    runtime.ReadMemStats(&m)
    
    pm.MemoryUsage = m.Alloc
    pm.GoroutineCount = runtime.NumGoroutine()
}

func (pm *PerformanceMetrics) GetStats() map[string]interface{} {
    pm.mutex.RLock()
    defer pm.mutex.RUnlock()
    
    avgResponseTime := time.Duration(0)
    if pm.RequestCount > 0 {
        avgResponseTime = pm.ResponseTime / time.Duration(pm.RequestCount)
    }
    
    return map[string]interface{}{
        "request_count":     pm.RequestCount,
        "error_count":       pm.ErrorCount,
        "error_rate":        float64(pm.ErrorCount) / float64(pm.RequestCount),
        "avg_response_time": avgResponseTime.String(),
        "memory_usage_mb":   pm.MemoryUsage / 1024 / 1024,
        "goroutine_count":   pm.GoroutineCount,
    }
}

// HTTP middleware for performance monitoring
func PerformanceMiddleware(metrics *PerformanceMetrics) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            start := time.Now()
            
            // Capture response writer to get status code
            wrapped := &responseWriter{ResponseWriter: w, statusCode: 200}
            
            next.ServeHTTP(wrapped, r)
            
            duration := time.Since(start)
            var err error
            if wrapped.statusCode >= 400 {
                err = fmt.Errorf("HTTP %d", wrapped.statusCode)
            }
            
            metrics.RecordRequest(duration, err)
        })
    }
}

type responseWriter struct {
    http.ResponseWriter
    statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
    rw.statusCode = code
    rw.ResponseWriter.WriteHeader(code)
}
```

## 🚀 Best Practices Checklist

### Concurrency Performance
- [ ] Use worker pools for goroutine management
- [ ] Implement proper goroutine lifecycle management
- [ ] Use buffered channels to prevent blocking
- [ ] Avoid goroutine leaks with context cancellation
- [ ] Use sync.WaitGroup for coordinating goroutines
- [ ] Monitor goroutine count in production

### Memory Management
- [ ] Pre-allocate slices and maps when possible
- [ ] Use strings.Builder for string concatenation
- [ ] Implement object pooling for expensive allocations
- [ ] Monitor memory usage and GC pressure
- [ ] Use in-place operations when possible
- [ ] Tune GC parameters for your workload

### I/O Performance
- [ ] Use buffered I/O for file operations
- [ ] Implement connection pooling for databases
- [ ] Use concurrent HTTP requests
- [ ] Stream large files instead of loading entirely
- [ ] Use appropriate buffer sizes
- [ ] Implement proper timeout handling

### Database Performance
- [ ] Use prepared statements for repeated queries
- [ ] Implement batch operations for bulk inserts/updates
- [ ] Use connection pooling
- [ ] Add appropriate database indexes
- [ ] Monitor query performance
- [ ] Use read replicas for read-heavy workloads

### Monitoring & Testing
- [ ] Implement comprehensive benchmarking
- [ ] Use pprof for regular profiling
- [ ] Monitor key performance metrics
- [ ] Set up load testing for critical paths
- [ ] Use custom performance middleware
- [ ] Conduct regular performance audits

---

**Go Version**: [GO_VERSION]  
**Performance Framework**: pprof, go-torch, built-in testing  
**Last Updated**: [DATE]  
**Template Version**: 1.0
