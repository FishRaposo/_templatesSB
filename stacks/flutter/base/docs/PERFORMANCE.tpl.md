<!--
File: PERFORMANCE.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# Performance Optimization Guide - Flutter

This guide covers performance optimization techniques, profiling tools, and best practices for Flutter applications.

## 🚀 Flutter Performance Overview

Flutter provides excellent performance out of the box, but proper optimization can make your app even smoother. This guide covers rendering performance, memory management, and optimization strategies.

## 📊 Performance Metrics

### Key Performance Indicators
- **Frame Rate**: Target 60 FPS (16.67ms per frame)
- **Jank**: Frames that take longer than 16.67ms
- **Memory Usage**: Monitor for memory leaks
- **App Startup Time**: Time to first meaningful frame
- **Build Time**: Widget rebuild frequency

### Performance Targets
```dart
// Target performance metrics
const TARGET_FPS = 60.0;
const TARGET_FRAME_TIME_MS = 16.67;
const MAX_MEMORY_USAGE_MB = 150;
const TARGET_STARTUP_TIME_MS = 1000;
```

## 🔍 Performance Profiling Tools

### Flutter DevTools
```bash
# Install Flutter DevTools
flutter pub global activate devtools

# Run DevTools
flutter pub global run devtools

# Connect to running app
flutter run --profile
# Then open DevTools and connect
```

### Performance Overlay
```dart
// Enable performance overlay
MaterialApp(
  debugShowCheckedModeBanner: false,
  showPerformanceOverlay: true, // Show performance overlay
  checkerboardRasterCacheImages: true, // Show raster cache
  checkerboardOffscreenLayers: true, // Show offscreen layers
  home: MyApp(),
);
```

### Flutter Inspector
```bash
# Run with profiling
flutter run --profile

# Open Flutter Inspector in VS Code
# or use Android Studio's Flutter Inspector
```

## ⚡ Rendering Performance Optimization

### Widget Optimization

#### Before: Inefficient Widget
```dart
// BAD: Rebuilds entire list on every change
class BadListView extends StatelessWidget {
  final List<Item> items;
  
  const BadListView({required this.items});
  
  @override
  Widget build(BuildContext context) {
    return ListView.builder(
      itemCount: items.length,
      itemBuilder: (context, index) {
        return ItemWidget(item: items[index]); // Rebuilds every item
      },
    );
  }
}

class ItemWidget extends StatelessWidget {
  final Item item;
  
  const ItemWidget({required this.item});
  
  @override
  Widget build(BuildContext context) {
    return Container(
      margin: EdgeInsets.all(8.0),
      child: Column(
        children: [
          Text(item.title), // Expensive text rendering
          Text(item.description),
          Text(item.timestamp.toString()),
        ],
      ),
    );
  }
}
```

#### After: Optimized Widget
```dart
// GOOD: Uses const constructors and efficient widgets
class OptimizedListView extends StatelessWidget {
  final List<Item> items;
  
  const OptimizedListView({required this.items});
  
  @override
  Widget build(BuildContext context) {
    return ListView.builder(
      itemCount: items.length,
      itemBuilder: (context, index) {
        return ItemWidget(
          key: ValueKey(items[index].id), // Stable keys
          item: items[index],
        );
      },
    );
  }
}

class ItemWidget extends StatelessWidget {
  final Item item;
  
  const ItemWidget({required this.item, Key? key}) : super(key: key);
  
  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.all(8.0), // const margin
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            item.title,
            style: const TextStyle(fontWeight: FontWeight.bold),
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
          Text(
            item.description,
            maxLines: 2,
            overflow: TextOverflow.ellipsis,
          ),
          Text(
            _formatTimestamp(item.timestamp),
            style: const TextStyle(fontSize: 12, color: Colors.grey),
          ),
        ],
      ),
    );
  }
  
  String _formatTimestamp(DateTime timestamp) {
    // Efficient timestamp formatting
    final now = DateTime.now();
    final difference = now.difference(timestamp);
    
    if (difference.inDays > 0) {
      return '${difference.inDays} days ago';
    } else if (difference.inHours > 0) {
      return '${difference.inHours} hours ago';
    } else {
      return '${difference.inMinutes} minutes ago';
    }
  }
}
```

### Const Constructors
```dart
// BAD: Non-const widgets
class BadWidget extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Container(
      padding: EdgeInsets.all(16.0),
      decoration: BoxDecoration(
        color: Colors.blue,
        borderRadius: BorderRadius.circular(8.0),
      ),
      child: Text('Hello'),
    );
  }
}

// GOOD: Const constructors
class GoodWidget extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return const Container(
      padding: EdgeInsets.all(16.0),
      decoration: BoxDecoration(
        color: Colors.blue,
        borderRadius: BorderRadius.all(Radius.circular(8.0)),
      ),
      child: Text('Hello'),
    );
  }
}
```

### Efficient List Building
```dart
// GOOD: Use ListView.builder for large lists
class EfficientList extends StatelessWidget {
  final List<String> items;
  
  const EfficientList({required this.items});
  
  @override
  Widget build(BuildContext context) {
    return ListView.builder(
      itemCount: items.length,
      itemBuilder: (context, index) {
        return ListTile(
          title: Text(items[index]),
        );
      },
    );
  }
}

// BETTER: Use SliverList for complex scrolling
class AdvancedList extends StatelessWidget {
  final List<String> items;
  
  const AdvancedList({required this.items});
  
  @override
  Widget build(BuildContext context) {
    return CustomScrollView(
      slivers: [
        SliverAppBar(
          title: const Text('Advanced List'),
          floating: true,
        ),
        SliverList(
          delegate: SliverChildBuilderDelegate(
            (context, index) => ListTile(title: Text(items[index])),
            childCount: items.length,
          ),
        ),
      ],
    );
  }
}
```

## 💾 Memory Management

### Image Optimization
```dart
// BAD: Loading large images without optimization
class BadImageWidget extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Image.asset('assets/large_image.jpg'); // Loads full resolution
  }
}

// GOOD: Optimized image loading
class GoodImageWidget extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Image.asset(
      'assets/large_image.jpg',
      width: 300,
      height: 200,
      fit: BoxFit.cover,
      cacheWidth: 600, // Resize for memory efficiency
      cacheHeight: 400,
    );
  }
}

// BETTER: Use cached network images
class NetworkImageWidget extends StatelessWidget {
  final String imageUrl;
  
  const NetworkImageWidget({required this.imageUrl});
  
  @override
  Widget build(BuildContext context) {
    return CachedNetworkImage(
      imageUrl: imageUrl,
      placeholder: (context, url) => const CircularProgressIndicator(),
      errorWidget: (context, url, error) => const Icon(Icons.error),
      memCacheWidth: 600,
      memCacheHeight: 400,
    );
  }
}
```

### Memory Leak Prevention
```dart
// BAD: Potential memory leak with controllers
class BadControllerWidget extends StatefulWidget {
  @override
  _BadControllerWidgetState createState() => _BadControllerWidgetState();
}

class _BadControllerWidgetState extends State<BadControllerWidget> {
  late AnimationController _controller;
  late StreamSubscription _subscription;
  
  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      duration: const Duration(seconds: 1),
      vsync: this,
    );
    
    // Forgot to dispose subscription
    _subscription = someStream.listen((data) {
      setState(() {});
    });
  }
  
  @override
  void dispose() {
    _controller.dispose(); // Missing subscription disposal
    super.dispose();
  }
}

// GOOD: Proper resource management
class GoodControllerWidget extends StatefulWidget {
  @override
  _GoodControllerWidgetState createState() => _GoodControllerWidgetState();
}

class _GoodControllerWidgetState extends State<GoodControllerWidget>
    with TickerProviderStateMixin {
  late AnimationController _controller;
  late StreamSubscription _subscription;
  
  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      duration: const Duration(seconds: 1),
      vsync: this,
    );
    
    _subscription = someStream.listen((data) {
      if (mounted) { // Check if widget is still mounted
        setState(() {});
      }
    });
  }
  
  @override
  void dispose() {
    _subscription.cancel(); // Properly dispose subscription
    _controller.dispose();
    super.dispose();
  }
}
```

## 🎯 State Management Performance

### Efficient State Updates
```dart
// BAD: Unnecessary rebuilds
class BadStateWidget extends StatefulWidget {
  @override
  _BadStateWidgetState createState() => _BadStateWidgetState();
}

class _BadStateWidgetState extends State<BadStateWidget> {
  int _counter = 0;
  String _name = '';
  
  void updateCounter() {
    setState(() {
      _counter++; // Rebuilds entire widget including name
    });
  }
  
  void updateName(String name) {
    setState(() {
      _name = name; // Rebuilds entire widget including counter
    });
  }
  
  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Text('Counter: $_counter'),
        Text('Name: $_name'),
        ElevatedButton(
          onPressed: updateCounter,
          child: Text('Increment'),
        ),
      ],
    );
  }
}

// GOOD: Granular state management
class GoodStateWidget extends StatefulWidget {
  @override
  _GoodStateWidgetState createState() => _GoodStateWidgetState();
}

class _GoodStateWidgetState extends State<GoodStateWidget> {
  int _counter = 0;
  String _name = '';
  
  void updateCounter() {
    setState(() {
      _counter++;
    });
  }
  
  void updateName(String name) {
    setState(() {
      _name = name;
    });
  }
  
  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        CounterDisplay(counter: _counter), // Separate widget
        NameDisplay(name: _name), // Separate widget
        Row(
          children: [
            ElevatedButton(
              onPressed: updateCounter,
              child: const Text('Increment'),
            ),
            ElevatedButton(
              onPressed: () => updateName('New Name'),
              child: const Text('Update Name'),
            ),
          ],
        ),
      ],
    );
  }
}

class CounterDisplay extends StatelessWidget {
  final int counter;
  
  const CounterDisplay({required this.counter});
  
  @override
  Widget build(BuildContext context) {
    return Text('Counter: $counter');
  }
}

class NameDisplay extends StatelessWidget {
  final String name;
  
  const NameDisplay({required this.name});
  
  @override
  Widget build(BuildContext context) {
    return Text('Name: $name');
  }
}
```

## 🔄 Asynchronous Operations

### Efficient Future Handling
```dart
// BAD: Blocking UI with expensive operations
class BadFutureWidget extends StatefulWidget {
  @override
  _BadFutureWidgetState createState() => _BadFutureWidgetState();
}

class _BadFutureWidgetState extends State<BadFutureWidget> {
  String _data = '';
  bool _loading = false;
  
  @override
  void initState() {
    super.initState();
    _loadData();
  }
  
  Future<void> _loadData() async {
    setState(() => _loading = true);
    
    // Expensive computation blocks UI
    final result = await expensiveComputation();
    
    setState(() {
      _data = result;
      _loading = false;
    });
  }
  
  @override
  Widget build(BuildContext context) {
    return _loading 
      ? CircularProgressIndicator()
      : Text(_data);
  }
}

// GOOD: Efficient async operations
class GoodFutureWidget extends StatefulWidget {
  @override
  _GoodFutureWidgetState createState() => _GoodFutureWidgetState();
}

class _GoodFutureWidgetState extends State<GoodFutureWidget> {
  Future<String>? _dataFuture;
  
  @override
  void initState() {
    super.initState();
    _dataFuture = _loadData();
  }
  
  Future<String> _loadData() async {
    // Use compute for expensive operations
    return await compute(expensiveComputation, 'input');
  }
  
  @override
  Widget build(BuildContext context) {
    return FutureBuilder<String>(
      future: _dataFuture,
      builder: (context, snapshot) {
        if (snapshot.connectionState == ConnectionState.waiting) {
          return const CircularProgressIndicator();
        }
        
        if (snapshot.hasError) {
          return Text('Error: ${snapshot.error}');
        }
        
        return Text(snapshot.data ?? 'No data');
      },
    );
  }
}

// Isolate function for expensive computation
Future<String> expensiveComputation(String input) async {
  // Simulate expensive computation
  await Future.delayed(const Duration(seconds: 2));
  return 'Processed: $input';
}
```

## 📱 Platform-Specific Optimizations

### iOS Performance
```dart
// Optimize for iOS
class IOOptimizedWidget extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Theme(
      data: ThemeData.light().copyWith(
        platform: TargetPlatform.iOS,
      ),
      child: CupertinoPageScaffold(
        navigationBar: const CupertinoNavigationBar(
          middle: Text('iOS Optimized'),
        ),
        child: ListView.builder(
          itemCount: 1000,
          itemBuilder: (context, index) {
            return const CupertinoListTile(
              title: Text('Item'),
              leading: Icon(CupertinoIcons.star),
            );
          },
        ),
      ),
    );
  }
}
```

### Android Performance
```dart
// Optimize for Android
class AndroidOptimizedWidget extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Theme(
      data: ThemeData.light().copyWith(
        platform: TargetPlatform.android,
      ),
      child: Scaffold(
        appBar: AppBar(
          title: const Text('Android Optimized'),
        ),
        body: ListView.builder(
          itemCount: 1000,
          itemBuilder: (context, index) {
            return const ListTile(
              title: Text('Item'),
              leading: Icon(Icons.star),
            );
          },
        ),
      ),
    );
  }
}
```

## 🧪 Performance Testing

### Benchmark Tests
```dart
// Performance benchmark tests
void main() {
  testWidgets('List view performance test', (WidgetTester tester) async {
    final stopwatch = Stopwatch()..start();
    
    await tester.pumpWidget(
      MaterialApp(
        home: ListView.builder(
          itemCount: 1000,
          itemBuilder: (context, index) => ListTile(title: Text('Item $index')),
        ),
      ),
    );
    
    await tester.pumpAndSettle();
    stopwatch.stop();
    
    // Assert build time is acceptable
    expect(stopwatch.elapsedMilliseconds, lessThan(100));
    
    // Test scrolling performance
    final scrollStopwatch = Stopwatch()..start();
    await tester.fling(find.byType(ListView), const Offset(0, -500), 5000);
    await tester.pumpAndSettle();
    scrollStopwatch.stop();
    
    expect(scrollStopwatch.elapsedMilliseconds, lessThan(50));
  });
}
```

### Integration Tests
```dart
// Performance integration tests
void main() {
  integrationTest('App startup performance', () async {
    final stopwatch = Stopwatch()..start();
    
    app.main();
    await tester.pumpAndSettle();
    
    stopwatch.stop();
    
    // Assert startup time is acceptable
    expect(stopwatch.elapsedMilliseconds, lessThan(2000));
  });
}
```

## 📈 Performance Monitoring

### Custom Performance Tracking
```dart
class PerformanceTracker {
  static final Map<String, List<int>> _metrics = {};
  
  static void startTimer(String operation) {
    _metrics[operation] = _metrics[operation] ?? [];
    _metrics[operation]!.add(DateTime.now().millisecondsSinceEpoch);
  }
  
  static void endTimer(String operation) {
    if (_metrics[operation]?.isNotEmpty == true) {
      final startTime = _metrics[operation]!.removeLast();
      final duration = DateTime.now().millisecondsSinceEpoch - startTime;
      
      if (duration > 100) { // Log slow operations
        debugPrint('Slow operation: $operation took ${duration}ms');
      }
    }
  }
}

// Usage in widgets
class TrackedWidget extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    PerformanceTracker.startTimer('build');
    
    final widget = Container(
      child: Text('Tracked Widget'),
    );
    
    PerformanceTracker.endTimer('build');
    return widget;
  }
}
```

## 🚀 Best Practices Checklist

### Rendering Performance
- [ ] Use `const` constructors where possible
- [ ] Implement proper widget keys for lists
- [ ] Use `ListView.builder` for large lists
- [ ] Avoid rebuilding unchanged widgets
- [ ] Use `RepaintBoundary` for complex animations
- [ ] Optimize image loading with proper sizing

### Memory Management
- [ ] Dispose controllers and subscriptions properly
- [ ] Use `compute()` for expensive operations
- [ ] Implement proper image caching
- [ ] Monitor memory usage with DevTools
- [ ] Use `AutomaticKeepAliveClientMixin` judiciously

### State Management
- [ ] Minimize widget rebuilds
- [ ] Use granular state updates
- [ ] Implement efficient state management patterns
- [ ] Use `ValueNotifier` for simple state
- [ ] Consider BLoC/Provider for complex state

### Asynchronous Operations
- [ ] Use `FutureBuilder` for async UI
- [ ] Implement proper error handling
- [ ] Use `compute()` for expensive computations
- [ ] Optimize network requests with caching
- [ ] Use `StreamBuilder` for real-time data

---

**Flutter Version**: [FLUTTER_VERSION]  
**Performance Target**: 60 FPS  
**Last Updated**: [DATE]  
**Template Version**: 1.0
