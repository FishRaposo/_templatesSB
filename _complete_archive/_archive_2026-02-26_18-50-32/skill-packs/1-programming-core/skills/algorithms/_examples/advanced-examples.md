# Advanced Algorithms

## Dijkstra's Algorithm

```javascript
function dijkstra(graph, start) {
    const distances = {};
    const visited = new Set();
    const queue = [[start, 0]];
    
    // Initialize distances
    for (const node in graph) {
        distances[node] = Infinity;
    }
    distances[start] = 0;
    
    while (queue.length) {
        queue.sort((a, b) => a[1] - b[1]);
        const [current, distance] = queue.shift();
        
        if (visited.has(current)) continue;
        visited.add(current);
        
        for (const [neighbor, weight] of Object.entries(graph[current])) {
            const newDistance = distance + weight;
            if (newDistance < distances[neighbor]) {
                distances[neighbor] = newDistance;
                queue.push([neighbor, newDistance]);
            }
        }
    }
    
    return distances;
}
```