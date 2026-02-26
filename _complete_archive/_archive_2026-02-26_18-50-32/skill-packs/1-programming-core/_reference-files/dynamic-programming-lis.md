<!-- Generated from task-outputs/task-04-problem-solving.md -->

# Dynamic Programming: Longest Increasing Subsequence

## Solution
`python
def lis(nums):
    dp = [1] * len(nums)
    for i in range(1, len(nums)):
        for j in range(i):
            if nums[i] > nums[j]:
                dp[i] = max(dp[i], dp[j] + 1)
    return max(dp)
`

## Complexity
- Time: O(n²)
- Space: O(n)