# Task 4 — Problem Solving Response (RERUN)

## Longest Increasing Subsequence

`python
def lis(nums):
    if not nums:
        return 0
    dp = [1] * len(nums)
    for i in range(1, len(nums)):
        for j in range(i):
            if nums[i] > nums[j]:
                dp[i] = max(dp[i], dp[j] + 1)
    return max(dp)
``n
**Complexity:** Time O(n²), Space O(n)

- [x] Brute force analyzed
- [x] DP solution implemented
- [x] Complexity analyzed