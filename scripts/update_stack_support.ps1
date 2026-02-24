# PowerShell script to update task-index.yaml with stack support levels

# Read the file
$content = Get-Content -Path "c:\Projects\_templates\tasks\task-index.yaml" -Raw

# Define the pattern to find allowed_stacks sections and add stack_support after them
$pattern = '(allowed_stacks:\r?\n(?:    - .+\r?\n)+)'

# Function to generate stack_support section
function Get-StackSupport {
    param($allowedSection)
    
    # Extract stacks from allowed_stacks
    $stacks = [regex]::Matches($allowedSection, '    - (.+)') | ForEach-Object { $_.Groups[1].Value }
    
    # Build stack_support section
    $supportLines = @("    stack_support:")
    foreach ($stack in $stacks) {
        if ($stack -in @('python', 'node', 'go', 'nextjs')) {
            $supportLines += "      $stack`: full"
        } else {
            $supportLines += "      $stack`: base-fallback"
        }
    }
    
    return $allowedSection + ($supportLines -join "`r`n") + "`r`n"
}

# Apply the transformation
$updatedContent = [regex]::Replace($content, $pattern, { param($match) Get-StackSupport $match.Groups[0].Value })

# Write back to file
$updatedContent | Out-File -FilePath "c:\Projects\_templates\tasks\task-index.yaml" -Encoding UTF8

Write-Host "Updated task-index.yaml with stack support levels for all tasks"
