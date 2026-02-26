# PowerShell script to add stack_support to all tasks in task-index.yaml

# Read the file
$content = Get-Content -Path "c:\Projects\_templates\tasks\task-index.yaml" -Raw

# Define the pattern to find allowed_stacks sections
$pattern = '(allowed_stacks:\r?\n((?:    - .+\r?\n)+))'

# Function to generate stack_support section
function Get-StackSupport {
    param($allowedSection)
    
    # Extract stacks from allowed_stacks
    $stacks = [regex]::Matches($allowedSection, '    - (.+)') | ForEach-Object { $_.Groups[1].Value }
    
    # Build stack_support section based on actual implementations
    # Full support: python, node, go, nextjs (where we found implementations)
    # Base-fallback: all others
    $supportLines = @("    stack_support:")
    foreach ($stack in $stacks) {
        if ($stack -in @('python', 'node', 'go', 'nextjs')) {
            $supportLines += "      $stack`: full"
        } else {
            $supportLines += "      $stack`: base-fallback"
        }
    }
    
    return $allowedSection + "`r`n" + ($supportLines -join "`r`n") + "`r`n"
}

# Apply the transformation
$updatedContent = [regex]::Replace($content, $pattern, { param($match) Get-StackSupport $match.Groups[0].Value })

# Write back to file
$updatedContent | Out-File -FilePath "c:\Projects\_templates\tasks\task-index.yaml" -Encoding UTF8 -NoNewline

Write-Host "Successfully added stack_support levels to all tasks"
