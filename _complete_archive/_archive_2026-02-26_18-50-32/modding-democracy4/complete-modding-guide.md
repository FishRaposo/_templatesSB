# Democracy 4 — Complete Modding Guide

> **Source references:** [Official Positech Modding Docs](https://www.positech.co.uk/democracy4/modding.html) + inspection of real workshop mods.

---

## Table of Contents

1. [How the Simulation Works](#1-how-the-simulation-works)
2. [Mod Folder Structure](#2-mod-folder-structure)
3. [config.txt — Mod Metadata](#3-configtxt--mod-metadata)
4. [Policies (policies.csv)](#4-policies-policiescsv)
5. [Simulation Values (simulation.csv)](#5-simulation-values-simulationcsv)
6. [Situations (situations.csv)](#6-situations-situationscsv)
7. [Sliders (sliders.csv)](#7-sliders-sliderscsv)
8. [Events (events/*.txt)](#8-events-eventstxt)
9. [Dilemmas (dilemmas/*.txt)](#9-dilemmas-dilemmatxt)
10. [Overrides (.ini files)](#10-overrides-ini-files)
11. [Translations](#11-translations)
12. [Countries](#12-countries)
13. [Graphics (SVG & Bitmaps)](#13-graphics-svg--bitmaps)
14. [Pre-Requisites (prereqs.txt)](#14-pre-requisites-prereqstxt)
15. [Effect Equation Syntax](#15-effect-equation-syntax)
16. [Voter Groups & Special Names](#16-voter-groups--special-names)
17. [Installing & Testing Your Mod](#17-installing--testing-your-mod)
18. [Publishing to Steam Workshop](#18-publishing-to-steam-workshop)

---

## 1. How the Simulation Works

Democracy 4's engine is a **neural network simulation**. Every object in the game — policies, voter groups, statistics, situations, events — is a **node**. Nodes are connected to each other by **effects** (weighted equations). Nothing is hard-coded; it all loads from CSV and text files.

Key principles:
- All values in the simulation are **between 0.0 and 1.0**.
- Effects use a simple equation syntax with `x` as the input value.
- **Inertia** controls how slowly a value responds to changes (higher = slower).
- The game re-evaluates the whole network each turn.

---

## 2. Mod Folder Structure

Mods live in:
```
Documents\My Games\Democracy4\mods\<your_mod_name>\
```

When installed via Steam Workshop they live in:
```
Steam\steamapps\workshop\content\1410710\<workshop_id>\
```

The internal layout mirrors the game's own data folder:

```
<your_mod_name>/
├── config.txt                        ← required: mod metadata
├── data/
│   ├── simulation/
│   │   ├── policies.csv              ← new policies
│   │   ├── simulation.csv            ← new simulation values (blue nodes)
│   │   ├── situations.csv            ← new situations (orange/green nodes)
│   │   ├── sliders.csv               ← custom slider types
│   │   ├── prereqs.txt               ← custom pre-requisite flags
│   │   ├── events/
│   │   │   └── MyEventName.txt       ← one file per event
│   │   └── dilemmas/
│   │       └── MyDilemmaName.txt     ← one file per dilemma
│   ├── overrides/
│   │   └── ModName_Host-Target.ini   ← patch existing connections
│   ├── bitmaps/
│   │   └── myevent_image.png         ← event/dilemma artwork (512x512 PNG)
│   └── svg/
│       └── my_policy_icon.svg        ← policy/sim/situation icons
└── translations/
    └── English/
        ├── policies.csv
        ├── simulation.csv
        ├── situations.csv
        ├── sliders.csv
        └── events.csv
```

You only need to include the files/folders relevant to what your mod adds. Empty folders can be omitted.

---

## 3. config.txt — Mod Metadata

Every mod **must** have a `config.txt` in its root folder. This is what the game reads to show the mod in the mod control panel.

```ini
[config]
name = my_mod_internal_name
path = C:\Users\YourName\Documents/My Games/democracy4/mods/my_mod_internal_name
guiname = My Mod Display Name
author = YourName
description = A short description of what your mod does.
```

- **`name`** — internal identifier, no spaces, used by the game engine.
- **`path`** — the full path to the mod folder on the author's machine (used during development; Workshop installs override this).
- **`guiname`** — the name shown to players in the mod menu.
- **`author`** — your name/handle.
- **`description`** — shown in the mod browser.

---

## 4. Policies (policies.csv)

File location: `data/simulation/policies.csv`

Each row that starts with `#` in column A defines a new policy. Any row without a leading `#` is treated as a comment and ignored.

### Column Reference

| Column | Name | Description |
|---|---|---|
| A | `#` | Row marker — must be `#` to be loaded |
| B | `name` | Internal object name (no spaces). Referenced by other objects. Never shown to players. |
| C | `slider` | Slider type. Use `default` for a plain 0–1 slider, or a name defined in `sliders.csv` for discrete options. |
| D | `flags` | Optional. `UNCANCELLABLE` = always active, greyed-out cancel button. `MULTIPLYINCOME` = income inputs are multiplied rather than added. |
| E | `opposites` | Comma-separated list of policy names that conflict with this one (they cancel each other). |
| F | `introduce` | Political capital cost to introduce this policy. |
| G | `cancel` | Political capital cost to cancel this policy. |
| H | `raise` | Political capital cost to raise the slider. |
| I | `lower` | Political capital cost to lower the slider. |
| J | `department` | Which zone/minister controls this policy. E.g. `ECONOMY`, `WELFARE`, `HEALTH`, `EDUCATION`, `TRANSPORT`, `FOREIGN`, `SECURITY`, `ENVIRONMENT`. |
| K | `prereqs` | Comma-separated pre-requisite flags that must be true for this policy to be available. See `prereqs.txt`. |
| L | `mincost` | Cost per turn at slider = 0. |
| M | `maxcost` | Cost per turn at slider = 1. |
| N | `costfunction` | Equation for cost curve. Default: `0+(1.0*x)` (linear). |
| O | `cost multiplier` | Colon-separated list of inputs that scale the final cost. Format: `SimName,equation` or `_default_,value`. |
| P | `implementation` | Turns to fully implement or cancel. Adjusted by minister competence. |
| Q | `minincome` | Income per turn at slider = 0. |
| R | `maxincome` | Income per turn at slider = 1. |
| S | `incomefunction` | Equation for income curve. Default: `0+(1.0*x)`. |
| T | `incomemultiplier` | Same as cost multiplier but for income. Use `MULTIPLYINCOME` flag to multiply inputs instead of adding. |
| U | `nationalisation GDP percentage` | Percentage of GDP credited/debited when the policy is nationalised or privatised. |
| — | `#Effects` | **Marker column.** Everything to the right of this is an effect output. |
| … | Effects | One effect per cell: `TargetName,equation,inertia` |

### Minimal Example

```
#,MySalesTax,default,,,30,30,15,10,ECONOMY,,0,80,0+(1.0*x),,2,0,200,0+(1.0*x),,,,#Effects,"GDP,-0.02+(0.01*x),4","Capitalist,0.05-(0.10*x),6","Socialist,-0.03+(0.06*x),6"
```

---

## 5. Simulation Values (simulation.csv)

File location: `data/simulation/simulation.csv`

These are the **blue circular nodes** on the policy screen. They represent statistics like GDP, Crime, Unemployment, etc.

Each row starting with `#` defines a new simulation value.

### Column Reference

| Column | Name | Description |
|---|---|---|
| A | `#` | Row marker |
| B | `name` | Internal object name |
| C | `zone` | Display area. E.g. `ECONOMY`, `WELFARE`, `ENVIRONMENT`, `HIDDEN` (not shown in UI). |
| D | `def` | Default starting value (0.0–1.0). |
| E | `min` | Minimum value. Usually `0`. |
| F | `max` | Maximum value. Usually `1`. |
| G | `emotion` | How changes are shown on the graph. `HIGHGOOD` (green when rising), `LOWGOOD` (green when falling), `UNKNOWN` (black). |
| H | `icon` | SVG filename (without path) for the icon. Place the SVG in `data/svg/`. |
| — | `#` (inputs) | **First `#` marker.** Everything to the right until the next `#` is an **input** into this sim value. |
| … | Inputs | `SourceName,equation,inertia` — what feeds INTO this value. |
| — | `#` (outputs) | **Second `#` marker.** Everything to the right is an **output** from this sim value. |
| … | Outputs | `TargetName,equation,inertia` — what this value feeds INTO. |

### Example

```
#,MyCostOfLiving,ECONOMY,0.4,0,1,LOWGOOD,cost_of_living_icon,#,"Inflation,0+(0.5*x),8","FoodPrices,0+(0.3*x),4",#,"PovertyRate,0+(0.4*x),6","WorkerProductivity,-0.1+(0.0*x),4"
```

---

## 6. Situations (situations.csv)

File location: `data/simulation/situations.csv`

Situations are the **orange (bad) or green (good) banner nodes** — things like a Housing Crisis, Tech Boom, or Pandemic. They are triggered when their value crosses a threshold.

### Column Reference

| Column | Description |
|---|---|
| `name` | Internal object name |
| `department` | Zone where the situation icon appears |
| `prereqs` | Pre-requisite flags required for this situation to be possible |
| `icon` | SVG filename (place in `data/svg/`) |
| `positive` | `1` = green background (good situation), `0` = red background (bad situation) |
| `starttrigger` | Value above which the situation activates |
| `stoptrigger` | Value below which the situation deactivates |
| `mincost` / `maxcost` | Cost per turn while active (multiplied by country multiplier) |
| `costfunction` | Usually `0+(1.0*x)` |
| `minincome` / `maxincome` | Income per turn while active |
| `incomefunction` | Usually `0+(1.0*x)` |
| `#` (inputs) | Effects that feed INTO this situation (determine its strength/trigger) |
| `#` (outputs) | Effects this situation has ON other objects while active |

The `_default_` source can be used to set a base level for the situation's strength.

### Example

```
#,MyHousingCrisis,WELFARE,,housing_crisis,0,,0.65,0.35,50,100,0+(1.0*x),0,0,0+(1.0*x),#,"_default_,0.9+(0*x)","HousingSubsidies,0-(0.6*x),6","PropertyTax,0-(0.3*x),4",#,"PovertyRate,0+(0.3*x),4","Liberal,-0.05+(0.0*x),4"
```

---

## 7. Sliders (sliders.csv)

File location: `data/simulation/sliders.csv`

Defines custom slider types for policies that have discrete options (e.g. "None / Low / Medium / High") rather than a continuous 0–1 range.

```
#,myslidername,DISCRETE,0
```

- **`DISCRETE`** — snaps to fixed positions.
- **`CONTINUOUS`** — standard smooth slider (same as `default`).
- The last value is the default position index.

The human-readable labels for each position go in `translations/English/sliders.csv`.

---

## 8. Events (events/*.txt)

File location: `data/simulation/events/MyEventName.txt`

Each event is a **separate `.txt` file**. Every 3 turns the game evaluates all events; the highest-scoring one above 70% probability is triggered.

### Format

```ini
[config]
Name = MyEventName
Texture = myevent_image.png
GUISound = DM4_Some Sound.wav
OnImplement = CreateGrudge(GDP,-0.05,0.95);CreateGrudge(Unemployment,0.08,0.92);CreateGrudge(MyEventName,-0.9,0.83);

[influences]
0 = _default_,0.5+(0*x)
1 = _random_,0,0.3
2 = Unemployment,0.4-(0.3*x)
3 = GDP,0.3-(0.4*x)
```

### [config] Fields

| Field | Description |
|---|---|
| `Name` | Internal name (must match filename) |
| `Texture` | PNG filename for the event image. Place in `data/bitmaps/`. Recommended 512×512. |
| `GUISound` | Sound file played when the event window is open. |
| `OnImplement` | Semicolon-separated list of `CreateGrudge()` calls run when the event fires. |

### CreateGrudge Syntax

```
CreateGrudge(TargetObjectName, EffectValue, Decay)
```

- **TargetObjectName** — any named object in the simulation.
- **EffectValue** — the initial strength of the effect (positive or negative).
- **Decay** — multiplied by itself each turn (e.g. `0.95` means the effect shrinks by 5% per turn). Higher = longer lasting. Use `0.83` for a short-lived effect, `0.97` for a long one.

**Always add a negative grudge against the event itself** (e.g. `CreateGrudge(MyEventName,-0.9,0.83)`) to prevent it from immediately re-triggering.

### [influences] Fields

Numbered list of inputs that determine the event's trigger probability. Uses standard effect syntax but **without inertia**. Special values:
- `_default_` — sets a base probability.
- `_random_,min,max` — adds random variation each evaluation.

---

## 9. Dilemmas (dilemmas/*.txt)

File location: `data/simulation/dilemmas/MyDilemmaName.txt`

Dilemmas are player choices. Unlike events they present **options** the player must pick from. Once triggered, a dilemma won't re-trigger for **32 turns**.

### Format

```ini
[dilemma]
name = MyDilemmaName

[influences]
0 = _random_,0,0.3
1 = Health,0.8-(0.6*x)
2 = Unemployment,0.3-(0.2*x)

[option0]
OnImplement = CreateGrudge(Health,0.05,0.92);CreateGrudge(Capitalist,-0.04,0.90);

[option1]
OnImplement = CreateGrudge(Health,-0.03,0.90);CreateGrudge(GDP,0.04,0.92);
```

- You can have **2 or 3 options** (`[option0]`, `[option1]`, optionally `[option2]`).
- `[influences]` works identically to events — no inertia allowed.
- `OnImplement` uses `CreateGrudge()` exactly as in events.
- The human-readable text (title, description, option labels) goes in `translations/English/`.

---

## 10. Overrides (.ini files)

File location: `data/overrides/ModName_Host-Target.ini`

Overrides let you **modify an existing connection** between two objects already in the game (or in another mod), without editing the original CSV files. This is the cleanest way to patch vanilla behaviour.

```ini
[override]
TargetName = "CorporateExodus"
HostName = "LabourLaws"
Equation = "0+(0.4*x)"
Inertia = 8
```

- **`HostName`** — the source object (the one producing the effect).
- **`TargetName`** — the object being affected.
- **`Equation`** — replaces the original equation for this specific connection.
- **`Inertia`** — replaces the original inertia for this connection.

The filename is just for your own organisation — only the contents matter.

---

## 11. Translations

All human-readable text is stored separately from the data files, inside:

```
translations/English/
```

This makes it easy to add other languages later by duplicating the folder.

### translations/English/policies.csv

```
#,InternalPolicyName,Display Name,"Full description of the policy shown to the player."
```

### translations/English/simulation.csv

```
#,InternalSimName,Display Name,hidden
```

The optional `hidden` flag suppresses the name from appearing in certain UI contexts.

### translations/English/situations.csv

```
#,InternalSituationName,Display Name,"Description shown when the player clicks the situation."
```

### translations/English/sliders.csv

```
#,myslidername,Label at 0,Label at 0.25,Label at 0.5,Label at 0.75,Label at 1.0
```

### translations/English/events.csv

```
#,MyEventName,Event Display Title,"Body text describing the event to the player."
```

---

## 12. Countries

Adding a new country requires a folder under `data/missions/<countryname>/` containing:

```
<countryname>/
├── <countryname>.txt      ← main country config (UTF-8 encoded)
├── overrides/             ← country-specific sim overrides (.ini files)
└── scripts/               ← startup grudge scripts (.txt files)
```

### countryname.txt Sections

**`[config]`** — name, flag image, anthem, population, area, currency, GDP multiplier, etc.

**`[options]`** — special flags like `MULTIPLEPARTIES` or `COMPULSORY_VOTING`.

**`[stats]`** — **initial simulation values** (0.0–1.0) for this country. e.g. `GDP = 0.62`, `Unemployment = 0.18`, `Health = 0.55`. These set where the sim starts; the display metadata (population, area, currency) goes in `[config]`, not here.

**`[policies]`** — starting policy values. Each line: `PolicyName = 0.65`. Any policy listed here is active at game start, fully implemented. Also include any applicable `prereqs.txt` entries here (e.g. `_prereq_has_coast = 1`).

### Country Overrides

Same `.ini` format as mod overrides — used to adjust simulation connections specifically for this country.

### Country Scripts

`.txt` files containing `CreateGrudge()` calls run at game start, used to set initial voter group compositions or temporary boosts/penalties unique to that country.

---

## 13. Graphics (SVG & Bitmaps)

### Policy / Simulation / Situation Icons

- **Format:** SVG (vector graphics)
- **Location:** `data/svg/`
- **Tool:** [Inkscape](https://inkscape.org/) (free)
- The blue circle border for simulation values is added automatically by the game — just provide the central icon.

### Event / Dilemma Images

- **Format:** PNG
- **Recommended size:** 512×512 pixels
- **Location:** `data/bitmaps/`
- Referenced by filename in the event's `[config]` `Texture` field.

---

## 14. Pre-Requisites (prereqs.txt)

File location: `data/simulation/prereqs.txt`

Pre-requisites are boolean flags (0 or 1) that gate content. Built-in examples:

```
0 = _prereq_has_coast
1 = _prereq_mining_industry
2 = _prereq_royal_family
3 = _prereq_land_border
4 = _prereq_deadly_animals
```

To add your own, create `data/simulation/prereqs.txt` in your mod and list new names using numbers **100 or higher** to avoid clashing with vanilla:

```
100 = _prereq_my_custom_flag
101 = _prereq_my_other_condition
```

Then reference them in the `prereqs` column of policies, situations, or in event/dilemma influences. Set them per-country in that country's `[policies]` section.

---

## 15. Effect Equation Syntax

Effects are the core of the simulation. Every connection between two objects uses this format:

```
TargetName, equation, inertia
```

### The Equation

- `x` = the current value of the **source** object (0.0–1.0).
- For policies, `x` = the current slider position.
- Operators: `+`, `-`, `*`, `/`, `^` (power/exponent).
- You can reference **other simulation values by name** directly in the equation.

### Examples

```
Education, 0.04+(0.04*x), 4
```
→ Adds between 0.04 and 0.08 to Education depending on slider.

```
Education, 0.04+((0.04*x)*Technology), 4
```
→ Same but scaled by the current level of Technology.

```
Unemployment, 0-(0.3*x), 6
```
→ Reduces Unemployment by up to 0.3 at full slider.

```
GDP, -0.02+(0.05*x)^1.5, 8
```
→ Non-linear curve using power operator.

### Inertia

Inertia is the **third value** in an effect. It controls how many past turns are averaged to smooth the effect:
- `1` = instant response.
- `4` = takes ~4 turns to fully respond to a change.
- `8`–`12` = slow, structural changes.
- Higher inertia = more stable but less responsive simulation.

### Special Source Names

| Name | Meaning |
|---|---|
| `_default_` | A fixed base value (not from any object) |
| `_random_,min,max` | Random number between min and max each turn |
| `_inv_SimName` | The inverse of a simulation value (`1 - SimValue`) |
| `_global_socialism` | Aggregate socialism level across all active policies |
| `_global_capitalism` | Aggregate capitalism level |

### Voter Group Effects

- `GroupName` — affects the **happiness** of that voter group.
- `GroupName_freq` — affects the **membership size** of that voter group.

Common voter groups: `Capitalist`, `Socialist`, `Liberal`, `Conservative`, `Religious`, `Ethnic`, `Retired`, `Commuter`, `Farmer`, `TradeUnionist`, `Patriot`, `SelfEmployed`, `Parents`, `Youth`, `Poor`, `Middle`, `Wealthy`.

---

## 16. Voter Groups & Special Names

| Name | Description |
|---|---|
| `Poor` | Low-income voters |
| `Middle` | Middle-income voters |
| `Wealthy` | High-income voters |
| `Capitalist` | Pro-market voters |
| `Socialist` | Pro-state voters |
| `Liberal` | Civil liberties focused |
| `Conservative` | Traditional values focused |
| `Religious` | Faith-based voters |
| `Ethnic` | Ethnic minority voters |
| `Retired` | Pensioners |
| `Commuter` | Car/transit dependent voters |
| `Farmer` | Agricultural voters |
| `TradeUnionist` | Union members |
| `Patriot` | Nationalist voters |
| `SelfEmployed` | Small business / freelancers |
| `Parents` | Voters with children |
| `Youth` | Young voters |

---

## 17. Installing & Testing Your Mod

1. Create your mod folder at:
   ```
   Documents\My Games\Democracy4\mods\<your_mod_name>\
   ```
2. Add your `config.txt` and data files.
3. Launch Democracy 4.
4. Go to **Mods** from the main menu.
5. Find your mod and **enable** it.
6. Start a **new game** — mod changes only take effect on new games, not saves.
7. Check the game's log file for errors if something doesn't load:
   ```
   Documents\My Games\Democracy4\debug.txt
   ```

**Tips:**
- Always back up original game files before editing them.
- Save CSV files as **CSV format only** — never let Excel change the format.
- Use a plain text editor (Notepad++, VS Code) for `.txt` and `.ini` files.
- Internal names (object names) are **case-sensitive**.
- Avoid spaces in internal names — use underscores or camelCase.
- Use [GraphCalc](http://www.graphcalc.com/) or [Desmos](https://www.desmos.com/calculator) to visualise your equations before using them.

---

## 18. Publishing to Steam Workshop

Publishing is handled **inside the game**:

1. Enable your mod in the mod menu.
2. Click the **Upload to Workshop** button next to your mod.
3. The game will package and upload it automatically.
4. The Workshop ID folder will be created in:
   ```
   Steam\steamapps\workshop\content\1410710\<workshop_id>\
   ```

To update an existing Workshop mod, make your changes locally, then upload again — the game will update the existing Workshop entry rather than creating a new one (as long as the `config.txt` `name` field matches).

---

## Quick Reference Cheat Sheet

```
New policy          → data/simulation/policies.csv        (one row per policy)
New sim value       → data/simulation/simulation.csv      (one row per value)
New situation       → data/simulation/situations.csv      (one row per situation)
New slider type     → data/simulation/sliders.csv         (one row per slider)
New event           → data/simulation/events/Name.txt     (one file per event)
New dilemma         → data/simulation/dilemmas/Name.txt   (one file per dilemma)
Patch existing link → data/overrides/Name.ini             (one file per connection)
Icons               → data/svg/*.svg
Event images        → data/bitmaps/*.png
Display text        → translations/English/*.csv
New country         → data/missions/<name>/<name>.txt
```

---

*Sources: [positech.co.uk/democracy4/modding.html](https://www.positech.co.uk/democracy4/modding.html) and sub-pages, Steam Workshop guide by cliffski (ID 2242250360), and direct inspection of installed workshop mods.*

---

## See Also

- `democracy4-mod-reference.md` — quick column-by-column lookup tables for all CSV formats.
- `D4U-MODPACK.md` — developer reference for the **D4U Ultimate** multi-module modpack (module index, cross-module dependencies, balance audit scripts, fix history). Relevant if you are contributing to or maintaining the D4U Ultimate Steam Workshop collection.
