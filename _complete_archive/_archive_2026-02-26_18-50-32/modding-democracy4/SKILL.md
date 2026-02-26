---
name: modding-democracy4
description: Use this skill when creating, editing, or debugging mods for Democracy 4. This includes adding new policies, simulation values, situations, events, dilemmas, overrides, sliders, translations, or countries. Use when the user mentions Democracy 4 modding, D4 mods, policies.csv, simulation.csv, situations.csv, config.txt, CreateGrudge, or any Democracy 4 mod file format.
---

# Modding Democracy 4

I'll help you create, edit, and debug mods for Democracy 4. I understand the full mod file format and simulation engine.

# Core Approach

1. Identify what the mod needs to add or change (policy, sim value, situation, event, dilemma, override, country).
2. Use the correct file for each element — never mix data into the wrong CSV.
3. Keep internal names unique, camelCase or underscore_separated, no spaces.
4. Always pair data files with matching translation entries.
5. Test by checking `Documents\My Games\Democracy4\debug.txt` after enabling the mod.

# Mod Folder Structure

```
Documents\My Games\Democracy4\mods\<mod_name>\
├── config.txt
├── data/
│   ├── simulation/
│   │   ├── policies.csv
│   │   ├── simulation.csv
│   │   ├── situations.csv
│   │   ├── sliders.csv
│   │   ├── prereqs.txt
│   │   ├── events/MyEvent.txt
│   │   └── dilemmas/MyDilemma.txt
│   ├── overrides/ModName_Host-Target.ini
│   ├── bitmaps/event_image.png
│   └── svg/policy_icon.svg
└── translations/
    └── English/
        ├── policies.csv
        ├── simulation.csv
        ├── situations.csv
        ├── sliders.csv
        └── events.csv
```

Only include folders/files relevant to what the mod adds.

# Step-by-Step Instructions

## 1. config.txt (required in every mod)

```ini
[config]
name = my_mod_name
path = C:\Users\YourName\Documents/My Games/democracy4/mods/my_mod_name
guiname = My Mod Display Name
author = YourName
description = What this mod does.
version = 1
```

`name` must have no spaces. `guiname` is what players see.

## 2. Adding a Policy (policies.csv)

Each row starting with `#` is a policy. Columns in order:

```
#, name, slider, flags, opposites, introduce, cancel, raise, lower, department, prereqs, mincost, maxcost, costfunction, cost multiplier, implementation, minincome, maxincome, incomefunction, incomemultiplier, nationalisation GDP percentage, ..., #Effects, "Target,equation,inertia", ...
```

**Minimal example:**
```
#,MyNewPolicy,default,,,30,30,15,10,ECONOMY,,0,50,0+(1.0*x),,2,0,0,0+(1.0*x),,,,#Effects,"GDP,0.02+(0.03*x),4","Capitalist,0.05-(0.10*x),6"
```

**Key columns:**
- `slider` — `default` for continuous 0–1, or a name from `sliders.csv` for discrete options.
- `flags` — `UNCANCELLABLE` (always active), `MULTIPLYINCOME` (multiply income inputs).
- `department` — `ECONOMY`, `FOREIGNPOLICY`, `LAWANDORDER`, `PUBLICSERVICES`, `WELFARE`, `TRANSPORT`, `TECHNOLOGY`, `HEALTH`, `EDUCATION`, `ENVIRONMENT`, `AGRICULTURE`, `TAX`.
- `prereqs` — flags from `prereqs.txt` that must be true (e.g. `_prereq_has_coast`).
- `implementation` — turns to fully implement; adjusted by minister competence.
- `costmultiplier` — colon-separated list of inputs that multiply the final cost. Format: `_default_,1.0;SomeSimValue,0.5+(0.5*x)`. Each entry is either `_default_,value` (fixed base multiplier) or a normal effect equation. Multiple entries are **added** together (or multiplied if `MULTIPLYINCOME` flag is set).
- `nationalisationGDPpercentage` — percentage of current GDP credited to the player when this policy is cancelled (privatisation) or debited when introduced (nationalisation). Leave blank for most policies.
- `#Effects` — marker; everything to the right is an output effect.

**Translation entry** (`translations/English/policies.csv`):
```
#,MyNewPolicy,Display Name,"Full description shown to the player."
```

## 3. Adding a Simulation Value (simulation.csv)

Blue circular nodes. Columns: `#, name, zone, def, min, max, emotion, icon, #[inputs], #[outputs]`

```
#,MyCostOfLiving,ECONOMY,0.4,0,1,HIGHBAD,cost_of_living,#,"Inflation,0+(0.5*x),8","FoodPrices,0+(0.3*x),4",#,"PovertyRate,0+(0.4*x),6"
```

- `zone` — `ECONOMY`, `FOREIGNPOLICY`, `LAWANDORDER`, `PUBLICSERVICES`, `WELFARE`, `TRANSPORT`, `TECHNOLOGY`, `HEALTH`, `EDUCATION`, `ENVIRONMENT`, `AGRICULTURE`, `NOICON` (hidden from UI).
- `emotion` (goodbad) — `HIGHGOOD` (rising = good), `HIGHBAD` (rising = bad), or blank for neutral axis values. Never use `UNKNOWN`.
- `icon` — SVG filename (no path) from `data/svg/`.
- First `#` = start of inputs; second `#` = start of outputs.

**Translation entry** (`translations/English/simulation.csv`):
```
#,MyCostOfLiving,Cost of Living,hidden
```
Omit `hidden` if you want the name visible in the UI.

## 4. Adding a Situation (situations.csv)

Orange/green banner nodes triggered by threshold. Columns:

```
#, name, department, prereqs, icon, positive, starttrigger, stoptrigger, mincost, maxcost, costfunction, minincome, maxincome, incomefunction, #[inputs], #[outputs]
```

```
#,MyHousingCrisis,WELFARE,,housing_crisis,0,,0.65,0.35,50,100,0+(1.0*x),0,0,0+(1.0*x),#,"_default_,0.9+(0*x)","HousingSubsidies,0-(0.6*x),6",#,"PovertyRate,0+(0.3*x),4"
```

- `positive` — `1` = green (good), `0` = red (bad).
- `starttrigger` / `stoptrigger` — values at which the situation activates/deactivates.

## 5. Adding an Event (data/simulation/events/MyEvent.txt)

```ini
[config]
Name = MyEventName
Texture = myevent.png
GUISound = DM4_Mass Sentencing.wav
OnImplement = CreateGrudge(GDP,-0.05,0.95);CreateGrudge(Unemployment,0.08,0.92);CreateGrudge(MyEventName,-0.9,0.83);

[influences]
0 = _default_,0.5+(0*x)
1 = _random_,0,0.3
2 = Unemployment,0.4-(0.3*x)
```

- `OnImplement` — semicolon-separated `CreateGrudge(Target, value, decay)` calls.
- **Always add a self-grudge** (`CreateGrudge(MyEventName,-0.9,0.83)`) to prevent immediate re-triggering.
- Evaluated every 3 turns; triggers if score > 70%.
- `_random_,min,max` adds random variation to trigger probability.
- Inertia is **not** used in `[influences]`.

**Translation entry** (`translations/English/events.csv`):
```
#,MyEventName,Display Title,"Body text shown to the player."
```

## 6. Adding a Dilemma (data/simulation/dilemmas/MyDilemma.txt)

```ini
[dilemma]
name = MyDilemmaName

[influences]
0 = _random_,0,0.3
1 = Health,0.8-(0.6*x)

[option0]
OnImplement = CreateGrudge(Health,0.05,0.92);CreateGrudge(Capitalist,-0.04,0.90);

[option1]
OnImplement = CreateGrudge(GDP,0.04,0.92);CreateGrudge(Health,-0.03,0.90);
```

- 2 or 3 options (`[option0]`, `[option1]`, optionally `[option2]`).
- Won't re-trigger for 32 turns after firing.
- **Add a self-grudge** to prevent immediate re-triggering: `CreateGrudge(MyDilemmaName,-0.9,0.83)` in each option's `OnImplement`.

## 7. Adding a Country (data/missions/countrycode/)

Countries are folders under `data/missions/`. The folder name is the short country code (e.g. `fra`, `usa`). Inside:

```
data/missions/mycountry/
├── mycountry.txt      ← main country file (UTF-8!)
├── overrides/         ← sim tweaks specific to this country
└── scripts/           ← startup CreateGrudge scripts
```

**mycountry.txt structure:**
```ini
[config]
name = My Country
flag = mycountry          ; bitmap filename (no extension)
background = mycountry_bg
gdp = 28000
population = 50
currencysymbol = $
currencyprefix = 1

[options]
MULTIPLEPARTIES = 1
COMPULSORY_VOTING = 0

[stats]
GDP = 0.62
Unemployment = 0.18
Health = 0.55

[policies]
labourlaws = 0.5
incomeTax = 0.44
_prereq_has_coast = 1
```

- `[stats]` — initial sim values (0.0–1.0).
- `[policies]` — starting policies and their slider values. Also sets prereq flags (value `1` = true, `0` = false).
- `[options]` — `MULTIPLEPARTIES`, `COMPULSORY_VOTING`, etc.
- Country `.txt` **must be saved in UTF-8** to support currency symbols (€, £, etc.).
- `scripts/` runs `CreateGrudge` calls at game start (voter group composition tweaks, initial boosts).
- `overrides/` files use the same `[override]` format as mod overrides — applied only for this country.

## 8. Custom Pre-Requisites (data/simulation/prereqs.txt)

To add your own prereq flags (usable in policy/situation/dilemma `prereqs` fields):

```
100 = _prereq_my_custom_condition
101 = _prereq_my_other_condition
```

The numbers must not clash with vanilla `prereqs.txt` values. Set them to `1` or `0` in each country file under `[policies]`.

## 9. Patching an Existing Connection (overrides/*.ini)

To modify a vanilla or other mod's connection without editing their files:

```ini
[override]
TargetName = "CorporateExodus"
HostName = "LabourLaws"
Equation = "0+(0.4*x)"
Inertia = 8
```

Filename is for organisation only — only the file contents matter.

## 10. Custom Slider (sliders.csv)

```
#,myslidername,DISCRETE,0
```

Translation labels (`translations/English/sliders.csv`):
```
#,myslidername,None,Low,Medium,High,Maximum
```

# Effect Equation Syntax

Format: `TargetName, equation, inertia`

- `x` = current value of the source object (0.0–1.0); for policies, `x` = slider position.
- Operators: `+` `-` `*` `/` `^` (power).
- Reference other sim values by name directly in the equation.

```
GDP, 0.02+(0.03*x), 4                      ← linear boost
Unemployment, 0-(0.3*x), 6                 ← linear reduction
Education, 0.04+((0.04*x)*Technology), 4   ← scaled by another sim
Crime, -0.02+(0.05*x)^1.5, 8              ← non-linear curve
```

**Inertia guide:**
- `1–2` = instant (UI sliders, toggles)
- `4–6` = moderate lag (most policies)
- `8–12` = slow structural change (GDP, demographics)

**Special sources:**

| Name | Meaning |
|---|---|
| `_default_` | Fixed base value |
| `_random_,min,max` | Random value each turn |
| `_inv_SimName` | `1 - SimValue` |
| `_global_socialism` | Aggregate socialism across all policies |
| `_global_capitalism` | Aggregate capitalism across all policies |

**Voter group targeting:**
- `GroupName` — affects happiness of that group.
- `GroupName_freq` — affects membership size of that group.

Common groups: `Capitalist`, `Socialist`, `Liberal`, `Conservative`, `Religious`, `Ethnic`, `Retired`, `Commuter`, `Farmer`, `TradeUnionist`, `Patriot`, `SelfEmployed`, `Parents`, `Youth`, `Poor`, `Middle`, `Wealthy`.

# Best Practices

- All values stay between `0.0` and `1.0`.
- Internal names: no spaces, unique across all mods, case-sensitive.
- Save CSV files as **CSV only** — never let Excel change the format.
- Use a text editor (Notepad++, VS Code) for `.txt` and `.ini` files.
- Visualise equations at [desmos.com/calculator](https://www.desmos.com/calculator) before using them.
- Always add a translation entry for every new object — missing translations cause display bugs.
- Use `NOICON` zone for intermediate sim values players don't need to see.
- Prefer overrides over editing vanilla files directly.

# Validation Checklist

**Format**
- [ ] Every data row starts with `#` in column A.
- [ ] Internal names have no spaces, no hyphens, and are unique across all mods.
- [ ] Every new object has a matching entry in `translations/English/`.
- [ ] SVG icons are in `data/svg/`, PNG images in `data/bitmaps/`.
- [ ] Events have a self-grudge in `OnImplement` to prevent re-triggering.
- [ ] CSV files saved in CSV format (not XLSX).
- [ ] `config.txt` exists with valid `name`, `path`, `guiname`, `author`, `description`, `version`.
- [ ] Country `.txt` files saved in **UTF-8** format.
- [ ] Custom prereq numbers in `prereqs.txt` don't clash with vanilla values (use 100+).
- [ ] Balanced parentheses in all equations.
- [ ] No `1/x` division pattern without an offset (causes divide-by-zero when sim=0).

**Balance**
- [ ] Policy `maxcost` ≤ 18,000 (vanilla max); typical range 100–5,000.
- [ ] Policy `mincost` in [−1,000, 5,100] and `mincost` ≤ `maxcost`.
- [ ] Policy `cancel` ≤ 60; 0 if `UNCANCELLABLE` flag is set.
- [ ] Policy `raise` ≤ 54; `lower` ≤ 70; `implementation` ≤ 50 (vanilla maxima).
- [ ] `MULTIPLYINCOME` flag → `maxincome` must be > 0.
- [ ] `cancel = 0` only when `UNCANCELLABLE`, or intentional; `raise`/`lower` = 0 only for toggle laws.
- [ ] Sim value defaults in [0.0, 1.0]; `HIGHBAD` defaults ≤ 0.85 (not at 1.0 — that means already at worst).
- [ ] Sim/voter effect coefficients ≤ 1.0 per term. Exception: axis patterns `-1+(2*x)` or `1-(2*x)` are vanilla-standard (coeff=2 allowed for full-range axis effects).
- [ ] Income formula coefficients are monetary amounts — they can be large; do not confuse with sim-effect coefficients.
- [ ] `opposites` field only names policies that actually exist.
- [ ] Policy `department` is one of the valid dept names (not `ENERGY`, `INDUSTRY`, `FOREIGN`, `SECURITY`).
- [ ] Sim value `zone` uses `NOICON`, not `HIDDEN`.
- [ ] `goodbad` (emotion) is `HIGHGOOD`, `HIGHBAD`, or blank — never `UNKNOWN`.

**Testing**
- [ ] Mod enabled in-game and tested on a **new game** (not an existing save).

# Troubleshooting

## Issue: Mod content not appearing in-game

**Check:** `Documents\My Games\Democracy4\debug.txt` for load errors.
**Common causes:**
- Row missing the leading `#`.
- CSV saved in wrong format (XLSX instead of CSV).
- Internal name contains a space.
- Missing translation entry causing a silent skip.

## Issue: Event never triggers

**Check:** Influences sum — the total must be able to exceed 0.7 (70%) for the event to fire.
**Fix:** Add `0 = _default_,0.5+(0*x)` as a base influence, or increase other influence values.

## Issue: Situation never activates

**Check:** `starttrigger` value — inputs must push the situation's value above this threshold.
**Fix:** Lower `starttrigger`, or strengthen the input equations feeding the situation.

## Issue: Game crashes on load

**Common causes:**
- Referencing a sim/policy name that doesn't exist yet.
- Malformed equation (unmatched parentheses).
- Non-UTF8 characters in a country `.txt` file.

# Supporting Files

- See `./democracy4-mod-reference.md` for the complete column-by-column reference of all CSV formats and quick lookup tables.
- See `./complete-modding-guide.md` for the comprehensive modding guide with detailed explanations and examples.

## Related Skills

- **skill-builder** — for creating or editing AI agent skills like this one.

Remember: All simulation values stay between 0.0 and 1.0!
