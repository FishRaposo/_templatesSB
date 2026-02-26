# Democracy 4 Modding Reference

> Complete reference for Democracy 4 mod file formats and structure.

---

## CSV Column References

### Policies (policies.csv)

| Column | Name | Description | Example |
|---|---|---|---|
| A | `#` | Row marker — must be `#` to be loaded | `#` |
| B | `name` | Internal object name (no spaces) | `MySalesTax` |
| C | `slider` | Slider type: `default` or name from `sliders.csv` | `default` |
| D | `flags` | `UNCANCELLABLE`, `MULTIPLYINCOME`, or blank | `UNCANCELLABLE` |
| E | `opposites` | Comma-separated conflicting policies | `FlatTax,ProgressiveTax` |
| F | `introduce` | Political capital to introduce | `30` |
| G | `cancel` | Political capital to cancel | `30` |
| H | `raise` | Political capital to raise slider | `15` |
| I | `lower` | Political capital to lower slider | `10` |
| J | `department` | Zone/minister | `ECONOMY` |
| K | `prereqs` | Required flags from `prereqs.txt` | `_prereq_has_coast` |
| L | `mincost` | Cost at slider=0 | `0` |
| M | `maxcost` | Cost at slider=1 | `80` |
| N | `costfunction` | Cost equation | `0+(1.0*x)` |
| O | `cost multiplier` | Semicolon-separated scaling inputs | `_default_,1.0;GDP,0+(0.5*x)` |
| P | `implementation` | Turns to fully implement | `2` |
| Q | `minincome` | Income at slider=0 | `0` |
| R | `maxincome` | Income at slider=1 | `200` |
| S | `incomefunction` | Income equation | `0+(1.0*x)` |
| T | `incomemultiplier` | Income scaling inputs | `Technology,0+(0.2*x)` |
| U | `nationalisation GDP percentage` | % of GDP for privatisation/nationalisation | `0.05` |
| — | `#Effects` | Marker column | `#Effects` |
| … | Effects | `Target,equation,inertia` (one per cell) | `"GDP,0.02+(0.03*x),4"` |

**Valid Policy Departments:** `ECONOMY`, `FOREIGNPOLICY`, `LAWANDORDER`, `PUBLICSERVICES`, `WELFARE`, `TRANSPORT`, `TECHNOLOGY`, `HEALTH`, `EDUCATION`, `ENVIRONMENT`, `AGRICULTURE`, `TAX`

> ❌ Do **not** use: `FOREIGN`, `SECURITY`, `ENERGY`, `INDUSTRY`, `DEFENCE`

### Simulation Values (simulation.csv)

| Column | Name | Description | Example |
|---|---|---|---|
| A | `#` | Row marker | `#` |
| B | `name` | Internal object name | `MyCostOfLiving` |
| C | `zone` | Display area | `ECONOMY` |
| D | `def` | Default value (0–1) | `0.4` |
| E | `min` | Minimum value | `0` |
| F | `max` | Maximum value | `1` |
| G | `emotion` | Graph coloring (`HIGHGOOD`/`HIGHBAD`/blank) | `HIGHBAD` |
| H | `icon` | SVG filename | `cost_of_living.svg` |
| — | `#` (inputs) | Start of inputs | `#` |
| … | Inputs | Effects feeding INTO this value | `"Inflation,0+(0.5*x),8"` |
| — | `#` (outputs) | Start of outputs | `#` |
| … | Outputs | Effects FROM this value | `"PovertyRate,0+(0.4*x),6"` |

**Valid Sim Value Zones:** `ECONOMY`, `FOREIGNPOLICY`, `LAWANDORDER`, `PUBLICSERVICES`, `WELFARE`, `TRANSPORT`, `TECHNOLOGY`, `HEALTH`, `EDUCATION`, `ENVIRONMENT`, `AGRICULTURE`, `NOICON` (hidden from UI)

> ❌ Do **not** use: `HIDDEN` (use `NOICON` instead), `INDUSTRY`, `ENERGY`

**Valid goodbad (emotion) values:** `HIGHGOOD` (higher = better), `HIGHBAD` (higher = worse), blank (neutral axis)

> ❌ Do **not** use: `LOWGOOD`, `UNKNOWN`

### Situations (situations.csv)

| Column | Name | Description | Example |
|---|---|---|---|
| A | `#` | Row marker | `#` |
| B | `name` | Internal object name | `MyHousingCrisis` |
| C | `department` | Display zone | `WELFARE` |
| D | `prereqs` | Required flags | `_prereq_has_coast` |
| E | `icon` | SVG filename | `housing_crisis.svg` |
| F | `positive` | `1`=green, `0`=red | `0` |
| G | `starttrigger` | Value to activate | `0.65` |
| H | `stoptrigger` | Value to deactivate | `0.35` |
| I | `mincost` | Cost per turn | `50` |
| J | `maxcost` | Cost per turn | `100` |
| K | `costfunction` | Cost equation | `0+(1.0*x)` |
| L | `minincome` | Income per turn | `0` |
| M | `maxincome` | Income per turn | `0` |
| N | `incomefunction` | Income equation | `0+(1.0*x)` |
| — | `#` (inputs) | Start of inputs | `#` |
| … | Inputs | Effects feeding the situation | `"HousingSubsidies,0-(0.6*x),6"` |
| — | `#` (outputs) | Start of outputs | `#` |
| … | Outputs | Effects while active | `"PovertyRate,0+(0.3*x),4"` |

### Sliders (sliders.csv)

```
#,slidername,DISCRETE|CONTINUOUS,default_position
```

- `DISCRETE` — snaps to fixed positions
- `CONTINUOUS` — smooth slider (same as `default`)

### Translation Files

All translation files follow the pattern: `#,InternalName,Display Name,"Description or label"`

**policies.csv:** `#,MyPolicy,Display Name,"Full description"`

**simulation.csv:** `#,MySim,Display Name,hidden` (optional `hidden` flag)

**situations.csv:** `#,MySituation,Display Name,"Description"`

**sliders.csv:** `#,myslidername,Label0,Label0.25,Label0.5,Label0.75,Label1.0`

**events.csv:** `#,MyEvent,Display Title,"Body text shown to player"`

---

## File Formats

### Events (events/*.txt)

```ini
[config]
Name = MyEventName
Texture = myevent.png
GUISound = DM4_Mass Sentencing.wav
OnImplement = CreateGrudge(Target1,value1,decay1);CreateGrudge(Target2,value2,decay2);

[influences]
0 = _default_,base_value
1 = _random_,min,max
2 = SimName,equation
3 = AnotherSim,equation
```

### Dilemmas (dilemmas/*.txt)

```ini
[dilemma]
name = MyDilemmaName

[influences]
0 = _random_,min,max
1 = SimName,equation

[option0]
OnImplement = CreateGrudge(Target,value,decay);

[option1]
OnImplement = CreateGrudge(Target,value,decay);

[option2]  <!-- optional third option -->
OnImplement = CreateGrudge(Target,value,decay);
```

### Overrides (overrides/*.ini)

```ini
[override]
TargetName = "TargetObjectName"
HostName = "SourceObjectName"
Equation = "0+(0.4*x)"
Inertia = 8
```

### Countries (data/missions/country/country.txt)

> **Must be saved in UTF-8** to preserve currency symbols (€, £, ¥, etc.).

**[config] section:**
```
name = CountryName
flag = flag.png
anthem = anthem.wav
jobtitle = President
population = "50.0 million (2020)"
area = "500,000 km2"
currency = "Dollar (USD)"
gdp = "$2.0 trillion (~USD4000)"
```

**[options] section:**
```
MULTIPLEPARTIES = 1
COMPULSORY_VOTING = 0
```

**[stats] section:** Initial sim values (0.0–1.0). e.g. `GDP = 0.62`, `Unemployment = 0.18`.

**[policies] section:** Starting policies and their slider values. Also sets prereq flags.
```
PolicyName = 0.65
_prereq_has_coast = 1
```

**overrides/ folder:** Per-country `[override]` files — same format as mod overrides, applied only for this country.

**scripts/ folder:** Text files with `CreateGrudge()` calls run at game start. Used to adjust voter group compositions, add initial boosts, etc.

---

## Effect Equation Patterns

### Common Patterns

| Pattern | Use Case | Example |
|---|---|---|
| `0+(a*x)` | Linear boost | `0+(0.05*x)` |
| `0-(a*x)` | Linear reduction | `0-(0.3*x)` |
| `b+(a*x)` | Offset linear | `0.02+(0.03*x)` |
| `b+(a*x)^n` | Non-linear curve | `-0.02+(0.05*x)^1.5` |
| `b+(a*x)*OtherSim` | Scaled by another sim | `0.04+((0.04*x)*Technology)` |
| `b*(1-x)` | Inverse relationship | `0.5*(1-x)` |

### Inertia Values

| Inertia | Effect Duration | Use Case |
|---|---|---|
| 1–2 | Instant | UI feedback, toggles |
| 4–6 | Moderate | Most policies, economic effects |
| 8–12 | Slow | GDP, demographics, structural changes |
| 16+ | Very slow | Cultural shifts, long-term trends |

---

## Voter Groups

| Group | Typical Interests |
|---|---|
| Poor | Welfare, unemployment benefits, progressive taxes |
| Middle | Balanced policies, moderate taxes |
| Wealthy | Low taxes, business-friendly policies |
| Capitalist | Free markets, privatization |
| Socialist | State intervention, nationalization |
| Liberal | Civil liberties, social progress |
| Conservative | Traditional values, law and order |
| Religious | Religious freedom, moral policies |
| Ethnic | Anti-discrimination, minority rights |
| Retired | Pensions, healthcare |
| Commuter | Transport infrastructure |
| Farmer | Agricultural subsidies |
| TradeUnionist | Workers' rights, unions |
| Patriot | National strength, defense |
| SelfEmployed | Small business support |
| Parents | Childcare, education |
| Youth | Education, future opportunities |

---

## Pre-Requisite Flags

Built-in flags (add your own in mod's `data/simulation/prereqs.txt`, numbered from 100+ to avoid clashes):

```
_prereq_has_coast          # Country has coastline
_prereq_mining_industry    # Has mining industry
_prereq_royal_family       # Has monarchy
_prereq_land_border        # Has land borders
_prereq_deadly_animals     # Dangerous wildlife
_prereq_preindustrialized  # Pre-industrial economy
```

---

## Debugging Checklist

1. **Check `debug.txt`** in `Documents\My Games\Democracy4\`
2. **Verify CSV format** — must be actual CSV, not XLSX
3. **Check for leading `#`** on all data rows
4. **Verify internal names** — no spaces, unique
5. **Check translations** — every object needs a translation entry
6. **Test on new game** — mods don't apply to existing saves
7. **Check file paths** — use forward slashes in paths
8. **Verify equation syntax** — balanced parentheses, valid operators

---

## Quick Reference Summary

```
Config:   config.txt
Policies: data/simulation/policies.csv
Sims:     data/simulation/simulation.csv
Situations: data/simulation/situations.csv
Sliders:  data/simulation/sliders.csv
Events:   data/simulation/events/Name.txt
Dilemmas: data/simulation/dilemmas/Name.txt
Overrides: data/overrides/Name.ini
Graphics: data/svg/*.svg, data/bitmaps/*.png
Translations: translations/English/*.csv
Countries: data/missions/<name>/<name>.txt
```

Remember: All values stay between 0.0 and 1.0 in the simulation!

---

## Vanilla Balance Reference

Use these thresholds to keep mod content balanced with the base game. All values are **measured from the vanilla Democracy 4 `policies.csv` and `simulation.csv`** (270 policies, 76 declared sim values). Values outside these ranges will feel broken or exploitable.

### Policy Numeric Thresholds

| Field | Vanilla p50 | Vanilla p95 | Vanilla max | Notes |
|---|---|---|---|---|
| `maxcost` | 23 | 2,250 | **18,000** | Most policies 100–5,000. Landmark reforms up to 18,000. |
| `mincost` | 5 | 250 | 5,100 | Can be negative (min −1,000). Must be ≤ `maxcost`. |
| `cancel` | 14 | 45 | **60** | Must be **0** if `UNCANCELLABLE` flag is set. |
| `raise` | 14 | 36 | **54** | Political cost to move slider up. |
| `lower` | 8 | 32 | **70** | Political cost to move slider down. |
| `implementation` | 9 | 25 | **50** | 0 for instant toggle laws. Most policies 2–15. |
| `maxincome` | — | — | — | Must be > 0 if `MULTIPLYINCOME` flag is set. |
| `minincome` | 0 | — | `maxincome` | Never greater than `maxincome`. |

### Policy Flags Constraints

| Flag | Constraint |
|---|---|
| `UNCANCELLABLE` | `cancel` must be `0` |
| `MULTIPLYINCOME` | `maxincome` must be > 0 |
| `intro = 0` | Only valid when `maxcost = 0` (free toggle law) |

### Simulation Value Constraints

| Field | Constraint |
|---|---|
| `def` (default) | Must be in [0.0, 1.0] |
| `min` | Always `0` |
| `max` | Always `1` |
| `HIGHBAD` default | 0.1 – 0.85 (not 1.0; that means already at absolute worst on game start) |
| `HIGHGOOD` default | Can be 0.0 for things that don't exist at start (e.g. space programs) |
| `goodbad` | `HIGHGOOD`, `HIGHBAD`, or blank — never `UNKNOWN` or `LOWGOOD` |

### Effect Coefficient Magnitudes

All figures measured from vanilla. Policy income formula coefficients are **monetary amounts** and are intentionally large — do not confuse them with sim-effect coefficients.

| Type | Vanilla p50 | Vanilla p95 | Vanilla max | Notes |
|---|---|---|---|---|
| Sim-value effect | 0.15 | 0.60 | **1.0** | Voter happiness, GDP, etc. |
| Axis full-range pattern | — | — | **2.0** | `-1+(2*x)` or `1-(2*x)` — vanilla-standard for ideological axes going from −1 to +1 |
| Income formula coefficient | — | — | 18,000+ | These are monetary multipliers, not sim effects — large values are correct |

> **Rule of thumb:** if a coefficient appears inside a named-target effect like `"GDP,0+(0.15*x)"`, keep it ≤ 1.0. If it is a full-range axis effect using the `-1+(2*x)` pattern, coeff=2 is vanilla-standard and correct.

### Equation Safety Rules

- **No `1/x` without offset.** `1-(1/x)` → divide-by-zero when x=0. Replace with `1-(2*x)` or similar linear form.
- **Balanced parentheses.** Count `(` and `)` — they must be equal.
- **No hyphenated names.** `Antibiotics-ResistantBacteria` is invalid. Use camelCase or underscores.
- **No x^0 exponent.** `x^0 = 1` always — replace with a constant.

### Situation Trigger Values

| Field | Rule |
|---|---|
| `starttrigger` | Must be > `stoptrigger` |
| Negative situation | Typical range: `starttrigger` 0.5–0.8, `stoptrigger` 0.2–0.5 |
| Positive situation | Typical range: `starttrigger` 0.4–0.7, `stoptrigger` 0.2–0.4 |

### Cross-Reference Rules

- **`opposites`** — must reference policy names that actually exist in vanilla or the mod.
- **Effect targets** — sim values, policies, situations referenced in equations must exist.
- **Slider refs** — any `slider` name other than `default` must be defined in `sliders.csv` (mod or vanilla).
- **Situation prereqs** — must be a valid flag from `prereqs.txt` or a known built-in `_prereq_` token.

### Valid Department / Zone Quick Reference

```
For policies AND situations:
  ECONOMY        FOREIGNPOLICY    LAWANDORDER    PUBLICSERVICES
  WELFARE        TRANSPORT        TECHNOLOGY     HEALTH
  EDUCATION      ENVIRONMENT      AGRICULTURE    TAX

For sim values (zone field):
  Same list above, plus NOICON (hidden from UI)
  Use NOICON for internal tracking values the player doesn't need to see.
```

### Common Balance Mistakes

| Mistake | Fix |
|---|---|
| `dept = ENERGY` or `INDUSTRY` | → `ECONOMY` |
| `dept = FOREIGN` or `SECURITY` | → `FOREIGNPOLICY` or `LAWANDORDER` |
| `zone = HIDDEN` on sim value | → `NOICON` |
| `goodbad = UNKNOWN` | → `HIGHGOOD`, `HIGHBAD`, or blank |
| `UNCANCELLABLE` + `cancel > 0` | → Set `cancel = 0` |
| `MULTIPLYINCOME` + `maxincome = 0` | → Set `maxincome` or remove flag |
| Sim default > 1.0 | → Clamp to [0.0, 1.0] |
| `HIGHBAD` sim default = 1.0 | → Set to 0.3–0.5 |
| Effect coeff > 5.0 | → Scale down |
| `1/x` in equation | → Replace with linear approximation |
| Hyphen in internal name | → Use camelCase or underscore |
| Empty `opposites` pointing to deleted policy | → Clear the field |
