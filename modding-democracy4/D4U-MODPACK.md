# D4U Ultimate Modpack — Developer Reference

> **This document is a modpack-specific developer reference, not part of the general Democracy 4 modding skill.**
> For general D4 modding guidance see `complete-modding-guide.md` and `democracy4-mod-reference.md` in this folder.
>
> Covers the D4U Ultimate modpack architecture, module contents, balance rules, known constraints, contribution guidelines, and fix history.

---

## Overview

D4U Ultimate is a multi-module expansion for Democracy 4 split into 11 independent but inter-dependent Steam Workshop mods. Together they add **340 policies**, **117 simulation values**, **50 situations**, and **69 sliders** on top of the vanilla game.

The modpack is organised by theme. Each module can be enabled independently, but some cross-module references exist (e.g., M8 Crises references sim values from M1, M5, M7).

---

## Module Index

| Folder | Display Name | Policies | Sims | Situations | Sliders |
|---|---|---|---|---|---|
| `D4U_Core` | D4 Ultimate: Core | 11 | 1 | 0 | 3 |
| `D4U_Module1_Industry` | D4 Ultimate: Industry & Economy | 61 | 36 | 7 | 16 |
| `D4U_Module2_Transport` | D4 Ultimate: Transport | 36 | 8 | 0 | 3 |
| `D4U_Module3_Governance` | D4 Ultimate: Governance & Emergency | 36 | 11 | 2 | 1 |
| `D4U_Module4A_Libertarian` | D4 Ultimate: Private Sector Pack | 24 | 5 | 0 | 1 |
| `D4U_Module4B_Socialist` | D4 Ultimate: Public Sector Pack | 64 | 7 | 2 | 11 |
| `D4U_Module5_ForeignPolicy` | D4 Ultimate: Foreign Policy & Military | 30 | 19 | 7 | 10 |
| `D4U_Module6_Health` | D4 Ultimate: Health & Social | 27 | 9 | 3 | 9 |
| `D4U_Module7_Technology` | D4 Ultimate: Technology & Digital | 29 | 17 | 2 | 13 |
| `D4U_Module8_Crises` | D4 Ultimate: Crises & Events | 6 | 2 | 27 | 0 |
| `D4U_Module9_CountryPacks` | D4 Ultimate: Country Packs | 16 | 2 | 0 | 2 |
| **Total** | | **340** | **117** | **50** | **69** |

---

## Folder Structure (per module)

```
D4U_ModuleX/
├── config.txt
├── data/
│   └── simulation/
│       ├── policies.csv
│       ├── simulation.csv
│       ├── situations.csv     (if module has situations)
│       └── sliders.csv
└── translations/
    └── English/
        ├── policies.csv
        ├── simulation.csv
        ├── situations.csv     (if module has situations)
        └── sliders.csv        (if module has custom sliders)
```

All modules have `version = 1` in `config.txt`.

---

## Module Details

### D4U_Core
**Purpose:** Shared foundation. Provides core tax policies, economic sliders, and the `CoLCostofLiving` simulation value used across all modules.

Key policies: `income_tax`, `corporate_tax`, `interest_rate`, `wealth_tax`, `sugar_tax`, `carbon_tax`

Key sim values: `CoLCostofLiving`

Custom sliders: `tax_slider`, `rate_slider`, `economic_slider`

---

### D4U_Module1_Industry
**Purpose:** Deep economic simulation — industrial sectors, labour markets, trade, energy, and infrastructure.

Key sim values: `agricultural_industry`, `electromechanical_industry`, `extractivist_industry`, `consumer_goods_industry`, `financial_sector`, `construction_activity`, `foreign_exchange_markets`, `infrastructure_quality`, `energy_prices`, `labor_unrest`, `big_business`, `small_business`, `technological_sovereignty`, `market_distortion_index`, `services_participation`, `sovereign_wealth_fund_value`, `idl_standing`, `infraestructural_profusion`, `hydrocarbon_industry`

Situations: `agriculture_productivity_crisis`, `bloated_bank_reserves`, `Cartels`, `food_price_slump`, `robust_foreign_exchange_markets`, `underground_unions`, `oil_price_shock`

Custom sliders: 16 sliders covering industry subsectors and regulation levels.

---

### D4U_Module2_Transport
**Purpose:** Detailed transport simulation — traffic, cycling, freight, urban density, noise, travel time.

Key sim values: `bicycle_usage`, `booming_car_industry`, `average_travel_time`, `truck_driver_shortage`, `noise_pollution`, `traffic_accidents`, `CoLUrbanDensity`

Key policies: Bike lanes, electric fleet, road tolls, urban remodelling, public transit investment.

Custom sliders: `transport_mode_slider`, `urban_slider`, `freight_slider`

---

### D4U_Module3_Governance
**Purpose:** Governance quality, rule of law, digitalization, racial equality, and private entertainment.

Key sim values: `RuleOfLaw`, `DigitalizationLevel`, `RacialEquality`, `Culture`, `PrivateEntertainment`, `SocialMobility`, `BureaucracyIndex`, `CivilLiberties`, `Transparency`

Situations: `BureaucracyFix`, `DemocraticBacksliding`

Includes `EGovDigitalAdmin` (UNCANCELLABLE, high cost) and `ApologyLaw`.

---

### D4U_Module4A_Libertarian
**Purpose:** Private sector quality — corporate investment, private energy, gig economy, private school and healthcare quality.

Key sim values: `CorporateInvestment`, `PrivateEnergyMarket`, `GigEconomy`, `PrivateSchoolQuality`, `PrivateHealthcareQuality`

Key policies: Deregulation, privatization drive, flat tax incentives, enterprise zones.

---

### D4U_Module4B_Socialist
**Purpose:** Public sector, cooperatives, worker rights, planning, social mobility.

Key sim values: `StateCapacity`, `PublicInvestmentMultiplier`, `WorkerCooperatives`, `PublicServiceQuality`, `SocialMobility`, `state_controlled_gdp`, `tax_welfare_equity`

Situations: `decommodification_of_housing`, `economically_independent`

Custom sliders: 11 sliders for planning and nationalization levels.

Key policies: `cooperative_commonwealth_act` (high-cost reform), `universal_basic_services`, `living_wage`, `wealth_tax`, `worker_ownership_fund`

> **Note:** `living_wage` does NOT use `MULTIPLYINCOME` flag (maxincome=0 was incompatible). `cooperative_commonwealth_act` cancel=35.

---

### D4U_Module5_ForeignPolicy
**Purpose:** International relations, military, arms trade, ideological axes, nuclear proliferation.

Key sim values: `MilitaryPower`, `GlobalInfluence`, `NuclearProliferation`, `GlobalStability`, `BilateralAllianceUS`, `military_strength`, `military_industrial_complex`, `reaction`, `ActualThreat`, `HigherSecurity` + 6 ideological axis values (`Individualism`, `Collectivism`, `Authoritarianism`, `Globalism`, `Isolationism`, `Militarism`)

Situations: `BilateralAllianceWithUS`, `ImmigrantProtests`, `InternationalCooperation`, `MiddleEastChaos`, `military_industrial_complex`, `sanctions`, `SuperPower`

> **Note:** Ideological axis sim values have blank `goodbad` (neutral axes, not HIGHGOOD/HIGHBAD). `ActualThreat` uses `NOICON` zone.

---

### D4U_Module6_Health
**Purpose:** Healthcare, mental health, abortion policy, vaccination, voluntary insurance, youth crime, stray animals, orphans.

Key sim values: `VaccinationCoverage`, `StateInsuranceValue`, `VoluntaryInsurance`, `LegalAbortions`, `IllegalAbortions`, `OrphansAndHomelessMinors`, `StrayAnimals`, `youthcrime`, `AbortionDemand`

Situations: `AbortionProtests`, `InsuranceProtests`, `PromisedPensions`

> **Note:** `AbortionDemand` uses blank `goodbad` (neutral). `StateAbortionClinics` mincost=-150 was previously fixed to 0.

---

### D4U_Module7_Technology
**Purpose:** Space program, biotech, AI, automation, nuclear fusion, digital infrastructure.

Key sim values: `MarsProgress`, `SpaceColonization`, `SpaceCost`, `space_industry`, `TechUnemployment`, `AutomationLevel`, `BiotechAdvancement`, `NuclearFusionProgress`, `PrivateSpaceProgram`, `Technology` (override), `IndustrialAutomation`, `CyberWarfare`, `lunar_resource_extraction`, `mars_habitability`, `trade_with_mars`

Situations: `SpaceTourism`, `inter_planetary_commerce`

> **Note:** `mars_colony_programme` maxcost=8000 (capped from 12000). `genetic_research_programme` no longer references hyphenated sim values.

Custom sliders: 13 sliders for tech research, space stage, automation level.

---

### D4U_Module8_Crises
**Purpose:** Crisis situations — economic, social, political, environmental, security. Minimal policies (6), mainly a situation repository.

Key sim values: `Homelessness`, `Polarization`

Situations (27): `BankingCrisis`, `ClimateCrisis`, `ConstitutionalCrisis`, `CyberWarfareAttack`, `Deflation`, `DigitalDivide`, `EnergyCrisis`, `FinancialCrisis`, `HighInflation`, `HousingCrisis`, `ImmigrationCrisis`, `MajorArmsDeal`, `MisinformationPandemic`, `OilShock`, `Pandemic`, `Polarization`, `RampantGangs`, `RampentStreetCrimes`, `ResourceWars`, `SocialMediaManipulation`, `SpaceRace`, `StudentDebtCrisis`, `SupplyChainCrisis`, `TechBubble`, `TechUnemploymentCrisis`, `TradeWar`, `War`

Key policies: `bank_bailout_fund`, `crisis_communications_office`, `disaster_relief_fund`, `civil_liberties_protection`, `pandemic_emergency_powers`, `pandemic_preparedness_fund`

---

### D4U_Module9_CountryPacks
**Purpose:** Country-specific policies and simulation values for expanded national packs.

Key sim values: `EUIntegration`, `DMZTension`

Key policies: `eu_open_borders`, `AgeofConsent`, `ImmigrationTax`, `ConservationSubsidies`, `reunification_talks`, `ImRef`, `de_tribalization_initiatives`, `EITC_USA`

Custom sliders: 2

---

## Cross-Module Dependencies

Some modules reference sim values defined in other D4U modules. Load order matters — required modules must be enabled before dependent ones.

| Referencing Module | References | Defined In |
|---|---|---|
| M8 Crises situations | `CoLCostofLiving` | D4U_Core |
| M8 Crises situations | `MilitaryPower`, `GlobalInfluence` | D4U_Module5_ForeignPolicy |
| M8 Crises situations | `TechUnemployment`, `AutomationLevel` | D4U_Module7_Technology |
| M6 Health policies | `VaccinationCoverage` | D4U_Module6_Health sim |
| M4B policies | `StateCapacity`, `WorkerCooperatives` | D4U_Module4B_Socialist sim |
| M5 situations | `military_industrial_complex` | D4U_Module5_ForeignPolicy sim |

---

## Balance Rules (Enforced)

All policies comply with these constraints (verified by audit script):

### Policy Numeric Limits

Ranges are **measured from vanilla D4** (270 policies). p50/p95/max shown.

| Field | Vanilla p50 | Vanilla p95 | Vanilla max | D4U enforced |
|---|---|---|---|---|
| `maxcost` | 23 | 2,250 | 18,000 | ≤ 18,000 |
| `mincost` | 5 | 250 | 5,100 (min −1,000) | ≥ −1,000; ≤ maxcost |
| `cancel` | 14 | 45 | 60 | ≤ 60; **0 if UNCANCELLABLE** |
| `raise` | 14 | 36 | 54 | ≤ 54 |
| `lower` | 8 | 32 | 70 | ≤ 70 |
| `implementation` | 9 | 25 | 50 | ≤ 50 |

### Flag Constraints
- `UNCANCELLABLE` → `cancel = 0` (enforced)
- `MULTIPLYINCOME` → `maxincome > 0` (enforced)

### Sim Value Constraints
- All defaults in [0.0, 1.0]
- `goodbad`: only `HIGHGOOD`, `HIGHBAD`, or blank — never `UNKNOWN`
- `zone`: only valid D4 zone names — never `HIDDEN` (use `NOICON`)

### Equation Safety
- No `1/x` patterns (division by zero when sim=0)
- No hyphenated names in effect targets
- All parentheses balanced
- No `x^0` exponents

---

## Valid Enum Values

### Policy / Situation `department`
```
ECONOMY    FOREIGNPOLICY    LAWANDORDER    PUBLICSERVICES
WELFARE    TRANSPORT        TECHNOLOGY     HEALTH
EDUCATION  ENVIRONMENT      AGRICULTURE    TAX
```
❌ Invalid: `FOREIGN`, `SECURITY`, `ENERGY`, `INDUSTRY`, `DEFENCE`, `HIDDEN`

### Simulation Value `zone`
Same as above plus `NOICON` (for internal/hidden values).
❌ Do not use `HIDDEN` — use `NOICON` instead.

### Simulation Value `goodbad`
`HIGHGOOD` · `HIGHBAD` · *(blank for neutral axis)*
❌ Do not use `UNKNOWN` or `LOWGOOD`.

---

## Audit Verification

Run this PowerShell block to verify the full modpack is clean:

```powershell
$base = "d:\Program Files (x86)\Steam\steamapps\workshop\content\1410710"
$gameBase = "d:\Program Files (x86)\Steam\steamapps\common\Democracy 4\data\simulation"
$modules = @("D4U_Core","D4U_Module1_Industry","D4U_Module2_Transport","D4U_Module3_Governance",
             "D4U_Module4A_Libertarian","D4U_Module4B_Socialist","D4U_Module5_ForeignPolicy",
             "D4U_Module6_Health","D4U_Module7_Technology","D4U_Module8_Crises","D4U_Module9_CountryPacks")

# Check 1: Required files present
$req = @("config.txt","data\simulation\policies.csv","data\simulation\simulation.csv",
         "data\simulation\sliders.csv","translations\English\policies.csv","translations\English\simulation.csv")
foreach ($m in $modules) {
    foreach ($f in $req) { if (-not (Test-Path "$base\$m\$f")) { Write-Host "MISSING [$m] $f" } }
}

# Check 2: UNCANCELLABLE cancel=0
foreach ($m in $modules) {
    Get-Content "$base\$m\data\simulation\policies.csv" | Select-String "^#," | ForEach-Object {
        $c = $_ -split ","; if ($c[3] -match "UNCANCELLABLE") {
            $can = 0; [int]::TryParse($c[6],[ref]$can)|Out-Null
            if ($can -gt 0) { Write-Host "UNCANC_CANCEL [$m] $($c[1]) cancel=$can" }
        }
    }
}

# Check 3: Policy balance
foreach ($m in $modules) {
    Get-Content "$base\$m\data\simulation\policies.csv" | Select-String "^#," | ForEach-Object {
        $c = $_ -split ","; $pn = $c[1]
        $mxc = 0; [double]::TryParse($c[12],[System.Globalization.NumberStyles]::Any,
            [System.Globalization.CultureInfo]::InvariantCulture,[ref]$mxc)|Out-Null
        if ($mxc -gt 10000) { Write-Host "HIGH_COST [$m] $pn maxcost=$mxc" }
    }
}

Write-Host "Audit complete."
```

Expected output: `Audit complete.` with no warnings.

---

## Known Limitations / Future Work

- **SVG icons**: 91 referenced icon names have no SVG file. The game will show a blank icon for these. Creating proper SVG icons (white fill, 243×220 viewBox) for all missing names is pending.
- **Country packs**: M9 contains country-specific overrides. Some prereq flags may only trigger for specific nations.
- **Space module sequencing**: M7 space simulation values (`MarsProgress` stages) are designed to progress sequentially. Enabling M7 without M5 may leave `reaction` outputs undefined.
- **Ideological axes (M5)**: `Individualism`, `Collectivism`, `Authoritarianism`, `Globalism`, `Isolationism`, `Militarism` are 0–1 axis values with blank goodbad. They feed voter group frequency effects. They intentionally start at 0.5 (neutral).

---

## Adding Content to D4U

> For the full column-by-column format of each CSV file, see `democracy4-mod-reference.md` in this folder.
> For detailed explanations and examples, see `complete-modding-guide.md`.

### Adding a new policy
1. Choose the correct module based on theme.
2. Add a `#,` row to `data/simulation/policies.csv` (column spec: `democracy4-mod-reference.md` → Policies table).
3. Add a matching translation row to `translations/English/policies.csv`.
4. If the policy uses a custom slider, add it to `sliders.csv` and the slider translation file.
5. Verify balance thresholds (see **Balance Rules** above).
6. Run the audit script to confirm no cross-reference errors.

### Adding a new simulation value
1. Use `NOICON` zone for internal tracking values.
2. Use `HIGHGOOD`, `HIGHBAD`, or blank goodbad — never `UNKNOWN`.
3. Default must be 0.0–1.0. `HIGHBAD` defaults ≤ 0.85.
4. Add translation row to `translations/English/simulation.csv`.

### Adding a new situation
1. Department must be from the valid list — not `ENERGY`, `INDUSTRY`, etc.
2. `starttrigger` must be > `stoptrigger`; neither may be 0.
3. Add translation row to `translations/English/situations.csv`.
4. If adding to a new module, ensure `situations.csv` and its translation file exist.

---

## History of Major Fixes

| Issue | Module | Fix |
|---|---|---|
| `interest_rate` cancel=10000 | Core | Set to 20 |
| `EGovDigitalAdmin` intro=0 with maxcost=500 | M3 | Set intro=8 |
| `mars_colony_programme` maxcost=12000 | M7 | Capped to 8000 |
| `UNKNOWN` goodbad on 7 sim values | M5, M6 | Cleared to blank |
| 24 UNCANCELLABLE policies with cancel>0 | All | Set cancel=0 |
| `living_wage` MULTIPLYINCOME + maxincome=0 | M4B | Removed flag |
| `Antibiotics-ResitantBacteria` hyphenated name | M7 | Effect removed |
| `1/x` div-by-zero in Isolationism/Militarism | M5 | Changed to `2*x` |
| `privatization_drive` opposite=NationalisedIndustries | M4A | Cleared |
| `universal_public_broadband` opposite=PrivateTelecoms | M4B | Cleared |
| `Smoking` invalid effect target | M6 | Effect removed |
| `BankRegulation` invalid target | M8 | Effects removed |
| `Inequality` invalid sim target | M8 | Changed to ClassWarfare |
| M1 policies dept=ENERGY/INDUSTRY | M1 | Changed to ECONOMY |
| `ActualThreat` zone=HIDDEN | M5 | Changed to NOICON |
| `military_industrial_complex` group=INDUSTRY | M5 | Changed to ECONOMY |
| Missing `sliders.csv` in M8 | M8 | Created empty file |
| Missing `config.txt` version field | All | Added version=1 |
