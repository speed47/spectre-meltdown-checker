# vim: set ts=4 sw=4 sts=4 et:
# Human-friendly codename lookup for Intel CPUs.
# Depends on constants from 003_intel_models.sh being set.

# Print the human-friendly codename for the current Intel CPU, or nothing if unknown.
# Reads: cpu_family, cpu_model (set by parse_cpu_details)
get_intel_codename() {
    case "$cpu_family" in
        5)
            case "$cpu_model" in
                "$INTEL_FAM5_PENTIUM_75") echo "Pentium 75 (P54C)" ;;
                "$INTEL_FAM5_PENTIUM_MMX") echo "Pentium MMX (P55C)" ;;
                "$INTEL_FAM5_QUARK_X1000") echo "Quark X1000" ;;
            esac
            ;;
        6)
            case "$cpu_model" in
                "$INTEL_FAM6_PENTIUM_PRO") echo "Pentium Pro" ;;
                "$INTEL_FAM6_PENTIUM_II_KLAMATH") echo "Pentium II (Klamath)" ;;
                "$INTEL_FAM6_PENTIUM_III_DESCHUTES") echo "Pentium III (Deschutes)" ;;
                "$INTEL_FAM6_PENTIUM_III_TUALATIN") echo "Pentium III (Tualatin)" ;;
                "$INTEL_FAM6_PENTIUM_M_DOTHAN") echo "Pentium M (Dothan)" ;;
                "$INTEL_FAM6_CORE_YONAH") echo "Core (Yonah)" ;;
                "$INTEL_FAM6_CORE2_MEROM") echo "Core 2 (Merom)" ;;
                "$INTEL_FAM6_CORE2_MEROM_L") echo "Core 2 (Merom-L)" ;;
                "$INTEL_FAM6_CORE2_PENRYN") echo "Core 2 (Penryn)" ;;
                "$INTEL_FAM6_CORE2_DUNNINGTON") echo "Core 2 (Dunnington)" ;;
                "$INTEL_FAM6_NEHALEM") echo "Nehalem" ;;
                "$INTEL_FAM6_NEHALEM_G") echo "Nehalem (Auburndale / Havendale)" ;;
                "$INTEL_FAM6_NEHALEM_EP") echo "Nehalem EP" ;;
                "$INTEL_FAM6_NEHALEM_EX") echo "Nehalem EX" ;;
                "$INTEL_FAM6_WESTMERE") echo "Westmere" ;;
                "$INTEL_FAM6_WESTMERE_EP") echo "Westmere EP" ;;
                "$INTEL_FAM6_WESTMERE_EX") echo "Westmere EX" ;;
                "$INTEL_FAM6_SANDYBRIDGE") echo "Sandy Bridge" ;;
                "$INTEL_FAM6_SANDYBRIDGE_X") echo "Sandy Bridge-E" ;;
                "$INTEL_FAM6_IVYBRIDGE") echo "Ivy Bridge" ;;
                "$INTEL_FAM6_IVYBRIDGE_X") echo "Ivy Bridge-E" ;;
                "$INTEL_FAM6_HASWELL") echo "Haswell" ;;
                "$INTEL_FAM6_HASWELL_X") echo "Haswell-E" ;;
                "$INTEL_FAM6_HASWELL_L") echo "Haswell (low power)" ;;
                "$INTEL_FAM6_HASWELL_G") echo "Haswell (GT3e)" ;;
                "$INTEL_FAM6_BROADWELL") echo "Broadwell" ;;
                "$INTEL_FAM6_BROADWELL_G") echo "Broadwell (GT3e)" ;;
                "$INTEL_FAM6_BROADWELL_X") echo "Broadwell-E" ;;
                "$INTEL_FAM6_BROADWELL_D") echo "Broadwell-DE" ;;
                "$INTEL_FAM6_SKYLAKE_L") echo "Skylake (mobile)" ;;
                "$INTEL_FAM6_SKYLAKE") echo "Skylake (desktop)" ;;
                "$INTEL_FAM6_SKYLAKE_X") echo "Skylake-X / Cascade Lake / Cooper Lake" ;;
                "$INTEL_FAM6_KABYLAKE_L") echo "Kaby Lake (mobile) / Sky Lake" ;;
                "$INTEL_FAM6_KABYLAKE") echo "Kaby Lake / Coffee Lake / Sky Lake" ;;
                "$INTEL_FAM6_COMETLAKE") echo "Comet Lake / Sky Lake" ;;
                "$INTEL_FAM6_COMETLAKE_L") echo "Comet Lake (mobile) / Sky Lake" ;;
                "$INTEL_FAM6_CANNONLAKE_L") echo "Cannon Lake (Palm Cove)" ;;
                "$INTEL_FAM6_ICELAKE_X") echo "Ice Lake-X (Sunny Cove)" ;;
                "$INTEL_FAM6_ICELAKE_D") echo "Ice Lake-D (Sunny Cove)" ;;
                "$INTEL_FAM6_ICELAKE") echo "Ice Lake (Sunny Cove)" ;;
                "$INTEL_FAM6_ICELAKE_L") echo "Ice Lake-L (Sunny Cove)" ;;
                "$INTEL_FAM6_ICELAKE_NNPI") echo "Ice Lake NNPI (Sunny Cove)" ;;
                "$INTEL_FAM6_ROCKETLAKE") echo "Rocket Lake (Cypress Cove)" ;;
                "$INTEL_FAM6_TIGERLAKE_L") echo "Tiger Lake-L (Willow Cove)" ;;
                "$INTEL_FAM6_TIGERLAKE") echo "Tiger Lake (Willow Cove)" ;;
                "$INTEL_FAM6_SAPPHIRERAPIDS_X") echo "Sapphire Rapids-X (Golden Cove)" ;;
                "$INTEL_FAM6_EMERALDRAPIDS_X") echo "Emerald Rapids-X (Raptor Cove)" ;;
                "$INTEL_FAM6_GRANITERAPIDS_X") echo "Granite Rapids-X (Redwood Cove)" ;;
                "$INTEL_FAM6_GRANITERAPIDS_D") echo "Granite Rapids-D (Redwood Cove)" ;;
                "$INTEL_FAM6_BARTLETTLAKE") echo "Bartlett Lake (Raptor Cove)" ;;
                "$INTEL_FAM6_LAKEFIELD") echo "Lakefield (Sunny Cove + Tremont)" ;;
                "$INTEL_FAM6_ALDERLAKE") echo "Alder Lake (Golden Cove + Gracemont)" ;;
                "$INTEL_FAM6_ALDERLAKE_L") echo "Alder Lake-L (Golden Cove + Gracemont)" ;;
                "$INTEL_FAM6_RAPTORLAKE") echo "Raptor Lake (Raptor Cove + Enhanced Gracemont)" ;;
                "$INTEL_FAM6_RAPTORLAKE_P") echo "Raptor Lake-P (Raptor Cove + Enhanced Gracemont)" ;;
                "$INTEL_FAM6_RAPTORLAKE_S") echo "Raptor Lake-S (Raptor Cove + Enhanced Gracemont)" ;;
                "$INTEL_FAM6_METEORLAKE") echo "Meteor Lake (Redwood Cove + Crestmont)" ;;
                "$INTEL_FAM6_METEORLAKE_L") echo "Meteor Lake-L (Redwood Cove + Crestmont)" ;;
                "$INTEL_FAM6_ARROWLAKE_H") echo "Arrow Lake-H (Lion Cove + Skymont)" ;;
                "$INTEL_FAM6_ARROWLAKE") echo "Arrow Lake (Lion Cove + Skymont)" ;;
                "$INTEL_FAM6_ARROWLAKE_U") echo "Arrow Lake-U (Lion Cove + Skymont)" ;;
                "$INTEL_FAM6_LUNARLAKE_M") echo "Lunar Lake-M (Lion Cove + Skymont)" ;;
                "$INTEL_FAM6_PANTHERLAKE_L") echo "Panther Lake-L (Cougar Cove + Darkmont)" ;;
                "$INTEL_FAM6_WILDCATLAKE_L") echo "Wildcat Lake-L" ;;
                "$INTEL_FAM6_ATOM_BONNELL") echo "Atom Bonnell (Diamondville / Pineview)" ;;
                "$INTEL_FAM6_ATOM_BONNELL_MID") echo "Atom Bonnell (Silverthorne / Lincroft)" ;;
                "$INTEL_FAM6_ATOM_SALTWELL") echo "Atom Saltwell (Cedarview)" ;;
                "$INTEL_FAM6_ATOM_SALTWELL_MID") echo "Atom Saltwell (Penwell)" ;;
                "$INTEL_FAM6_ATOM_SALTWELL_TABLET") echo "Atom Saltwell (Cloverview)" ;;
                "$INTEL_FAM6_ATOM_SILVERMONT") echo "Atom Silvermont (Bay Trail)" ;;
                "$INTEL_FAM6_ATOM_SILVERMONT_D") echo "Atom Silvermont-D (Avaton / Rangely)" ;;
                "$INTEL_FAM6_ATOM_SILVERMONT_MID") echo "Atom Silvermont (Merriefield)" ;;
                "$INTEL_FAM6_ATOM_SILVERMONT_MID2") echo "Atom Silvermont (Anniedale)" ;;
                "$INTEL_FAM6_ATOM_AIRMONT") echo "Atom Airmont (Cherry Trail / Braswell)" ;;
                "$INTEL_FAM6_ATOM_AIRMONT_NP") echo "Atom Airmont (Lightning Mountain)" ;;
                "$INTEL_FAM6_ATOM_GOLDMONT") echo "Atom Goldmont (Apollo Lake)" ;;
                "$INTEL_FAM6_ATOM_GOLDMONT_D") echo "Atom Goldmont-D (Denverton)" ;;
                "$INTEL_FAM6_ATOM_GOLDMONT_PLUS") echo "Atom Goldmont Plus (Gemini Lake)" ;;
                "$INTEL_FAM6_ATOM_TREMONT_D") echo "Atom Tremont-D (Jacobsville)" ;;
                "$INTEL_FAM6_ATOM_TREMONT") echo "Atom Tremont (Elkhart Lake)" ;;
                "$INTEL_FAM6_ATOM_TREMONT_L") echo "Atom Tremont-L (Jasper Lake)" ;;
                "$INTEL_FAM6_ATOM_GRACEMONT") echo "Atom Gracemont (Alder Lake-N)" ;;
                "$INTEL_FAM6_ATOM_CRESTMONT_X") echo "Atom Crestmont-X (Sierra Forest)" ;;
                "$INTEL_FAM6_ATOM_CRESTMONT") echo "Atom Crestmont (Grand Ridge)" ;;
                "$INTEL_FAM6_ATOM_DARKMONT_X") echo "Atom Darkmont-X (Clearwater Forest)" ;;
                "$INTEL_FAM6_XEON_PHI_KNL") echo "Xeon Phi (Knights Landing)" ;;
                "$INTEL_FAM6_XEON_PHI_KNM") echo "Xeon Phi (Knights Mill)" ;;
            esac
            ;;
        15)
            case "$cpu_model" in
                "$INTEL_FAM15_P4_WILLAMETTE") echo "Pentium 4 (Willamette)" ;;
                "$INTEL_FAM15_P4_PRESCOTT") echo "Pentium 4 (Prescott)" ;;
                "$INTEL_FAM15_P4_PRESCOTT_2M") echo "Pentium 4 (Prescott 2M)" ;;
                "$INTEL_FAM15_P4_CEDARMILL") echo "Pentium 4 (Cedarmill)" ;;
            esac
            ;;
        18)
            case "$cpu_model" in
                "$INTEL_FAM18_NOVALAKE") echo "Nova Lake (Coyote Cove)" ;;
                "$INTEL_FAM18_NOVALAKE_L") echo "Nova Lake-L (Coyote Cove)" ;;
            esac
            ;;
        19)
            case "$cpu_model" in
                "$INTEL_FAM19_DIAMONDRAPIDS_X") echo "Diamond Rapids-X (Panther Cove)" ;;
            esac
            ;;
    esac
}
