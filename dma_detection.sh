#!/bin/bash

##############################################################################################
# dma_confg.yml generation through detect_dma tool in parallel when fuzzing with GDMA        #
# ############################################################################################
# May not work sometimes, experimental                                                       #
##############################################################################################

if [ $# -ne 2 ]; then
    echo "Usage: $0 <fuzzware_project_path> <num_fuzzers>"
    echo "Example: $0 /path/to/project 4"
    exit 1
fi

PROJECT_PATH="$1"
NUM_FUZZERS="$2"

if [ ! -d "$PROJECT_PATH" ]; then
    echo "Error: Project path '$PROJECT_PATH' does not exist"
    exit 1
fi

if ! [[ "$NUM_FUZZERS" =~ ^[0-9]+$ ]] || [ "$NUM_FUZZERS" -le 0 ]; then
    echo "Error: Number of fuzzers must be a positive integer"
    exit 1
fi


PARALLEL_JOBS=$(nproc 2>/dev/null || echo 4)
echo "Running with up to $PARALLEL_JOBS parallel jobs."

DETECT_DMA_BINARY="/home/user/fuzzware/pipeline/dma_modeling/target/release/detect_dma"
if [ ! -f "$DETECT_DMA_BINARY" ]; then
    echo "Error: detect_dma binary not found at $DETECT_DMA_BINARY"
    echo "Please build it first with: cd pipeline/dma_modeling && cargo build --release"
    exit 1
fi

FUZZWARE_PROJECT=""
if [ -d "$PROJECT_PATH/fuzzware-project" ]; then
    FUZZWARE_PROJECT="$PROJECT_PATH/fuzzware-project"
elif [ -d "$PROJECT_PATH" ] && [[ "$(basename "$PROJECT_PATH")" == "fuzzware-project" ]]; then
    FUZZWARE_PROJECT="$PROJECT_PATH"
else
    echo "Error: Could not find fuzzware-project directory in $PROJECT_PATH"
    exit 1
fi

echo "Using fuzzware project: $FUZZWARE_PROJECT"

CONFIG_FILE=""
if [ -f "$FUZZWARE_PROJECT/../config.yml" ]; then
    CONFIG_FILE="$FUZZWARE_PROJECT/../config.yml"
elif [ -f "$PROJECT_PATH/config.yml" ]; then
    CONFIG_FILE="$PROJECT_PATH/config.yml"
else
    echo "Error: Could not find config.yml file"
    exit 1
fi

echo "Using config file: $CONFIG_FILE"

DMA_SNIPPETS_DIR="$FUZZWARE_PROJECT/dma_snippets"
if [ -d "$DMA_SNIPPETS_DIR" ]; then
    echo "Cleaning up previous DMA snippets..."
    rm -rf "$DMA_SNIPPETS_DIR"
fi
mkdir -p "$DMA_SNIPPETS_DIR"

echo "DMA snippets will be saved to: $DMA_SNIPPETS_DIR"

find_latest_main_dir() {
    local main_dirs=("$FUZZWARE_PROJECT"/main*)
    if [ ${#main_dirs[@]} -eq 0 ]; then
        echo "Error: No main directories found in $FUZZWARE_PROJECT"
        exit 1
    fi
    
    printf '%s\n' "${main_dirs[@]}" | sort -V | tail -n1
}

MAIN_DIR=$(find_latest_main_dir)
echo "Using main directory: $MAIN_DIR"


process_trace_pair() {
    local ram_trace="$1"
    local mmio_trace="$2"
    local fuzzer_num="$3"
    local config_file="$4"
    local dma_snippets_dir="$5"
    
    local DETECT_DMA_BINARY="/home/user/fuzzware/pipeline/dma_modeling/target/release/detect_dma"

    ram_filename=$(basename "$ram_trace")
    ram_id=$(echo "$ram_filename" | grep -o 'ram_id:[0-9]*' | cut -d: -f2)
    ram_time=$(echo "$ram_filename" | grep -o 'time:[0-9]*' | cut -d: -f2)
    
    if [ -z "$ram_id" ]; then
        ram_id=$(echo "$ram_filename" | sed 's/[^0-9]//g' | head -c10)
        [ -z "$ram_id" ] && ram_id="1"
    fi
    
    if [ -z "$ram_time" ]; then
        ram_time=$(echo "$ram_filename" | sed 's/[^0-9]//g' | tail -c10)
        [ -z "$ram_time" ] && ram_time="1"
    fi
    
    output_snippet="$dma_snippets_dir/fuzzer${fuzzer_num}_ram${ram_id}_time${ram_time}.yml"
    
    if "$DETECT_DMA_BINARY" model \
        --fuzzware-config "$config_file" \
        --fuzzware-ram-trace "$ram_trace" \
        --fuzzware-mmio-trace "$mmio_trace" \
        -o "$output_snippet" \
        --snip-format yaml >/dev/null 2>&1; then
        
        if [ -s "$output_snippet" ]; then
            if head -1 "$output_snippet" | grep -q "^---" 2>/dev/null; then
                echo "✓ Generated snippet for fuzzer $fuzzer_num, ram_id $ram_id"
            else
                [ -f "$output_snippet" ] && rm "$output_snippet"
            fi
        else
            [ -f "$output_snippet" ] && rm "$output_snippet"
        fi
    else
        echo "✗ Error processing fuzzer $fuzzer_num, ram_id $ram_id"
        [ -f "$output_snippet" ] && rm "$output_snippet"
    fi
}
export -f process_trace_pair

echo "Scanning for trace pairs to process..."
trace_pairs_file=$(mktemp)
total_ram_traces=0

for ((fuzzer_num=1; fuzzer_num<=NUM_FUZZERS; fuzzer_num++)); do
    FUZZER_DIR="$MAIN_DIR/fuzzers/fuzzer$fuzzer_num"
    
    echo "  Checking fuzzer $fuzzer_num at: $FUZZER_DIR"
    
    if [ ! -d "$FUZZER_DIR" ]; then
        echo "    Fuzzer directory does not exist, skipping..."
        continue
    fi
    
    TRACES_DIR="$FUZZER_DIR/traces"
    if [ ! -d "$TRACES_DIR" ]; then
        echo "    Traces directory does not exist, skipping..."
        continue
    fi
    
    echo "    Traces directory contents:"
    ls -la "$TRACES_DIR" | head -5
    echo "    (showing first 5 files only)"
    
    echo "    Finding trace files..."
    ram_traces=($(find "$TRACES_DIR" -name "*ram*" -type f -not -name "*.yaml" -not -name "*.yml" 2>/dev/null | head -10 | sort))
    mmio_traces=($(find "$TRACES_DIR" -name "*mmio*" -type f -not -name "*.yaml" -not -name "*.yml" 2>/dev/null | head -10 | sort))
    dma_traces=($(find "$TRACES_DIR" -name "*dma*" -type f -not -name "*.yaml" -not -name "*.yml" 2>/dev/null | head -10 | sort))
    
    if [ ${#ram_traces[@]} -eq 0 ]; then
        ram_traces=($(find "$TRACES_DIR" -name "ram*" -type f -not -name "*.yaml" -not -name "*.yml" 2>/dev/null | head -10 | sort))
    fi
    
    if [ ${#mmio_traces[@]} -eq 0 ]; then
        mmio_traces=($(find "$TRACES_DIR" -name "mmio*" -type f -not -name "*.yaml" -not -name "*.yml" 2>/dev/null | head -10 | sort))
    fi
    
    if [ ${#dma_traces[@]} -eq 0 ]; then
        dma_traces=($(find "$TRACES_DIR" -name "dma*" -type f -not -name "*.yaml" -not -name "*.yml" 2>/dev/null | head -10 | sort))
    fi
    
    echo "    Found ${#ram_traces[@]} RAM traces, ${#mmio_traces[@]} MMIO traces, and ${#dma_traces[@]} DMA traces"
    
    if [ ${#ram_traces[@]} -gt 0 ]; then
        echo "    First RAM trace: $(basename "${ram_traces[0]}")"
    fi
    if [ ${#mmio_traces[@]} -gt 0 ]; then
        echo "    First MMIO trace: $(basename "${mmio_traces[0]}")"
    fi
    if [ ${#dma_traces[@]} -gt 0 ]; then
        echo "    First DMA trace: $(basename "${dma_traces[0]}")"
        echo "    Note: DMA traces found but detect_dma tool only uses RAM+MMIO for analysis"
    fi
    
    if [ ${#ram_traces[@]} -eq 0 ] || [ ${#mmio_traces[@]} -eq 0 ]; then
        echo "    No valid RAM+MMIO trace pairs found, skipping..."
        echo "    (detect_dma analyzes RAM+MMIO to detect DMA patterns)"
        continue
    fi
    
    ((total_ram_traces += ${#ram_traces[@]}))

    echo "    Pairing traces..."
    pair_count=0
    for ram_trace in "${ram_traces[@]}"; do
        if [ $pair_count -ge 5 ]; then
            echo "    Limiting to 5 pairs per fuzzer to prevent hanging..."
            break
        fi
        
        ram_time=$(basename "$ram_trace" | grep -o 'time:[0-9]*' | cut -d: -f2)
        if [ -z "$ram_time" ]; then
            ram_time=$(echo "$(basename "$ram_trace")" | cksum | cut -d' ' -f1)
        fi
        
        best_mmio_trace=""
        best_time_diff=999999
        
        for mmio_trace in "${mmio_traces[@]}"; do
            mmio_time=$(basename "$mmio_trace" | grep -o 'time:[0-9]*' | cut -d: -f2)
            if [ -z "$mmio_time" ]; then
                mmio_time=$(echo "$(basename "$mmio_trace")" | cksum | cut -d' ' -f1)
            fi
            
            time_diff=$((ram_time > mmio_time ? ram_time - mmio_time : mmio_time - ram_time))
            
            if [ "$time_diff" -lt "$best_time_diff" ] && [ "$time_diff" -le 1000 ]; then
                best_time_diff="$time_diff"
                best_mmio_trace="$mmio_trace"
            fi
        done
        
        if [ -n "$best_mmio_trace" ]; then
            echo "$ram_trace $best_mmio_trace $fuzzer_num $CONFIG_FILE $DMA_SNIPPETS_DIR" >> "$trace_pairs_file"
            ((pair_count++))
            echo "      Paired RAM trace $(basename "$ram_trace") with MMIO trace $(basename "$best_mmio_trace")"
        fi
    done
done

num_pairs=$(wc -l < "$trace_pairs_file")
echo "Found $num_pairs trace pairs to process out of $total_ram_traces total RAM traces."

if [ "$num_pairs" -gt 0 ]; then
    echo "Starting parallel DMA detection..."
    
    cat "$trace_pairs_file" | xargs -n5 -P"$PARALLEL_JOBS" \
        bash -c 'process_trace_pair "$0" "$1" "$2" "$3" "$4"'
fi

rm "$trace_pairs_file"

echo ""
echo "=== DMA Detection Summary ==="
find "$DMA_SNIPPETS_DIR" -name "*queue*" -delete 2>/dev/null
find "$DMA_SNIPPETS_DIR" -name "*main001*" -delete 2>/dev/null

snippet_count=$(find "$DMA_SNIPPETS_DIR" -name "*.yml" -type f 2>/dev/null | wc -l)
echo "Total inputs processed: $num_pairs"
echo "DMA snippets generated: $snippet_count"
echo "Snippets directory: $DMA_SNIPPETS_DIR"

if [ "$snippet_count" -gt 0 ]; then
    echo ""
    echo "=== Snippet Analysis ==="
    empty_candidates=0
    non_empty_candidates=0
    
    for snippet in "$DMA_SNIPPETS_DIR"/*.yml; do
        if grep -q "detected_candidates: {}" "$snippet" 2>/dev/null; then
            ((empty_candidates++))
        else
            ((non_empty_candidates++))
        fi
    done
    
    echo "Snippets with empty candidates: $empty_candidates"
    echo "Snippets with DMA candidates: $non_empty_candidates"
    
    if [ "$non_empty_candidates" -gt 0 ]; then
        echo "Sample snippet with candidates:"
        for snippet in "$DMA_SNIPPETS_DIR"/*.yml; do
            if ! grep -q "detected_candidates: {}" "$snippet" 2>/dev/null; then
                echo "  $(basename "$snippet")"
                break
            fi
        done
        
        echo ""
        echo "=== Analyzing Potential Conflicts ==="
        echo "Extracting MMIO addresses from candidates..."
        
        mmio_addrs=$(grep -h "0x[0-9a-fA-F]*:" "$DMA_SNIPPETS_DIR"/*.yml 2>/dev/null | grep -E "^\s+0x" | sort | uniq -c | sort -nr)
        
        if [ -n "$mmio_addrs" ]; then
            echo "MMIO addresses found in candidates (count, address):"
            echo "$mmio_addrs" | head -10
            
            echo ""
            echo "Checking for conflicting interpretations..."
            conflict_found=false
            
            for addr in $(echo "$mmio_addrs" | awk '$1 > 1 {print $2}' | sed 's/:$//' | head -5); do
                echo "  Address $addr appears in multiple snippets - potential conflict source"
                conflict_found=true
            done
            
            if [ "$conflict_found" = false ]; then
                echo "  No obvious conflicts detected in MMIO address usage"
                echo "  Issue may be insufficient votes or confidence thresholds"
            fi
        else
            echo "No MMIO addresses found in detected_candidates sections"
        fi
    fi
fi

if [ -d "$DMA_SNIPPETS_DIR" ]; then
    echo ""
    echo "Generated snippet files:"
    ls -la "$DMA_SNIPPETS_DIR" 2>/dev/null || echo "  (directory is empty)"
fi

if [ "$snippet_count" -gt 0 ]; then
    echo ""
    echo "Generating final DMA configuration..."
    
    final_config="$FUZZWARE_PROJECT/dma_config.yml"
    
    echo "Running: $DETECT_DMA_BINARY summarize --snipdir $DMA_SNIPPETS_DIR -o $final_config --snip-format yaml"
    
    if "$DETECT_DMA_BINARY" summarize \
        --snipdir "$DMA_SNIPPETS_DIR" \
        -o "$final_config" \
        --snip-format yaml 2>&1; then
        
        if [ -f "$final_config" ] && [ -s "$final_config" ]; then
            echo "Final DMA config generated: $final_config"
            echo ""
            echo "=== DMA Configuration Preview ==="
            head -20 "$final_config"
        else
            echo "No final DMA config generated (file empty or not created)"
            echo "This usually means insufficient valid/consistent DMA patterns across snippets"
            
            if [ "$non_empty_candidates" -gt 0 ]; then
                echo ""
                echo "However, $non_empty_candidates snippets contained DMA candidates."
                echo "The patterns may be too inconsistent or not meet confidence thresholds."
                echo "Consider:"
                echo "1. Running longer fuzzing sessions to get more consistent patterns"
                echo "2. Checking if the detected patterns are actually valid DMA operations"
                echo "3. Manually reviewing snippets with candidates for useful patterns"
            fi
        fi
    else
        echo "Error running summarize command"
        exit 1
    fi
else
    echo "No DMA snippets were generated. This could mean:"
    echo "1. No DMA patterns were detected in the traces"
    echo "2. The traces don't contain sufficient DMA activity"
    echo "3. There might be an issue with the trace format"
fi

echo ""
echo "DMA detection completed!"
