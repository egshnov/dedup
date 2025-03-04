#!/bin/bash

run_dir=$(readlink -f $1)
PREFIX="|--->"
SET_PREFIX="|-> "
SECTOR_SIZE=4096


function run_test() {
    local test_dir="$1"
    local dir_name=$(basename "$test_dir")
    
    # Run FIO verification
    for fio_job in "$test_dir"/*.fio; do
        echo -e "${SET_PREFIX} Running FIO verification..."
        if ! sudo fio "$fio_job" > /dev/null; then
            echo -e "${PREFIX} \e[31mVERIFICATION FAILED\e[0m"
            return 1
        fi
    done

    # Cleanup
    return 0
}

echo -e "\e[34mDEDUP TESTS\e[0m"
for test_case in "$run_dir"/*/; do
    if [ -d "$test_case" ]; then
        echo -e "${SET_PREFIX} Testing: $(basename "$test_case")"
        if run_test "$test_case"; then
            echo -e "${PREFIX} \e[32mTEST PASSED\e[0m"
        else
            echo -e "${PREFIX} \e[31mTEST FAILED\e[0m"
        fi
    fi
done