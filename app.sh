#!/bin/bash
### Make part to set running parameters as variables (not IO but beautiful)
if [ -z $1 ]
then
    iterations=1
else
    iterations=$1
fi

if [ -z $2 ]
then
    experimentdate=$(date +%Y-%m-%d_%H%M)
else
    experimentdate=$2
fi

sourcefiles=./../send_files
receivedfiles=./../received_files
datasocket=127.0.0.1:4433
clientsocket=127.0.0.1:1234
sleeptimer=30

# Possible values are trace, debug, info and warn
rustlog="error"

# Optional parameters
logging=true
qlogdir=./../qlogs
logdir=./../eval_logs
saveintermediate=false
storerx=./../server_rx
storetx=./../server_tx

# Compiling the applications
cargo build --bin quiche-server
cargo build --bin quiche-client
cargo build --bin quiche-data
echo "Built apps"

for (( iteration=1; iteration<=$iterations; iteration++ ))
do

### Make part to set up the directories
# Only create logging directories if we want logging
if [ "$logging" = true ]
then
    mkdir -p $qlogdir
    mkdir -p $logdir
fi

mkdir -p $sourcefiles
mkdir -p $receivedfiles

# Only create directories for intermediate results if we want them
if [ "$saveintermediate" = true ]
then
    mkdir -p $storerx
    mkdir -p $storetx
    
fi

### Run the three applications with arguments according to the set preferences
if [ "$logging" = true ]
then
    if [ "$saveintermediate" = true ]
    then
        RUST_LOG="$rustlog" QLOGDIR="$qlogdir" ./target/debug/quiche-server --listen-from "$datasocket" --listen-to "$clientsocket" --cert apps/src/bin/cert.crt --key apps/src/bin/cert.key --store-rx "$storerx" --store-tx "$storetx" --store-eval "$logdir" & pids=$!
    else
        RUST_LOG="$rustlog" QLOGDIR="$qlogdir" ./target/debug/quiche-server --listen-from "$datasocket" --listen-to "$clientsocket" --cert apps/src/bin/cert.crt --key apps/src/bin/cert.key --store-eval "$logdir" & pids=$!
    fi
    RUST_LOG="$rustlog" QLOGDIR="$qlogdir" ./target/debug/quiche-client https://${clientsocket} --no-verify  --dump-responses "$receivedfiles" --store-eval "$logdir" & pidc=$!
    RUST_LOG="$rustlog" QLOGDIR="$qlogdir" ./target/debug/quiche-data https://${datasocket} --no-verify --root "${sourcefiles}/" --method=POST --store-eval "$logdir" & pidd=$!
else
    if [ "$saveintermediate" = true ]
    then
        RUST_LOG="$rustlog" ./target/debug/quiche-server --listen-from "$datasocket" --listen-to "$clientsocket" --cert apps/src/bin/cert.crt --key apps/src/bin/cert.key --store-rx "$storerx" --store-tx "$storetx" & pids=$!
    else
        RUST_LOG="$rustlog" ./target/debug/quiche-server --listen-from "$datasocket" --listen-to "$clientsocket" --cert apps/src/bin/cert.crt --key apps/src/bin/cert.key & pids=$!
    fi

    RUST_LOG="$rustlog" ./target/debug/quiche-client https://${clientsocket} --no-verify  --dump-responses "$receivedfiles" &
    RUST_LOG="$rustlog" ./target/debug/quiche-data https://${datasocket} --no-verify --root "${sourcefiles}/" --method=POST &
fi

# Kill server after time elapsed
sleep $sleeptimer
kill $pids
echo "killed server"

# Wait for the clients to gracefully end themselves (so they can end processing their data)
wait

echo "Iteration ${iteration}: Done"

# Rename the log directories so they do not get overridden by something
mkdir -p "./../${experimentdate}"
mv $receivedfiles "./../${experimentdate}/${iteration}-rx"
cp -r $sourcefiles "./../${experimentdate}/${iteration}-tx"

if [ "$saveintermediate" = true ]
then
    mv $storerx "./../${experimentdate}/${iteration}-server-rx"
    mv $storetx "./../${experimentdate}/${iteration}-server-tx"
fi

if [ "$logging" = true ]
then
    mv $qlogdir "./../${experimentdate}/${iteration}-qlogs"
    mv $logdir "./../${experimentdate}/${iteration}-eval-logs"
fi

# Run a py-script to make log-files easier accessible for aggregation over multiple iterations
python3 "eval-per-iteration.py" "./../${experimentdate}/${iteration}-eval-logs"
done

# Make diagram of this experiment
python3 "eval-per-exp.py" "${iterations}" "./../${experimentdate}"
echo "Evaluated experiment from ${experimentdate}"