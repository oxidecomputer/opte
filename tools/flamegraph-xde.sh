# A little messy right now, written as though it is exec'd from within
# a git clone of FlameGraph.

pfexec dtrace -x stackframes=100 -n 'profile-201us /arg0/ { @[stack()] = count(); } tick-120s { exit(0); }' -o out.stacks
./stackcollapse.pl out.stacks > out.folded
cat out.folded | grep xde_rx > rx.folded
cat out.folded | grep xde_mc_tx > tx.folded

./flamegraph.pl rx.folded > ~/rx.svg
./flamegraph.pl tx.folded > ~/tx.svg
